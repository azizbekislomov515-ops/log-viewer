"""IngestPipeline: collectors -> multiline assembly -> normalizer/parsers -> storage -> GUI.

Flow::

    collector task (one per source) --await put--> ingest queue (bounded)
        --> writer task: batch (<= batch_size or flush_interval)
        --> MultilineAssembler (holds the last event per source until it is complete)
        --> Normalizer (parser registry: timestamps, severity, fields)
        --> Storage.write_batch (worker thread; entries + cursors in one transaction)
        --> per-source ring buffer --> subscriber callbacks (event-loop thread)

Isolation: each source has its own task. A collector that raises is recorded in
``errors`` and stops; nothing else is affected. Transient failures are retried inside the
collector itself (``reconnecting``). Storage failures are logged and the batch is still
delivered live, with negative ids, so the live view keeps working.

Memory ceilings (defaults, ``PipelineLimits``). Every buffer is bounded; when the queue
is full, collectors block and stop reading their input (backpressure), nothing is dropped:

=========================  =====================================  ===========  =========
Buffer                     Bound                                  Typical      Worst case
=========================  =====================================  ===========  =========
ingest queue               ``queue_size`` = 4096 records          ~2 MiB       256 MiB
writer batch in flight     ``batch_size`` = 500 records           ~0.3 MiB     32 MiB
ring buffer, per source    ``ring_size`` = 2000 entries           ~1.5 MiB     128 MiB
docker reader handoff      8 batches (1 Docker frame each)        ~64 KiB      8 MiB
per-collector line buffer  ``MAX_LINE_BYTES`` = 64 KiB            ~0           64 KiB
multiline event, per src   ``MAX_EVENT_CHARS`` = 64 KiB           ~0.3 KiB     64 KiB
journalctl line buffer     ``MAX_JSON_LINE`` = 1 MiB              ~1 KiB       1 MiB
=========================  =====================================  ===========  =========

"Typical" assumes ~300-byte lines; "worst case" assumes every line is at the 64 KiB cap.
Total ≈ queue + batch + ring_size x active sources. Example: 20 followed sources with
typical lines ≈ 2 + 0.3 + 20 x 1.5 ≈ 33 MiB.
"""

from __future__ import annotations

import asyncio
import contextlib
import itertools
import logging
from collections import defaultdict, deque
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field, replace
from datetime import datetime
from typing import TYPE_CHECKING

from loglens.core.models import LogEntry, LogSource, RawRecord, SourceKind
from loglens.parsers import MultilineAssembler, Normalizer
from loglens.security.redact import Redactor
from loglens.storage import RetentionPolicy, Storage

if TYPE_CHECKING:
    from loglens.collectors.base import Collector

log = logging.getLogger(__name__)

Subscriber = Callable[[Sequence[LogEntry]], None]


@dataclass(frozen=True, slots=True)
class PipelineLimits:
    """Buffer sizes and flush cadence. See the module docstring for memory ceilings."""

    queue_size: int = 4096
    batch_size: int = 500
    flush_interval: float = 0.2
    ring_size: int = 2000


@dataclass(slots=True)
class PipelineStats:
    """Counters for monitoring and tests."""

    received: int = 0
    stored: int = 0
    batches: int = 0
    storage_errors: int = 0
    max_queue: int = 0
    redacted: int = 0
    #: Entries deleted because the disk budget was exceeded.
    budget_trimmed: int = 0
    collector_errors: dict[str, str] = field(default_factory=dict)
    #: Sources refused because ``max_sources`` were already followed.
    refused: list[str] = field(default_factory=list)


class IngestPipeline:
    """Owns collector tasks, the writer task and the in-memory ring buffers.

    Use ``async with IngestPipeline(...) as p: p.add_source(...)``.
    """

    def __init__(
        self,
        storage: Storage,
        collectors: Mapping[SourceKind, Collector],
        *,
        limits: PipelineLimits = PipelineLimits(),
        retention: RetentionPolicy | None = RetentionPolicy(),  # noqa: B008
        retention_interval: float = 60.0,
        normalizer: Callable[[LogSource, RawRecord], LogEntry] | None = None,
        assembler: MultilineAssembler | None = None,
        redactor: Redactor | None = None,
        max_sources: int = 64,
    ) -> None:
        self._storage = storage
        self._collectors = dict(collectors)
        self._limits = limits
        self._retention = retention
        self._retention_interval = retention_interval
        self._normalize = normalizer or Normalizer()
        #: Secrets are removed here, before storage, the ring buffers and subscribers.
        self._redactor = redactor
        self._max_sources = max_sources
        self._assembler = assembler or MultilineAssembler()
        self._sources: dict[str, LogSource] = {}
        self._queue: asyncio.Queue[RawRecord | None] = asyncio.Queue(limits.queue_size)
        self._tasks: dict[str, asyncio.Task[None]] = {}
        self._rings: defaultdict[str, deque[LogEntry]] = defaultdict(
            lambda: deque(maxlen=limits.ring_size)
        )
        self._subscribers: list[Subscriber] = []
        self._writer: asyncio.Task[None] | None = None
        self._janitor: asyncio.Task[None] | None = None
        self._memory_ids = itertools.count(-1, -1)
        self.stats = PipelineStats()

    async def __aenter__(self) -> IngestPipeline:
        await self.start()
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.stop()

    async def start(self) -> None:
        """Start the writer (and retention) tasks."""
        self._writer = asyncio.create_task(self._write_loop(), name="loglens-writer")
        if self._retention is not None:
            self._janitor = asyncio.create_task(
                self._retention_loop(self._retention), name="loglens-retention"
            )

    async def stop(self) -> None:
        """Stop collectors, flush what is queued, stop the writer."""
        for source_id in list(self._tasks):
            await self.remove_source(source_id)
        if self._janitor is not None:
            self._janitor.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._janitor
        if self._writer is not None:
            await self._queue.put(None)  # sentinel: flush and exit
            await self._writer
            self._writer = None

    def add_source(
        self, source: LogSource, *, since: datetime | None = None, lines: int = 0
    ) -> None:
        """Start collecting ``source``. Resumes from the stored cursor when there is one;
        otherwise starts at ``since`` / the last ``lines`` lines / now."""
        if source.id in self._tasks:
            return
        if len(self._tasks) >= self._max_sources:
            if source.id not in self.stats.refused:
                self.stats.refused.append(source.id)
            log.warning("collector limit reached", extra={"source": source.id})
            return
        self._sources[source.id] = source
        self._tasks[source.id] = asyncio.create_task(
            self._collect(source, since, lines), name=f"collect:{source.id}"
        )

    async def remove_source(self, source_id: str) -> None:
        """Stop collecting a source (its ring buffer is kept)."""
        task = self._tasks.pop(source_id, None)
        if task is not None:
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await task

    def subscribe(self, subscriber: Subscriber) -> Callable[[], None]:
        """Call ``subscriber(entries)`` after every stored batch; returns an unsubscribe."""
        self._subscribers.append(subscriber)
        return lambda: self._subscribers.remove(subscriber)

    def recent(self, source_id: str) -> list[LogEntry]:
        """The ring buffer for a source, oldest first."""
        return list(self._rings.get(source_id, ()))

    @property
    def sources(self) -> list[str]:
        """Ids of sources currently being collected."""
        return list(self._tasks)

    async def _collect(self, source: LogSource, since: datetime | None, lines: int) -> None:
        try:
            collector = self._collectors.get(source.kind)
            if collector is None:
                raise LookupError(f"no collector for {source.kind.value} sources")
            await asyncio.to_thread(self._storage.upsert_source, source)
            cursor = await asyncio.to_thread(self._storage.cursor_for, source.id)
            stream = collector.stream(
                source, cursor=cursor, since=since, lines=lines, on_error=self._on_error
            )
            async for record in stream:
                await self._queue.put(record)  # blocks when full: backpressure
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            log.exception("collector stopped", extra={"source": source.id})
            self._on_error(source.id, exc)

    def _on_error(self, source_id: str, exc: BaseException) -> None:
        self.stats.collector_errors[source_id] = f"{type(exc).__name__}: {exc}"

    async def _write_loop(self) -> None:
        loop = asyncio.get_running_loop()
        limits = self._limits
        done = False
        while not done:
            if self._assembler.pending:  # wake up to emit events whose source went quiet
                try:
                    first = await asyncio.wait_for(self._queue.get(), self._assembler.idle)
                except TimeoutError:
                    await self._flush([])
                    continue
            else:
                first = await self._queue.get()
            if first is None:
                break
            batch = [first]
            deadline = loop.time() + limits.flush_interval
            self.stats.max_queue = max(self.stats.max_queue, self._queue.qsize() + 1)
            while len(batch) < limits.batch_size:
                try:
                    item = self._queue.get_nowait()
                except asyncio.QueueEmpty:
                    remaining = deadline - loop.time()
                    if remaining <= 0:
                        break
                    try:
                        item = await asyncio.wait_for(self._queue.get(), remaining)
                    except TimeoutError:
                        break
                if item is None:
                    done = True
                    break
                batch.append(item)
            await self._flush(batch)
        await self._flush([], final=True)

    async def _flush(self, records: list[RawRecord], *, final: bool = False) -> None:
        self.stats.received += len(records)
        now = asyncio.get_running_loop().time()
        events = [event for r in records for event in self._assembler.feed(r, now)]
        events += self._assembler.flush() if final else self._assembler.flush_idle(now)
        if not events:
            return
        entries = [self._normalize(self._sources[r.source_id], r) for r in events]
        if self._redactor is not None:
            entries = [self._redactor.redact_entry(e) for e in entries]
            self.stats.redacted += sum(1 for e in entries if "redacted" in e.fields)
        # Only emitted events carry cursors, so a line still pending in the assembler is
        # never covered by a stored cursor. dict keeps the last cursor per source.
        cursors = {r.source_id: r.cursor for r in events if r.cursor is not None}
        try:
            stored = await asyncio.to_thread(self._storage.write_batch, entries, cursors)
            self.stats.stored += len(stored)
        except Exception:
            log.exception("storage write failed; delivering batch live only")
            self.stats.storage_errors += 1
            stored = [replace(e, id=next(self._memory_ids)) for e in entries]
        self.stats.batches += 1
        for entry in stored:
            self._rings[entry.source_id].append(entry)
        for subscriber in list(self._subscribers):
            try:
                subscriber(stored)
            except Exception:
                log.exception("pipeline subscriber failed")

    async def _retention_loop(self, policy: RetentionPolicy) -> None:
        while True:
            try:
                await asyncio.to_thread(self._storage.apply_retention, policy)
                self.stats.budget_trimmed = self._storage.budget_trimmed
            except Exception:
                log.exception("retention failed")
            await asyncio.sleep(self._retention_interval)
