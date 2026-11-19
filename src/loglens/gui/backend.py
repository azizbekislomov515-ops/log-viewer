"""Backend: the asyncio side of the app (discovery + ingest pipeline) on its own thread.

GUI -> backend: ``follow``/``unfollow``/``refresh_discovery`` schedule work on the event
loop with ``call_soon_threadsafe`` and return immediately.

Backend -> GUI: low-rate events (sources, issues, stats) are Qt signals, delivered queued
to the GUI thread. Entries can arrive at tens of thousands per second, so they go into a
deque that the GUI drains on a timer (``take_entries``): one model update per frame, not
one signal per batch.
"""

from __future__ import annotations

import asyncio
import logging
import threading
import time
from collections import deque
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path

from PySide6.QtCore import QObject, Signal

from loglens.collectors.base import Collector
from loglens.collectors.discovery.base import Discoverer
from loglens.core.models import (
    DiscoveryIssue,
    LogEntry,
    LogSource,
    RawRecord,
    ServiceGroup,
    SourceKind,
)
from loglens.core.pipeline import IngestPipeline, PipelineLimits
from loglens.core.registry import SourceRegistry
from loglens.security.redact import Redactor
from loglens.storage import RetentionPolicy, Storage

log = logging.getLogger(__name__)

#: Lines of history read when a source is followed for the first time.
BACKLOG_LINES = 1000


@dataclass(frozen=True, slots=True)
class BackendStats:
    """Snapshot sent to the status bar once a second."""

    lines_per_s: float = 0.0
    collectors: int = 0
    stored: int = 0
    queued: int = 0
    collector_errors: Mapping[str, str] = field(default_factory=dict)
    #: Entries deleted because the disk budget was exceeded.
    budget_trimmed: int = 0
    #: Sources not followed because the collector limit was reached.
    refused: tuple[str, ...] = ()


class Backend(QObject):
    """Owns the event-loop thread, the registry, storage writes and the pipeline."""

    sourcesChanged = Signal(object, object)  # tuple[ServiceGroup], tuple[DiscoveryIssue]
    statsChanged = Signal(object)  # BackendStats
    failed = Signal(str)

    def __init__(
        self,
        db_path: Path | str,
        discoverers: Sequence[Discoverer],
        collectors: Mapping[SourceKind, Collector],
        *,
        retention: RetentionPolicy | None = None,
        discovery_interval: float = 30.0,
        limits: PipelineLimits | None = None,
        normalizer: Callable[[LogSource, RawRecord], LogEntry] | None = None,
        redactor: Redactor | None = None,
        max_sources: int = 64,
        parent: QObject | None = None,
    ) -> None:
        super().__init__(parent)
        self.db_path = db_path
        self._registry = SourceRegistry(discoverers)
        self._collectors = collectors
        self._retention = retention
        self._interval = discovery_interval
        self._limits = limits or PipelineLimits()
        self._normalizer = normalizer
        self._redactor = redactor
        self._max_sources = max_sources
        self._entries: deque[LogEntry] = deque()
        self._loop: asyncio.AbstractEventLoop | None = None
        self._pipeline: IngestPipeline | None = None
        self._stop: asyncio.Event | None = None
        self._ready = threading.Event()
        self._thread = threading.Thread(target=self._run, name="loglens-backend", daemon=True)
        self._last: tuple[tuple[ServiceGroup, ...], tuple[DiscoveryIssue, ...]] | None = None

    # ------------------------------------------------------------------ GUI-facing API

    def start(self) -> None:
        """Start the event-loop thread; returns once the pipeline accepts sources."""
        self._thread.start()
        self._ready.wait(10)

    def stop(self) -> None:
        """Stop collectors, flush, close storage, join the thread."""
        if self._loop is not None and self._stop is not None:
            self._loop.call_soon_threadsafe(self._stop.set)
        if self._thread.is_alive():
            self._thread.join(15)

    def follow(self, source: LogSource) -> None:
        """Start collecting ``source`` (no-op if already followed)."""
        self._call(lambda p: p.add_source(source, lines=BACKLOG_LINES))

    def unfollow(self, source_id: str) -> None:
        """Stop collecting a source."""
        self._call(lambda p: asyncio.ensure_future(p.remove_source(source_id)))

    def refresh_discovery(self) -> None:
        """Run discovery now (results arrive through ``sourcesChanged``)."""
        if self._loop is not None:
            self._loop.call_soon_threadsafe(lambda: asyncio.ensure_future(self._discover_once()))

    def take_entries(self, limit: int = 200_000) -> list[LogEntry]:
        """Drain entries delivered since the last call (GUI thread)."""
        out: list[LogEntry] = []
        pop = self._entries.popleft
        try:
            for _ in range(limit):
                out.append(pop())
        except IndexError:
            pass
        return out

    @property
    def backlog(self) -> int:
        """Entries waiting for the GUI."""
        return len(self._entries)

    # ------------------------------------------------------------------ event-loop side

    def _call(self, fn: object) -> None:
        loop, pipeline = self._loop, self._pipeline
        if loop is None or pipeline is None:
            return
        loop.call_soon_threadsafe(fn, pipeline)  # type: ignore[arg-type]

    def _run(self) -> None:
        try:
            asyncio.run(self._main())
        except Exception as exc:
            log.exception("backend crashed")
            self.failed.emit(f"Background service stopped: {exc}")
        finally:
            self._ready.set()

    async def _main(self) -> None:
        self._loop = asyncio.get_running_loop()
        self._stop = asyncio.Event()
        with Storage(self.db_path) as storage:
            pipeline = IngestPipeline(
                storage,
                self._collectors,
                limits=self._limits,
                retention=self._retention,
                normalizer=self._normalizer,
                redactor=self._redactor,
                max_sources=self._max_sources,
            )
            async with pipeline:
                pipeline.subscribe(self._entries.extend)
                self._pipeline = pipeline
                self._ready.set()
                tasks = [
                    asyncio.create_task(self._discovery_loop()),
                    asyncio.create_task(self._stats_loop(pipeline)),
                ]
                await self._stop.wait()
                for task in tasks:
                    task.cancel()
                await asyncio.gather(*tasks, return_exceptions=True)
                self._pipeline = None

    async def _discovery_loop(self) -> None:
        while True:
            await self._discover_once()
            await asyncio.sleep(self._interval)

    async def _discover_once(self) -> None:
        try:
            await asyncio.to_thread(self._registry.refresh)
        except Exception as exc:  # the registry already isolates discoverers
            log.exception("discovery failed")
            self.failed.emit(f"Discovery failed: {exc}")
            return
        snapshot = (self._registry.groups, self._registry.issues)
        if snapshot != self._last:
            self._last = snapshot
            self.sourcesChanged.emit(*snapshot)

    def clear_secrets(self) -> None:
        """Forget the secrets the live redactor kept for reveal (Clear all data)."""
        if self._redactor is not None and self._redactor.vault is not None:
            self._redactor.vault.clear()

    async def _stats_loop(self, pipeline: IngestPipeline) -> None:
        last_received, last_time = pipeline.stats.received, time.monotonic()
        while True:
            await asyncio.sleep(1.0)
            now = time.monotonic()
            received = pipeline.stats.received
            self.statsChanged.emit(
                BackendStats(
                    lines_per_s=(received - last_received) / (now - last_time),
                    collectors=len(pipeline.sources),
                    stored=pipeline.stats.stored,
                    queued=pipeline.stats.max_queue,
                    collector_errors=dict(pipeline.stats.collector_errors),
                    budget_trimmed=pipeline.stats.budget_trimmed,
                    refused=tuple(pipeline.stats.refused),
                )
            )
            last_received, last_time = received, now
