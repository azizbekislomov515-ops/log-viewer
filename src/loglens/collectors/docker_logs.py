"""Collect container logs through the Docker API (``GET /containers/{id}/logs``).

The container is followed **by name**, so a restarted or recreated container (``docker
compose up`` gives it a new id) is picked up again. When the log stream ends (container
stopped/removed) the shared reconnect loop polls with backoff until it is back.

Resume cursor: ``<timestamp_ns>:<n>`` = the last delivered line's Docker timestamp and how
many lines carried exactly that timestamp. Docker's ``since`` only has second resolution
and is inclusive, so on reattach we ask from the start of that second and drop everything
up to the cursor. That is what makes kill/restart and recreate duplicate-free.
"""

from __future__ import annotations

import asyncio
import concurrent.futures
import contextlib
import functools
import logging
import struct
import threading
import time
from collections.abc import AsyncIterator, Callable, Iterator, Mapping
from datetime import UTC, datetime, timedelta
from typing import Any, Protocol

from loglens.collectors.base import (
    Backoff,
    ErrorCallback,
    LineSplitter,
    decode,
    merge_streams,
    reconnecting,
)
from loglens.core.models import LogSource, RawRecord

log = logging.getLogger(__name__)

_EPOCH = datetime(1970, 1, 1, tzinfo=UTC)
_HEADER = struct.Struct(">BxxxL")
_READ_SIZE = 64 * 1024
#: Batches (one per Docker frame) buffered between the reader thread and the event loop.
HANDOFF_BATCHES = 8
_STREAM_NAMES = {2: "stderr"}  # 1 = stdout; anything else is treated as stdout


class LogStream(Protocol):
    """A raw, blocking Docker log response body."""

    def read(self, n: int) -> bytes:
        """Read exactly ``n`` bytes (fewer only at EOF)."""
        ...

    def read1(self, n: int) -> bytes:
        """Read up to ``n`` bytes, returning as soon as any are available (b"" at EOF)."""
        ...

    def close(self) -> None:
        """Abort the stream; must unblock a ``read`` running in another thread."""
        ...


class DockerLogAPI(Protocol):
    """The two Docker calls the collector needs (an adapter over the SDK; faked in tests)."""

    def inspect(self, name: str) -> Mapping[str, Any] | None:
        """Container details, or None if no container has that name."""
        ...

    def open_logs(self, container_id: str, params: Mapping[str, Any]) -> LogStream:
        """Start a log stream with the given query parameters."""
        ...

    def close(self) -> None:
        """Release the client."""
        ...


class _SdkLogStream:
    def __init__(self, response: Any) -> None:
        self._response = response

    def read(self, n: int) -> bytes:
        data: bytes = self._response.raw.read(n)
        return data

    def read1(self, n: int) -> bytes:
        data: bytes = self._response.raw.read1(n)
        return data

    def close(self) -> None:
        from docker.types.daemon import CancellableStream  # noqa: PLC0415

        try:
            CancellableStream(iter(()), self._response).close()  # shuts the socket down
        except Exception:
            self._response.close()


class SdkDockerLogAPI:
    """``DockerLogAPI`` backed by the official SDK.

    Uses ``APIClient._get``/``_url``/``_raise_for_status``: the SDK's public ``logs()``
    merges stdout and stderr, but we need each frame's stream type to tag it. This mirrors
    what the SDK itself does internally for multiplexed streams.
    """

    def __init__(self, timeout: int = 10) -> None:
        import docker  # noqa: PLC0415

        self._client = docker.from_env(timeout=timeout)
        self._not_found = docker.errors.NotFound

    def inspect(self, name: str) -> Mapping[str, Any] | None:
        try:
            info: Mapping[str, Any] = self._client.api.inspect_container(name)
        except self._not_found:
            return None
        return info

    def open_logs(self, container_id: str, params: Mapping[str, Any]) -> LogStream:
        api: Any = self._client.api
        response = api._get(
            api._url("/containers/{0}/logs", container_id),
            params=dict(params),
            stream=True,
        )
        api._raise_for_status(response)
        api._disable_socket_timeout(api._get_raw_response_socket(response))
        return _SdkLogStream(response)

    def events(self, name: str, since: int) -> EventStream:
        """Lifecycle events of container ``name`` since ``since`` (epoch seconds)."""
        stream: EventStream = self._client.api.events(
            since=since, filters={"container": name, "type": "container"}, decode=True
        )
        return stream

    def close(self) -> None:
        self._client.close()


class EventStream(Protocol):
    """A blocking iterator of decoded Docker event dicts that can be closed."""

    def __iter__(self) -> Iterator[Mapping[str, Any]]:
        """Yield events as they happen."""
        ...

    def close(self) -> None:
        """Stop the stream (unblocks the reading thread)."""
        ...


#: Container actions shown in the container's own stream. ``exec_*`` (every health check
#: runs one) and ``attach``/``resize``/``top`` are noise.
EVENT_ACTIONS = frozenset(
    {
        "create",
        "start",
        "restart",
        "die",
        "kill",
        "oom",
        "stop",
        "pause",
        "unpause",
        "destroy",
        "health_status",
    }
)
#: How far back lifecycle events are read the first time a container is followed.
EVENT_HISTORY_S = 3600


def event_record(source_id: str, event: Mapping[str, Any]) -> tuple[int, RawRecord] | None:
    """A Docker event as ``(time_ns, record)`` in ``docker events`` text form, e.g.
    ``2026-11-19T08:26:10.563+00:00 container die 4f1e... (exitCode=1, image=x, name=y)``.

    Labels (dotted keys) are left out; the rule packs match this text. None for noise.
    """
    action = str(event.get("Action") or event.get("status") or "")
    if action.split(":", 1)[0] not in EVENT_ACTIONS:
        return None
    actor = event.get("Actor") or {}
    attributes = actor.get("Attributes") or {}
    container_id = str(actor.get("ID") or event.get("id") or "")
    time_ns = int(event.get("timeNano") or int(event.get("time") or 0) * 1_000_000_000)
    stamp = datetime.fromtimestamp(time_ns / 1e9, UTC)
    details = ", ".join(f"{k}={v}" for k, v in sorted(attributes.items()) if "." not in k)
    text = (
        f"{stamp.isoformat(timespec='milliseconds')} container {action} {container_id} ({details})"
    )
    return time_ns, RawRecord(source_id, text, stamp, fields={"stream": "events"})


class DockerCollector:
    """Follows a container's stdout/stderr by name across restarts and recreation."""

    def __init__(
        self,
        api_factory: Callable[[], DockerLogAPI] = SdkDockerLogAPI,
        *,
        backoff_max: float = 5.0,
        events: bool = True,
    ) -> None:
        self._api_factory = api_factory
        self._backoff_max = backoff_max
        self._events = events

    def stream(
        self,
        source: LogSource,
        *,
        cursor: str | None = None,
        since: datetime | None = None,
        lines: int = 0,
        follow: bool = True,
        on_error: ErrorCallback | None = None,
    ) -> AsyncIterator[RawRecord]:
        """Stream container log lines for ``source`` (see ``Collector``)."""
        name = str(source.metadata.get("container_name") or source.id.removeprefix("docker:"))

        def open_stream(cur: str | None) -> AsyncIterator[RawRecord]:
            return self._attach(
                source.id, name, cursor=cur, since=since, lines=lines, follow=follow
            )

        logs = reconnecting(
            open_stream,
            source.id,
            cursor=cursor,
            follow=follow,
            backoff=Backoff(maximum=self._backoff_max),
            on_error=on_error,
        )
        if not (follow and self._events):
            return logs
        # Lifecycle events (start, die with exit code, oom, health) join the container's own
        # stream. On resume, from the last stored log line's time (a few duplicate events
        # are possible across app restarts); otherwise the last hour of history.
        resume_ns = Position.parse(cursor).resume_ts
        since_ns = resume_ns or (time.time_ns() - EVENT_HISTORY_S * 1_000_000_000)
        return merge_streams(logs, self._lifecycle(source.id, name, since_ns, on_error))

    async def _lifecycle(
        self, source_id: str, name: str, since_ns: int, on_error: ErrorCallback | None
    ) -> AsyncIterator[RawRecord]:
        """Follow ``name``'s lifecycle events forever, reconnecting with backoff. Events
        carry no cursor: the source's resume cursor stays the log position."""
        backoff = Backoff(maximum=self._backoff_max)
        while True:
            api = await asyncio.to_thread(self._api_factory)
            try:
                events = getattr(api, "events", None)
                if events is None:
                    return  # an API without events (tests, old adapters)
                stream = await asyncio.to_thread(events, name, since_ns // 1_000_000_000)
                async for event in _iterate_in_thread(stream, f"docker-events:{name}"):
                    found = event_record(source_id, event)
                    if found is None or found[0] <= since_ns:
                        continue  # noise, or already delivered (``since`` is in seconds)
                    since_ns = found[0]
                    backoff.reset()
                    yield found[1]
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                log.warning("docker events error, will retry", extra={"source": source_id})
                if on_error is not None:
                    on_error(source_id, exc)
            finally:
                await asyncio.to_thread(api.close)
            await asyncio.sleep(backoff.next_delay())

    async def _attach(
        self,
        source_id: str,
        name: str,
        *,
        cursor: str | None,
        since: datetime | None,
        lines: int,
        follow: bool,
    ) -> AsyncIterator[RawRecord]:
        api = await asyncio.to_thread(self._api_factory)
        try:
            info = await asyncio.to_thread(api.inspect, name)
            if info is None:
                return  # gone, maybe being recreated: the reconnect loop polls
            position = Position.parse(cursor)
            params: dict[str, Any] = {
                "stdout": 1,
                "stderr": 1,
                "timestamps": 1,
                "follow": int(follow),
            }
            if position.resume_ts:
                params["since"] = max(1, position.resume_ts // 1_000_000_000)
            elif since is not None:
                params["since"] = max(1, int(since.timestamp()))
            else:
                params["tail"] = str(max(lines, 0))
            tty = bool((info.get("Config") or {}).get("Tty"))
            stream = await asyncio.to_thread(api.open_logs, str(info["Id"]), params)
            async for record in _pump(stream, tty, source_id, position, name):
                yield record
        finally:
            await asyncio.to_thread(api.close)


async def _pump(
    stream: LogStream, tty: bool, source_id: str, position: Position, name: str
) -> AsyncIterator[RawRecord]:
    """Read the blocking stream in a thread; hand batches over through a bounded queue."""
    loop = asyncio.get_running_loop()
    queue: asyncio.Queue[list[RawRecord] | BaseException | None] = asyncio.Queue(HANDOFF_BATCHES)
    stop = threading.Event()

    def put(item: list[RawRecord] | BaseException | None) -> bool:
        future = asyncio.run_coroutine_threadsafe(queue.put(item), loop)
        while True:  # block (backpressure) but notice when the consumer has gone away
            try:
                future.result(timeout=0.5)
                return True
            except concurrent.futures.TimeoutError:
                if stop.is_set():
                    future.cancel()
                    return False

    def reader() -> None:
        try:
            for batch in read_records(stream, tty, source_id, position):
                if not put(batch):
                    return
            put(None)
        except BaseException as exc:
            if not stop.is_set():
                put(exc)

    thread = threading.Thread(target=reader, name=f"docker-logs:{name}", daemon=True)
    thread.start()
    try:
        while (item := await queue.get()) is not None:
            if isinstance(item, BaseException):
                raise item
            for record in item:
                yield record
    finally:
        stop.set()
        stream.close()
        await asyncio.to_thread(thread.join, 5)


async def _iterate_in_thread(stream: EventStream, name: str) -> AsyncIterator[Mapping[str, Any]]:
    """Consume a blocking iterator in a thread, with backpressure; closing the async
    iterator closes the stream (which unblocks the thread)."""
    loop = asyncio.get_running_loop()
    queue: asyncio.Queue[Mapping[str, Any] | BaseException | None] = asyncio.Queue(64)
    stop = threading.Event()

    def reader() -> None:
        try:
            for item in stream:
                if stop.is_set():
                    return
                asyncio.run_coroutine_threadsafe(queue.put(item), loop).result()
            asyncio.run_coroutine_threadsafe(queue.put(None), loop).result()
        except BaseException as exc:
            if not stop.is_set():
                with contextlib.suppress(Exception):
                    asyncio.run_coroutine_threadsafe(queue.put(exc), loop).result()

    thread = threading.Thread(target=reader, name=name, daemon=True)
    thread.start()
    try:
        while (item := await queue.get()) is not None:
            if isinstance(item, BaseException):
                raise item
            yield item
    finally:
        stop.set()
        with contextlib.suppress(Exception):
            stream.close()
        await asyncio.to_thread(thread.join, 5)


class Position:
    """Tracks the resume cursor and drops lines at or before it."""

    def __init__(self, ts: int = 0, count: int = 0) -> None:
        self.resume_ts = ts
        self._skip = count
        self.ts = ts
        self.count = count

    @classmethod
    def parse(cls, cursor: str | None) -> Position:
        """Parse ``<ts_ns>:<n>``; anything malformed means "no cursor"."""
        ts, _, count = (cursor or "").partition(":")
        if ts.isdigit() and count.isdigit():
            return cls(int(ts), int(count))
        return cls()

    def accept(self, ts: int) -> bool:
        """True if a line with Docker timestamp ``ts`` (ns) has not been delivered yet."""
        if ts < self.resume_ts:
            return False
        if ts == self.resume_ts and self._skip > 0:
            self._skip -= 1
            return False
        if ts == self.ts:
            self.count += 1
        elif ts > self.ts:
            self.ts, self.count = ts, 1
        return True

    @property
    def cursor(self) -> str:
        """Cursor for the last accepted line."""
        return f"{self.ts}:{self.count}"


def read_records(
    stream: LogStream, tty: bool, source_id: str, position: Position
) -> Iterator[list[RawRecord]]:
    """Blocking: decode frames into lines, then lines into records (one batch per read)."""
    splitters = {"stdout": LineSplitter(), "stderr": LineSplitter()}
    for stream_name, data in _frames(stream, tty):
        batch = []
        for line, truncated, _ in splitters[stream_name].feed(data):
            record = _to_record(source_id, stream_name, line, truncated, position)
            if record is not None:
                batch.append(record)
        if batch:
            yield batch
    tail = []
    for stream_name, splitter in splitters.items():
        if (rest := splitter.flush()) is not None:
            record = _to_record(source_id, stream_name, rest[0], rest[1], position)
            if record is not None:
                tail.append(record)
    if tail:
        yield tail


def _frames(stream: LogStream, tty: bool) -> Iterator[tuple[str, bytes]]:
    """Yield ``(stream_name, chunk)``. TTY output is one raw stream; otherwise each frame
    is ``[type, 0, 0, 0, size(4 BE)] + payload``. Payloads are read in bounded chunks."""
    if tty:
        while chunk := stream.read1(_READ_SIZE):
            yield "stdout", chunk
        return
    while len(header := stream.read(_HEADER.size)) == _HEADER.size:
        stream_type, remaining = _HEADER.unpack(header)
        name = _STREAM_NAMES.get(stream_type, "stdout")
        while remaining:
            chunk = stream.read(min(remaining, _READ_SIZE))
            if not chunk:
                return
            remaining -= len(chunk)
            yield name, chunk


def _to_record(
    source_id: str, stream_name: str, line: bytes, truncated: bool, position: Position
) -> RawRecord | None:
    text = decode(line)
    stamp, sep, message = text.partition(" ")
    ts = parse_timestamp_ns(stamp) if sep else None
    if ts is None:  # no timestamp prefix: keep the whole line, attribute it to the last time
        message, ts = text, position.ts
    elif not position.accept(ts):
        return None
    fields: dict[str, Any] = {"stream": stream_name}
    if truncated:
        fields["truncated"] = True
    return RawRecord(
        source_id=source_id,
        message=message,
        timestamp=_EPOCH + timedelta(microseconds=ts // 1000) if ts else None,
        fields=fields,
        cursor=position.cursor,
    )


def parse_timestamp_ns(stamp: str) -> int | None:
    """Parse Docker's RFC3339Nano UTC timestamp (``2026-11-17T22:50:01.123456789Z``)."""
    if not stamp.endswith("Z") or len(stamp) < 20:
        return None
    base, _, frac = stamp[:-1].partition(".")
    if not (frac.isdigit() or frac == ""):
        return None
    whole = _epoch_seconds(base)
    if whole is None:
        return None
    return whole * 1_000_000_000 + int(frac[:9].ljust(9, "0") or 0)


@functools.lru_cache(maxsize=8)  # consecutive lines share the same second; strptime is slow
def _epoch_seconds(base: str) -> int | None:
    try:
        seconds = datetime.strptime(base, "%Y-%m-%dT%H:%M:%S").replace(tzinfo=UTC)
    except ValueError:
        return None
    return (seconds - _EPOCH) // timedelta(seconds=1)
