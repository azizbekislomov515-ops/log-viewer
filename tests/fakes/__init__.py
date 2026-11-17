"""Test doubles for systemctl, the docker CLI/SDK, and discoverers."""

from __future__ import annotations

import asyncio
import contextlib
import datetime as _dt
import struct
import threading
from collections.abc import Callable, Iterable, Sequence
from typing import Any

from loglens.collectors.discovery.base import EXIT_NOT_FOUND, CommandResult
from loglens.core.models import DiscoveryResult


class FakeRunner:
    """CommandRunner that answers by argv prefix. Unmatched commands look 'not installed'."""

    def __init__(self, responses: dict[tuple[str, ...], CommandResult] | None = None) -> None:
        self.responses = responses or {}
        self.calls: list[list[str]] = []

    def __call__(self, args: Sequence[str], timeout: float = 10.0) -> CommandResult:
        argv = list(args)
        self.calls.append(argv)
        # Longest matching prefix wins so specific entries override generic ones.
        for prefix in sorted(self.responses, key=len, reverse=True):
            if tuple(argv[: len(prefix)]) == prefix:
                return self.responses[prefix]
        return CommandResult(EXIT_NOT_FOUND, "", f"command not found: {argv[0]}")


def ok(stdout: str = "") -> CommandResult:
    return CommandResult(0, stdout, "")


def fail(stderr: str, code: int = 1) -> CommandResult:
    return CommandResult(code, "", stderr)


class _FakeAPI:
    def __init__(self, rows: list[dict[str, Any]]) -> None:
        self.rows = rows
        self.list_calls: list[bool] = []

    def containers(self, *, all: bool = False) -> list[dict[str, Any]]:
        self.list_calls.append(all)
        return self.rows


class FakeDockerClient:
    def __init__(self, rows: list[dict[str, Any]]) -> None:
        self.api = _FakeAPI(rows)
        self.closed = False

    def close(self) -> None:
        self.closed = True


def raising_factory(exc: Exception) -> Callable[[], FakeDockerClient]:
    def factory() -> FakeDockerClient:
        raise exc

    return factory


def api_row(
    name: str,
    *,
    state: str = "running",
    status: str = "Up 2 hours",
    image: str = "nginx:latest",
    labels: dict[str, str] | None = None,
    container_id: str | None = None,
) -> dict[str, Any]:
    """A row shaped like Docker's ``GET /containers/json``."""
    return {
        "Id": container_id or (name.encode().hex() * 8)[:64],
        "Names": [f"/{name}"],
        "Image": image,
        "State": state,
        "Status": status,
        "Labels": labels or {},
    }


def compose_labels(project: str, service: str, number: int = 1) -> dict[str, str]:
    return {
        "com.docker.compose.project": project,
        "com.docker.compose.service": service,
        "com.docker.compose.container-number": str(number),
        "com.docker.compose.project.working_dir": f"/srv/{project}",
    }


class FakeDiscoverer:
    """Returns queued results in order (repeating the last); an Exception entry is raised."""

    def __init__(self, name: str, results: Iterable[DiscoveryResult | Exception]) -> None:
        self.name = name
        self._results = list(results)
        self.runs = 0

    def discover(self) -> DiscoveryResult:
        item = self._results[min(self.runs, len(self._results) - 1)]
        self.runs += 1
        if isinstance(item, Exception):
            raise item
        return item


# --- Docker log API fakes -------------------------------------------------------------


def rfc3339_ns(ts_ns: int) -> str:
    """Format like Docker's log timestamps (RFC3339Nano, fixed 9 digits, UTC)."""
    seconds, nanos = divmod(ts_ns, 1_000_000_000)
    base = _dt.datetime.fromtimestamp(seconds, _dt.UTC).strftime("%Y-%m-%dT%H:%M:%S")
    return f"{base}.{nanos:09d}Z"


def frame(stream: int, payload: bytes) -> bytes:
    """One multiplexed Docker frame (1 = stdout, 2 = stderr)."""
    return struct.pack(">BxxxL", stream, len(payload)) + payload


class FakeLogStream:
    """Thread-safe byte stream: data can be pushed while a reader blocks on it."""

    def __init__(self, data: bytes = b"", *, follow: bool = False) -> None:
        self._buf = bytearray(data)
        self._cond = threading.Condition()
        self._ended = not follow
        self.closed = False

    def push(self, data: bytes) -> None:
        with self._cond:
            self._buf += data
            self._cond.notify_all()

    def end(self) -> None:
        with self._cond:
            self._ended = True
            self._cond.notify_all()

    def close(self) -> None:
        self.closed = True
        self.end()

    def read(self, n: int) -> bytes:
        with self._cond:
            self._cond.wait_for(lambda: len(self._buf) >= n or self._ended)
            out = bytes(self._buf[:n])
            del self._buf[:n]
            return out

    def read1(self, n: int) -> bytes:
        with self._cond:
            self._cond.wait_for(lambda: bool(self._buf) or self._ended)
            out = bytes(self._buf[:n])
            del self._buf[:n]
            return out


class FakeContainer:
    def __init__(self, cid: str, *, running: bool = True, tty: bool = False) -> None:
        self.id = cid
        self.running = running
        self.tty = tty
        self.lines: list[tuple[int, int, str]] = []  # (ts_ns, stream, text)


class FakeLogAPI:
    """Mimics dockerd's log semantics: inclusive second-resolution ``since``, ``tail``,
    follow streams that end when the container stops, history kept across restarts."""

    def __init__(self) -> None:
        self.containers: dict[str, FakeContainer] = {}
        self.open_streams: list[tuple[str, FakeLogStream]] = []
        self.params: list[dict[str, Any]] = []

    # test controls
    def run(self, name: str, cid: str, *, tty: bool = False) -> None:
        self.containers[name] = FakeContainer(cid, tty=tty)

    def emit(self, name: str, ts_ns: int, text: str, stream: int = 1) -> None:
        container = self.containers[name]
        container.lines.append((ts_ns, stream, text))
        for cid, s in self.open_streams:
            if cid == container.id:
                s.push(self._encode(container, [(ts_ns, stream, text)]))

    def stop(self, name: str) -> None:
        container = self.containers[name]
        container.running = False
        for cid, s in self.open_streams:
            if cid == container.id:
                s.end()

    def start(self, name: str) -> None:
        self.containers[name].running = True

    def remove(self, name: str) -> None:
        self.stop(name)
        del self.containers[name]

    # DockerLogAPI
    def inspect(self, name: str) -> dict[str, Any] | None:
        c = self.containers.get(name)
        return None if c is None else {"Id": c.id, "Config": {"Tty": c.tty}}

    def open_logs(self, container_id: str, params: dict[str, Any]) -> FakeLogStream:
        self.params.append(dict(params))
        c = next(c for c in self.containers.values() if c.id == container_id)
        lines = c.lines
        if "since" in params:
            lines = [ln for ln in lines if ln[0] >= params["since"] * 1_000_000_000]
        elif "tail" in params:
            n = int(params["tail"])
            lines = lines[-n:] if n else []
        stream = FakeLogStream(self._encode(c, lines), follow=bool(params["follow"]) and c.running)
        self.open_streams.append((c.id, stream))
        return stream

    def close(self) -> None:
        pass

    @staticmethod
    def _encode(c: FakeContainer, lines: list[tuple[int, int, str]]) -> bytes:
        data = [(s, f"{rfc3339_ns(ts)} {text}\n".encode()) for ts, s, text in lines]
        if c.tty:
            return b"".join(d for _, d in data)
        return b"".join(frame(s, d) for s, d in data)


class FakeCollector:
    """Collector yielding scripted records/exceptions; records the arguments it got."""

    def __init__(self, items: Iterable[Any], *, hang: bool = True) -> None:
        self.items = list(items)
        self.hang = hang
        self.calls: list[dict[str, Any]] = []

    def stream(self, source: Any, **kwargs: Any) -> Any:
        self.calls.append({"source": source, **kwargs})
        return self._gen()

    async def _gen(self) -> Any:
        for item in self.items:
            if isinstance(item, BaseException):
                raise item
            yield item
            await asyncio.sleep(0)
        if self.hang:
            await asyncio.Event().wait()


async def take(stream: Any, n: int, timeout: float = 5.0) -> list[Any]:
    """Collect ``n`` items from an async iterator, then close it (runs its cleanup)."""
    out: list[Any] = []
    async with contextlib.aclosing(stream):
        async with asyncio.timeout(timeout):
            async for item in stream:
                out.append(item)
                if len(out) >= n:
                    break
    return out
