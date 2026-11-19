import asyncio
import contextlib
import threading
from datetime import UTC, datetime

import pytest

from loglens.collectors import source_from_id
from loglens.collectors.docker_logs import (
    DockerCollector,
    Position,
    parse_timestamp_ns,
    read_records,
)
from loglens.core.models import LogSource, RawRecord
from tests.fakes import FakeLogAPI, FakeLogStream, frame, rfc3339_ns, take

T = 1_794_939_061 * 1_000_000_000  # a whole second, in ns


def source() -> LogSource:
    return source_from_id("docker:web")


def test_parse_timestamp_ns() -> None:
    assert parse_timestamp_ns(rfc3339_ns(T + 123_456_789)) == T + 123_456_789
    assert parse_timestamp_ns("2026-11-17T22:50:01.5Z") == parse_timestamp_ns(
        "2026-11-17T22:50:01.500000000Z"
    )
    assert parse_timestamp_ns("2026-11-17T22:50:01Z") is not None
    for bad in ["", "hello", "2026-11-17T22:50:01.12x4Z", "2026-13-45T00:00:00.0Z"]:
        assert parse_timestamp_ns(bad) is None


def test_position_skips_up_to_cursor_including_same_timestamp_lines() -> None:
    p = Position.parse(f"{T}:2")  # two lines at exactly T were already delivered
    assert [p.accept(ts) for ts in (T - 1, T, T, T, T + 5)] == [False, False, False, True, True]
    assert p.cursor == f"{T + 5}:1"
    q = Position.parse(None)
    assert q.accept(T) and q.accept(T)
    assert q.cursor == f"{T}:2"
    assert Position.parse("garbage").resume_ts == 0


def _records(data: bytes, *, tty: bool = False, cursor: str | None = None) -> list[RawRecord]:
    stream = FakeLogStream(data)
    batches = read_records(stream, tty, "docker:web", Position.parse(cursor))
    return [r for batch in batches for r in batch]


def test_demultiplexes_and_tags_streams() -> None:
    data = (
        frame(1, f"{rfc3339_ns(T + 1)} hello\n".encode())
        + frame(2, f"{rfc3339_ns(T + 2)} boom\n{rfc3339_ns(T + 3)} more".encode())
        + frame(2, b" stderr\n")  # one line split across frames
    )
    recs = _records(data)
    assert [(r.fields["stream"], r.message) for r in recs] == [
        ("stdout", "hello"),
        ("stderr", "boom"),
        ("stderr", "more stderr"),
    ]
    assert recs[0].timestamp is not None
    assert recs[0].timestamp.microsecond == 0  # 1ns rounds down
    assert recs[-1].cursor == f"{T + 3}:1"


def test_tty_stream_is_raw_stdout_with_crlf() -> None:
    data = f"{rfc3339_ns(T)} a\r\n{rfc3339_ns(T + 1)} b\r\n".encode()
    recs = _records(data, tty=True)
    assert [(r.message, r.fields["stream"]) for r in recs] == [("a", "stdout"), ("b", "stdout")]


def test_very_long_line_is_truncated_not_buffered() -> None:
    huge = b"x" * (5 * 1024 * 1024)
    data = frame(1, f"{rfc3339_ns(T)} ".encode() + huge + b"\n") + frame(
        1, f"{rfc3339_ns(T + 1)} after\n".encode()
    )
    recs = _records(data)
    assert recs[0].fields["truncated"] is True
    assert len(recs[0].message) < 70 * 1024
    assert recs[1].message == "after"


def test_resume_cursor_drops_already_delivered_lines() -> None:
    data = b"".join(
        frame(1, f"{rfc3339_ns(ts)} {msg}\n".encode())
        for ts, msg in [(T, "a"), (T, "b"), (T + 7, "c")]
    )
    assert [r.message for r in _records(data, cursor=f"{T}:1")] == ["b", "c"]


async def test_start_params_follow_precedence() -> None:
    api = FakeLogAPI()
    api.run("web", "c1")
    api.stop("web")
    collector = DockerCollector(lambda: api)
    await take(collector.stream(source(), lines=5, follow=False), 1, timeout=2)
    since = datetime(2026, 1, 1, tzinfo=UTC)
    await take(collector.stream(source(), since=since, follow=False), 1, timeout=2)
    await take(collector.stream(source(), cursor=f"{T + 9}:1", follow=False), 1, timeout=2)
    assert api.params[0] == {"stdout": 1, "stderr": 1, "timestamps": 1, "follow": 0, "tail": "5"}
    assert api.params[1]["since"] == int(since.timestamp())
    assert api.params[2]["since"] == T // 1_000_000_000  # start of the cursor's second


async def _wait_for(predicate, timeout: float = 5.0) -> None:  # type: ignore[no-untyped-def]
    async with asyncio.timeout(timeout):
        while not predicate():
            await asyncio.sleep(0.01)


async def test_kill_restart_and_recreate_reattach_without_duplicates() -> None:
    """Acceptance: tailing survives stop/start and compose-style recreation, no dupes."""
    api = FakeLogAPI()
    api.run("web", "c1")
    api.emit("web", T + 100, "boot 1")
    api.emit("web", T + 100, "same-ns twin")  # identical timestamps happen
    collector = DockerCollector(lambda: api, backoff_max=0.02)
    got: list[str] = []

    async def consume() -> None:
        async for record in collector.stream(source(), lines=100):
            got.append(record.message)

    task = asyncio.create_task(consume())
    try:
        await _wait_for(lambda: len(got) == 2)
        api.emit("web", T + 200, "live line")  # arrives on the open follow stream
        await _wait_for(lambda: len(got) == 3)

        api.stop("web")  # docker kill: stream ends; history (same second!) is kept
        await asyncio.sleep(0.1)  # collector polls the stopped container a few times
        api.start("web")
        api.emit("web", T + 300, "boot 2")  # same second as everything before
        await _wait_for(lambda: len(got) == 4)

        api.remove("web")  # docker compose up --force-recreate: new id, same name
        await asyncio.sleep(0.1)
        api.run("web", "c2")
        api.emit("web", T + 2_000_000_000, "boot 3 (new container)")
        await _wait_for(lambda: len(got) == 5)
        await asyncio.sleep(0.1)  # give a duplicate the chance to show up
    finally:
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task

    assert got == ["boot 1", "same-ns twin", "live line", "boot 2", "boot 3 (new container)"]
    assert all(s.closed or not s._buf for _, s in api.open_streams)


async def test_cancel_stops_reader_thread() -> None:
    api = FakeLogAPI()
    api.run("web", "c1")
    api.emit("web", T, "x")
    records = await take(DockerCollector(lambda: api).stream(source(), lines=10), 1)
    assert [r.message for r in records] == ["x"]
    await _wait_for(
        lambda: not any(t.name.startswith("docker-logs:") for t in threading.enumerate())
    )
    assert api.open_streams[0][1].closed


@pytest.mark.parametrize("missing_first", [True, False])
async def test_waits_for_container_to_appear(missing_first: bool) -> None:
    api = FakeLogAPI()
    if not missing_first:
        api.run("web", "c1")
        api.stop("web")
    collector = DockerCollector(lambda: api, backoff_max=0.02)
    stream = collector.stream(source(), lines=10)

    async def later() -> None:
        await asyncio.sleep(0.1)
        if missing_first:
            api.run("web", "c9")
        else:
            api.start("web")
        api.emit("web", T, "finally")

    helper = asyncio.create_task(later())
    records = await take(stream, 1)
    await helper
    assert records[0].message == "finally"


# ---------------------------------------------------------------- lifecycle events

import queue as _queue  # noqa: E402
import time  # noqa: E402

from loglens.collectors.base import merge_streams  # noqa: E402
from loglens.collectors.docker_logs import event_record  # noqa: E402


def _event(action: str, ns: int, **attrs: str) -> dict[str, object]:
    return {"Action": action, "timeNano": ns, "Actor": {"ID": "4f1e2d3c4b5a", "Attributes": attrs}}


def test_event_record_text_matches_docker_events_format() -> None:
    found = event_record(
        "docker:web",
        _event(
            "die",
            T,
            exitCode="137",
            image="nginx",
            name="web",
            **{"com.docker.compose.project": "shop"},
        ),
    )
    assert found is not None
    ns, record = found
    assert ns == T and record.fields["stream"] == "events" and record.cursor is None
    assert record.message.endswith(
        "container die 4f1e2d3c4b5a (exitCode=137, image=nginx, name=web)"
    )  # labels (dotted keys) left out
    assert event_record("docker:web", _event("exec_start: sh -c curl", T)) is None  # noise
    health = event_record("docker:web", _event("health_status: unhealthy", T, name="web"))
    assert health is not None and "health_status: unhealthy" in health[1].message


class FakeEventStream:
    def __init__(self) -> None:
        self.items: _queue.Queue[object] = _queue.Queue()
        self.closed = False

    def __iter__(self):  # type: ignore[no-untyped-def]
        while (item := self.items.get()) is not None:
            yield item

    def close(self) -> None:
        self.closed = True
        self.items.put(None)


class EventAPI(FakeLogAPI):
    def __init__(self) -> None:
        super().__init__()
        self.event_streams: list[FakeEventStream] = []
        self.since: list[int] = []

    def events(self, name: str, since: int) -> FakeEventStream:
        stream = FakeEventStream()
        self.since.append(since)
        self.event_streams.append(stream)
        return stream


async def test_lifecycle_events_join_the_container_stream() -> None:
    from loglens.explain import ExplanationEngine  # noqa: PLC0415
    from loglens.parsers import Normalizer  # noqa: PLC0415

    api = EventAPI()
    api.run("web", "4f1e2d3c4b5a")
    api.emit("web", T, "booting")
    collector = DockerCollector(lambda: api, backoff_max=0.01)
    stream = collector.stream(source(), lines=10, follow=True)
    got = [await asyncio.wait_for(anext(stream), 2)]
    while not api.event_streams:
        await asyncio.sleep(0.01)
    events = api.event_streams[0]
    now = time.time_ns()
    events.items.put(_event("die", now - 7200 * 10**9, exitCode="1", name="web"))  # too old
    events.items.put(_event("exec_create: curl", now + 1))
    events.items.put(_event("die", now + 2, exitCode="137", image="nginx", name="web"))
    events.items.put(_event("die", now + 2, exitCode="137", image="nginx", name="web"))  # dup
    events.items.put(_event("start", now + 3, image="nginx", name="web"))
    got += [await asyncio.wait_for(anext(stream), 2) for _ in range(2)]
    await stream.aclose()  # type: ignore[attr-defined]
    assert [r.message.split(" ", 1)[-1][:15] for r in got] == [
        "booting",
        "container die 4",
        "container start",
    ]
    assert all(r.cursor is None for r in got[1:])  # the log cursor stays the resume point
    assert abs(api.since[0] - (time.time() - 3600)) < 60  # first follow: last hour
    assert events.closed
    engine = ExplanationEngine.from_directory()
    explained = engine.explain(Normalizer()(source(), got[1]))
    assert explained is not None and explained.rule_id == "docker.container.exit_137"
    assert explained.extracted["code"] == "137" and "exit" in explained.tags


async def test_events_are_skipped_without_follow_or_support() -> None:
    api = FakeLogAPI()
    api.run("web", "4f1e2d3c4b5a")
    api.emit("web", T, "only logs")
    records = await take(DockerCollector(lambda: api).stream(source(), lines=10, follow=False), 1)
    assert [r.message for r in records] == ["only logs"]


async def test_merge_streams_interleaves_and_propagates_errors() -> None:
    async def gen(*items: object):  # type: ignore[no-untyped-def]
        for item in items:
            if isinstance(item, Exception):
                raise item
            yield RawRecord("s", str(item))

    merged = [r.message async for r in merge_streams(gen("a", "b"), gen("c"))]
    assert sorted(merged) == ["a", "b", "c"]
    with pytest.raises(RuntimeError, match="boom"):
        async for _ in merge_streams(gen("a"), gen(RuntimeError("boom"))):
            pass
