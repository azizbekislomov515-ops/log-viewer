import asyncio
import time
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path

import pytest

from loglens.collectors import source_from_id
from loglens.core.models import LogEntry, RawRecord, Severity, SourceKind
from loglens.core.pipeline import IngestPipeline, PipelineLimits
from loglens.parsers import MAX_MESSAGE_CHARS, MultilineAssembler, Normalizer
from loglens.storage import Storage
from tests.fakes import FakeCollector

FAST = PipelineLimits(queue_size=16, batch_size=4, flush_interval=0.01, ring_size=3)


def rec(source: str, msg: str, cursor: str | None = None) -> RawRecord:
    return RawRecord(source, msg, cursor=cursor)


async def wait_until(predicate, timeout: float = 5.0) -> None:  # type: ignore[no-untyped-def]
    async with asyncio.timeout(timeout):
        while not predicate():
            await asyncio.sleep(0.01)


@pytest.fixture
def storage(tmp_path: Path):  # type: ignore[no-untyped-def]
    with Storage(tmp_path / "db.sqlite") as s:
        yield s


def test_normalize_defaults_and_caps() -> None:
    normalize = Normalizer()
    src = source_from_id("systemd:x.service")
    at = datetime(2026, 1, 1, tzinfo=UTC)
    e = normalize(src, RawRecord("s", "hi", timestamp=at, severity=Severity.ERROR, fields={"k": 1}))
    assert (e.id, e.timestamp, e.severity, e.raw, e.parsed) == (0, at, Severity.ERROR, "hi", False)
    d = normalize(src, RawRecord("s", "x" * (MAX_MESSAGE_CHARS + 5)))
    assert d.severity is Severity.INFO
    assert d.timestamp.tzinfo is UTC
    assert len(d.message) == MAX_MESSAGE_CHARS
    assert d.fields["truncated"] is True


async def test_end_to_end_store_ring_subscribers(storage: Storage) -> None:
    collector = FakeCollector([rec("docker:web", f"m{i}", f"c{i}") for i in range(10)])
    batches: list[Sequence[LogEntry]] = []
    async with IngestPipeline(storage, {SourceKind.DOCKER_CONTAINER: collector}, limits=FAST) as p:
        p.subscribe(batches.append)
        p.add_source(source_from_id("docker:web"), lines=50)
        await wait_until(lambda: p.stats.stored == 10)
        assert [e.message for e in p.recent("docker:web")] == ["m7", "m8", "m9"]  # ring bounded
    assert collector.calls[0]["lines"] == 50
    assert collector.calls[0]["cursor"] is None
    assert [e.id for b in batches for e in b] == list(range(1, 11))
    assert all(len(b) <= FAST.batch_size for b in batches)
    assert storage.cursor_for("docker:web") == "c9"
    assert storage.count("docker:web") == 10


async def test_restart_resumes_from_stored_cursor(storage: Storage) -> None:
    storage.write_batch([], {"docker:web": "c41"})
    collector = FakeCollector([])
    async with IngestPipeline(storage, {SourceKind.DOCKER_CONTAINER: collector}, limits=FAST) as p:
        p.add_source(source_from_id("docker:web"), lines=50)
        await wait_until(lambda: bool(collector.calls))
    assert collector.calls[0]["cursor"] == "c41"


async def test_failing_collector_does_not_affect_others(storage: Storage) -> None:
    bad = FakeCollector([rec("systemd:a", "before crash"), RuntimeError("journal exploded")])
    good = FakeCollector([rec("docker:b", f"ok{i}") for i in range(5)])
    collectors = {SourceKind.SYSTEMD: bad, SourceKind.DOCKER_CONTAINER: good}
    async with IngestPipeline(storage, collectors, limits=FAST) as p:
        p.add_source(source_from_id("systemd:a"))
        p.add_source(source_from_id("docker:b"))
        p.add_source(source_from_id("file:/no/collector/for/this"))
        await wait_until(lambda: p.stats.stored == 6)
        assert "journal exploded" in p.stats.collector_errors["systemd:a"]
        assert "LookupError" in p.stats.collector_errors["file:/no/collector/for/this"]
        assert len(p.recent("docker:b")) == 3


async def test_subscriber_exception_is_isolated(storage: Storage) -> None:
    seen: list[int] = []

    def broken(_: Sequence[LogEntry]) -> None:
        raise RuntimeError("bad subscriber")

    collector = FakeCollector([rec("docker:b", "x")])
    async with IngestPipeline(storage, {SourceKind.DOCKER_CONTAINER: collector}, limits=FAST) as p:
        p.subscribe(broken)
        p.subscribe(lambda b: seen.append(len(b)))
        p.add_source(source_from_id("docker:b"))
        await wait_until(lambda: seen == [1])


async def test_storage_failure_still_delivers_live(storage: Storage) -> None:
    def fail(*_: object) -> list[LogEntry]:
        raise OSError("disk full")

    storage.write_batch = fail  # type: ignore[method-assign]
    collector = FakeCollector([rec("docker:b", "x"), rec("docker:b", "y")])
    async with IngestPipeline(storage, {SourceKind.DOCKER_CONTAINER: collector}, limits=FAST) as p:
        p.add_source(source_from_id("docker:b"))
        await wait_until(lambda: len(p.recent("docker:b")) == 2)
        assert [e.id for e in p.recent("docker:b")] == [-1, -2]
        assert p.stats.storage_errors >= 1


async def test_stop_flushes_queued_records(storage: Storage) -> None:
    slow = PipelineLimits(queue_size=100, batch_size=1000, flush_interval=60, ring_size=10)
    collector = FakeCollector([rec("docker:b", f"m{i}") for i in range(7)])
    p = IngestPipeline(storage, {SourceKind.DOCKER_CONTAINER: collector}, limits=slow)
    await p.start()
    p.add_source(source_from_id("docker:b"))
    await asyncio.sleep(0.05)  # records are queued; the 60 s flush timer has not fired
    await p.stop()
    assert storage.count() == 7


async def test_backpressure_blocks_collector_instead_of_growing(storage: Storage) -> None:
    produced = 0

    class Firehose:
        def stream(self, source, **_):  # type: ignore[no-untyped-def]
            async def gen():  # type: ignore[no-untyped-def]
                nonlocal produced
                while True:
                    produced += 1
                    yield rec(source.id, "x")

            return gen()

    gate = asyncio.Event()

    def slow_write(entries, cursors):  # type: ignore[no-untyped-def]
        while not gate.is_set():
            time.sleep(0.01)
        return list(entries)

    storage.write_batch = slow_write  # type: ignore[method-assign]
    p = IngestPipeline(storage, {SourceKind.DOCKER_CONTAINER: Firehose()}, limits=FAST)
    await p.start()
    p.add_source(source_from_id("docker:b"))
    await asyncio.sleep(0.2)
    # queue (16) + one batch in flight (4) + one record waiting in put() at most
    assert produced <= FAST.queue_size + FAST.batch_size + 1
    gate.set()
    await p.stop()


async def test_multiline_event_is_one_entry_and_pending_lines_are_not_covered(
    storage: Storage,
) -> None:
    """A traceback split across batches is stored once; while its last line is still
    pending in the assembler, the stored cursor never moves past what was stored."""
    lines = [
        "2026-11-17T22:50:01Z INFO start",
        "2026-11-17T22:50:02Z ERROR job failed",
        "Traceback (most recent call last):",
        '  File "/app/job.py", line 3, in run',
        "KeyError: 'k'",
    ]
    collector = FakeCollector([rec("docker:web", m, f"c{i}") for i, m in enumerate(lines)])
    slow_idle = MultilineAssembler(idle=60)  # only shutdown may flush the pending event
    async with IngestPipeline(
        storage, {SourceKind.DOCKER_CONTAINER: collector}, limits=FAST, assembler=slow_idle
    ) as p:
        p.add_source(source_from_id("docker:web"))
        await wait_until(lambda: p.stats.received == len(lines))
        await asyncio.sleep(0.05)
        assert storage.count() == 1  # "start"; the traceback is still pending
        assert storage.cursor_for("docker:web") == "c0"
    # stop() flushes the pending event
    assert storage.cursor_for("docker:web") == "c4"
    [_, trace] = p.recent("docker:web")
    assert trace.fields["lines"] == 4
    assert trace.fields["exception_type"] == "KeyError"
    assert (trace.severity, trace.fields["parser"]) == (Severity.ERROR, "iso_text")
    assert trace.timestamp == datetime(2026, 11, 17, 22, 50, 2, tzinfo=UTC)


async def test_idle_source_flushes_its_last_line(storage: Storage) -> None:
    collector = FakeCollector([rec("docker:web", "only line", "c0")])
    async with IngestPipeline(
        storage, {SourceKind.DOCKER_CONTAINER: collector}, limits=FAST,
        assembler=MultilineAssembler(idle=0.05),
    ) as p:  # fmt: skip
        p.add_source(source_from_id("docker:web"))
        await wait_until(lambda: storage.count() == 1)
        assert storage.cursor_for("docker:web") == "c0"
