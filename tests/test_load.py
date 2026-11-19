"""Synthetic load: 50k lines/s for 10 s through the full pipeline into a real SQLite file."""

import asyncio
import os
import resource
from pathlib import Path

import pytest

from loglens.collectors import source_from_id
from loglens.core.models import RawRecord, SourceKind
from loglens.core.pipeline import IngestPipeline, PipelineLimits
from loglens.storage import Storage

pytestmark = pytest.mark.perf

RATE = 50_000  # lines/s offered, in total
DURATION = 10.0  # seconds
SOURCES = 5
#: RSS may grow by at most this much. The pipeline's own buffers are a few MiB; the rest
#: is SQLite page cache, allocator slack and the interpreter.
RSS_BUDGET_MIB = 150


def _rss_mib() -> float:
    with Path("/proc/self/statm").open() as f:
        return int(f.read().split()[1]) * os.sysconf("SC_PAGE_SIZE") / 2**20


class SyntheticCollector:
    """Offers RATE/SOURCES realistic lines/s per source, paced by the wall clock."""

    def __init__(self) -> None:
        self.produced = 0

    def stream(self, source, **_):  # type: ignore[no-untyped-def]
        async def gen():  # type: ignore[no-untyped-def]
            loop = asyncio.get_running_loop()
            rate = RATE / SOURCES
            start = loop.time()
            sent = 0
            while (elapsed := loop.time() - start) < DURATION:
                while sent < elapsed * rate:
                    sent += 1
                    self.produced += 1
                    yield RawRecord(
                        source.id,
                        f"1731844201.{sent:06d} 1 10.0.{sent % 256}.{sent % 199} TCP_DENIED/403 "
                        f"3942 GET http://example-{sent % 977}.com/path?q={sent} - HIER_NONE/- "
                        "text/html",
                        fields={"stream": "stdout"},
                        cursor=f"{sent}:1",
                    )
                await asyncio.sleep(0.005)

        return gen()


async def test_50k_lines_per_second_for_10_seconds(tmp_path: Path, capsys) -> None:  # type: ignore[no-untyped-def]
    limits = PipelineLimits()  # production defaults
    collector = SyntheticCollector()
    samples: list[float] = []

    async def sample_memory() -> None:
        while True:
            samples.append(_rss_mib())
            await asyncio.sleep(0.25)

    with Storage(tmp_path / "load.db") as storage:
        pipeline = IngestPipeline(storage, {SourceKind.DOCKER_CONTAINER: collector}, limits=limits)
        baseline = _rss_mib()
        sampler = asyncio.create_task(sample_memory())
        loop = asyncio.get_running_loop()
        started = loop.time()
        await pipeline.start()
        for i in range(SOURCES):
            pipeline.add_source(source_from_id(f"docker:load-{i}"))
        await asyncio.sleep(DURATION)
        offered_done = loop.time()
        await pipeline.stop()  # drains: everything produced must be stored
        finished = loop.time()
        sampler.cancel()

        stored = storage.count()
        rings = [len(pipeline.recent(f"docker:load-{i}")) for i in range(SOURCES)]

    elapsed = finished - started
    peak_growth = max(samples) - baseline
    with capsys.disabled():
        print(
            f"\n[load] offered target {RATE:,}/s for {DURATION:.0f}s -> produced "
            f"{collector.produced:,} in {offered_done - started:.1f}s, stored {stored:,} in "
            f"{elapsed:.1f}s = {stored / elapsed:,.0f} lines/s sustained; "
            f"batches {pipeline.stats.batches:,}, max queue {pipeline.stats.max_queue:,}/"
            f"{limits.queue_size:,}, RSS +{peak_growth:.0f} MiB (peak "
            f"{resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024:.0f} MiB)"
        )

    assert pipeline.stats.collector_errors == {}
    assert pipeline.stats.storage_errors == 0
    # Backpressure, not loss. On stop, each source may have one record parked in a cancelled
    # queue.put(); its cursor was never persisted, so a real collector re-reads it on restart.
    assert collector.produced - SOURCES <= stored <= collector.produced
    assert pipeline.stats.max_queue <= limits.queue_size
    assert all(n <= limits.ring_size for n in rings)
    assert peak_growth < RSS_BUDGET_MIB, f"memory grew {peak_growth:.0f} MiB"
