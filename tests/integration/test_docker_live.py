import asyncio
import contextlib
import uuid
from typing import Any

import pytest

from loglens.collectors import source_from_id
from loglens.collectors.docker_logs import DockerCollector
from loglens.core.models import RawRecord
from tests.fakes import take

pytestmark = pytest.mark.integration

SCRIPT = (
    "echo boot; i=0; while true; do i=$((i+1)); echo tick $i; echo warn $i >&2; sleep 0.1; done"
)


async def _until(predicate, timeout: float = 20.0) -> None:  # type: ignore[no-untyped-def]
    async with asyncio.timeout(timeout):
        while not predicate():
            await asyncio.sleep(0.05)


async def test_kill_restart_recreate_no_duplicates(docker_client: Any, local_image: str) -> None:
    """Acceptance: kill + start, then remove + recreate with the same name, while tailing."""
    name = f"loglens-it-{uuid.uuid4().hex[:8]}"

    def run() -> Any:
        return docker_client.containers.run(
            local_image, ["sh", "-c", SCRIPT], name=name, detach=True
        )

    container = run()
    got: list[RawRecord] = []

    async def consume() -> None:
        stream = DockerCollector(backoff_max=0.5).stream(
            source_from_id(f"docker:{name}"), lines=1000
        )
        async for record in stream:
            got.append(record)

    def boots() -> int:
        return sum(r.message == "boot" for r in got)

    task = asyncio.create_task(consume())
    try:
        await _until(lambda: len(got) >= 10)
        await asyncio.to_thread(container.kill)
        await asyncio.sleep(1.0)
        await asyncio.to_thread(container.start)
        await _until(lambda: boots() == 2)
        n = len(got)
        await _until(lambda: len(got) >= n + 6)

        await asyncio.to_thread(container.remove, force=True)
        await asyncio.sleep(1.0)
        container = await asyncio.to_thread(run)
        await _until(lambda: boots() == 3)
        n = len(got)
        await _until(lambda: len(got) >= n + 6)
    finally:
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task
        with contextlib.suppress(Exception):
            container.remove(force=True)

    events = [r.message for r in got if r.fields["stream"] == "events"]
    logs = [r for r in got if r.fields["stream"] != "events"]
    keys = [(r.timestamp, r.fields["stream"], r.message) for r in logs]
    assert len(keys) == len(set(keys)), "duplicate lines after reattach"
    assert boots() == 3
    assert {r.fields["stream"] for r in logs} == {"stdout", "stderr"}
    # Lifecycle events joined the container's stream: the kill and both restarts.
    assert any(" container die " in m and "exitCode=137" in m for m in events), events
    assert sum(" container start " in m for m in events) >= 2, events
    assert len(events) == len(set(events)), "duplicate events after reconnect"
    assert all(r.message.startswith("warn") for r in got if r.fields["stream"] == "stderr")
    for stream_name in ("stdout", "stderr"):
        times = [r.timestamp for r in got if r.fields["stream"] == stream_name]
        assert times == sorted(times)  # type: ignore[type-var]


async def test_tty_container(docker_client: Any, local_image: str) -> None:
    name = f"loglens-it-{uuid.uuid4().hex[:8]}"
    container = docker_client.containers.run(
        local_image, ["sh", "-c", "echo out; echo err >&2"], name=name, detach=True, tty=True
    )
    try:
        await asyncio.to_thread(container.wait, timeout=10)
        stream = DockerCollector().stream(source_from_id(f"docker:{name}"), lines=10, follow=False)
        records = await take(stream, 10)
    finally:
        container.remove(force=True)
    assert [(r.message, r.fields["stream"]) for r in records] == [
        ("out", "stdout"),
        ("err", "stdout"),
    ]
