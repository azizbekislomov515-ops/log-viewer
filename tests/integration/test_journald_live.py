import asyncio
import shutil
import subprocess
import time
import uuid
from datetime import UTC, datetime, timedelta

import pytest

from loglens.collectors.journald import JournaldCollector
from loglens.core.models import LogSource, Severity, SourceKind
from tests.fakes import take

pytestmark = pytest.mark.integration


def _journal_sees(ident: str, timeout: float = 5.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        out = subprocess.run(  # noqa: S603
            ["journalctl", "--no-pager", "-o", "cat", f"SYSLOG_IDENTIFIER={ident}"],  # noqa: S607
            capture_output=True, text=True, timeout=10, check=False,
        )  # fmt: skip
        if "three" in out.stdout:
            return True
        time.sleep(0.2)
    return False


async def test_follow_then_resume_from_cursor() -> None:
    if not (shutil.which("journalctl") and shutil.which("systemd-cat")):
        pytest.skip("journalctl/systemd-cat not available")
    ident = f"loglens-it-{uuid.uuid4().hex[:8]}"
    source = LogSource(
        f"systemd:{ident}", SourceKind.SYSTEMD, ident, "",
        metadata={"journal_match": [f"SYSLOG_IDENTIFIER={ident}"]},
    )  # fmt: skip
    collector = JournaldCollector()
    since = datetime.now(UTC) - timedelta(minutes=1)
    task = asyncio.create_task(take(collector.stream(source, since=since), 3, timeout=20))
    await asyncio.sleep(0.5)  # journalctl is following
    subprocess.run(  # noqa: S603
        ["systemd-cat", "-t", ident, "-p", "warning", "printf", "one\\ntwo\\nthree\\n"],  # noqa: S607
        check=True, timeout=10,
    )  # fmt: skip
    if not await asyncio.to_thread(_journal_sees, ident):
        task.cancel()
        pytest.skip("this user cannot read its own journal entries")
    records = await task

    assert [r.message for r in records] == ["one", "two", "three"]
    assert {r.severity for r in records} == {Severity.WARNING}
    assert all(r.cursor for r in records)

    resumed = await take(collector.stream(source, cursor=records[0].cursor, follow=False), 10)
    assert [r.message for r in resumed] == ["two", "three"]
