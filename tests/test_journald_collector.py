import asyncio
import json
import stat
from datetime import UTC, datetime
from pathlib import Path

import pytest

from loglens.collectors import source_from_id
from loglens.collectors.base import CollectorError
from loglens.collectors.journald import JournaldCollector, build_args, match_args, parse_entry
from loglens.core.models import LogSource, Severity, SourceKind
from tests.fakes import take

ENTRY = {
    "__CURSOR": "s=abc;i=1",
    "__REALTIME_TIMESTAMP": "1794939061657409",
    "__MONOTONIC_TIMESTAMP": "1",
    "PRIORITY": "3",
    "_SYSTEMD_UNIT": "nginx.service",
    "_PID": "42",
    "MESSAGE": "upstream timed out",
}


def _line(**overrides: object) -> bytes:
    return json.dumps({**ENTRY, **overrides}).encode() + b"\n"


def test_parse_entry() -> None:
    rec = parse_entry("systemd:nginx.service", _line())
    assert rec is not None
    assert rec.message == "upstream timed out"
    assert rec.severity is Severity.ERROR
    assert rec.cursor == "s=abc;i=1"
    assert rec.timestamp == datetime(2026, 11, 17, 18, 11, 1, 657409, tzinfo=UTC)
    assert rec.fields == {"PRIORITY": "3", "_SYSTEMD_UNIT": "nginx.service", "_PID": "42"}


def test_parse_entry_odd_field_encodings() -> None:
    rec = parse_entry(
        "s",
        _line(
            MESSAGE=list(b"caf\xc3\xa9 \xff"),  # non-UTF-8 -> byte array
            TAG=["a", list(b"b")],  # repeated field, one value binary
            BIG=None,  # too large to show
            PRIORITY=None,
        ),
    )
    assert rec is not None
    assert rec.message == "café �"
    assert rec.fields["TAG"] == ["a", "b"]
    assert rec.fields["BIG"] == ""
    assert rec.severity is None


@pytest.mark.parametrize("line", [b"", b"not json\n", b"[1,2]\n", b'"str"\n'])
def test_parse_entry_rejects_garbage(line: bytes) -> None:
    assert parse_entry("s", line) is None


def test_build_args_start_precedence() -> None:
    m = ["--unit=x.service"]
    since = datetime(2026, 1, 1, tzinfo=UTC)
    assert build_args(m, "c1", since, 5, True)[-3:] == ["--follow", "--after-cursor=c1", m[0]]
    assert f"--since=@{int(since.timestamp())}" in build_args(m, None, since, 5, False)
    no_start = build_args(m, None, None, 5, False)
    assert "--lines=5" in no_start
    assert "--follow" not in no_start


def test_match_args() -> None:
    assert match_args(source_from_id("systemd:nginx.service")) == ["--unit=nginx.service"]
    src = LogSource("x", SourceKind.SYSTEMD, "x", "", metadata={"journal_match": ["_COMM=sshd"]})
    assert match_args(src) == ["_COMM=sshd"]
    for bad in (["--evil"], "_COMM=x", ["lower=x"]):
        evil = LogSource("x", SourceKind.SYSTEMD, "x", "", metadata={"journal_match": bad})
        with pytest.raises(ValueError, match="journal_match"):
            match_args(evil)


def _fake_journalctl(
    tmp_path: Path, stdout: bytes, *, exit_code: int = 0, stderr: str = ""
) -> Path:
    """A stand-in journalctl: logs its argv, prints canned output, exits."""
    (tmp_path / "out.json").write_bytes(stdout)
    script = tmp_path / "journalctl"
    script.write_text(
        "#!/bin/sh\n"
        f'echo "$@" >> "{tmp_path}/argv"\n'
        f'cat "{tmp_path}/out.json"\n'
        f'printf "%s" "{stderr}" >&2\n'
        f"exit {exit_code}\n"
    )
    script.chmod(script.stat().st_mode | stat.S_IEXEC)
    return script


async def test_streams_from_subprocess_and_skips_oversized_lines(tmp_path: Path) -> None:
    huge = _line(MESSAGE="x" * (1024 * 1024 + 10), __CURSOR="huge")
    out = _line(__CURSOR="c1") + huge + b"garbage\n" + _line(__CURSOR="c2", MESSAGE="ok")
    collector = JournaldCollector(journalctl=str(_fake_journalctl(tmp_path, out)))
    records = await take(collector.stream(source_from_id("systemd:nginx.service"), follow=False), 9)
    assert [r.cursor for r in records] == ["c1", "c2"]


async def test_follow_reconnects_after_last_cursor(tmp_path: Path) -> None:
    script = _fake_journalctl(tmp_path, _line(__CURSOR="c1") + _line(__CURSOR="c2"))
    collector = JournaldCollector(journalctl=str(script), backoff_max=0.01)
    stream = collector.stream(source_from_id("systemd:nginx.service"), lines=10)
    await take(stream, 3)  # 2 from the first run, then journalctl "exits" and is restarted
    argv = (tmp_path / "argv").read_text().splitlines()
    assert "--lines=10" in argv[0]
    assert "--after-cursor=c2" in argv[1]


async def test_failure_surfaces_stderr(tmp_path: Path) -> None:
    script = _fake_journalctl(tmp_path, b"", exit_code=1, stderr="Failed to seek to cursor")
    collector = JournaldCollector(journalctl=str(script))
    with pytest.raises(CollectorError, match="Failed to seek to cursor"):
        await take(collector.stream(source_from_id("systemd:x"), follow=False), 1)


async def test_cancel_terminates_journalctl(tmp_path: Path) -> None:
    script = tmp_path / "journalctl"
    pidfile = tmp_path / "pid"
    script.write_text(
        f'#!/bin/sh\necho $$ > "{pidfile}"\n' + "printf '%s\\n' \"$0\"\nexec sleep 30\n"
    )
    script.chmod(0o755)
    stream = JournaldCollector(journalctl=str(script)).stream(source_from_id("systemd:x"))
    task = asyncio.create_task(take(stream, 5, timeout=30))
    for _ in range(200):
        if pidfile.exists() and pidfile.read_text().strip():
            break
        await asyncio.sleep(0.01)
    pid = int(pidfile.read_text())
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    await asyncio.sleep(0.1)
    assert not Path(f"/proc/{pid}").exists() or "zombie" in Path(f"/proc/{pid}/status").read_text()
