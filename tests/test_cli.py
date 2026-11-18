import asyncio
import contextlib
import io
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from loglens import __version__
from loglens.cli import cmd_search, cmd_sources, cmd_tail, format_entry, main, parse_since
from loglens.collectors import source_from_id
from loglens.core.models import (
    DiscoveryIssue,
    DiscoveryResult,
    GroupKind,
    LogEntry,
    LogSource,
    RawRecord,
    ServiceGroup,
    Severity,
    SourceKind,
    SourceStatus,
)
from loglens.storage import Storage
from tests.fakes import FakeCollector, FakeDiscoverer

SOURCES = (
    LogSource("docker:shop-web-1", SourceKind.DOCKER_CONTAINER, "web", "compose:shop",
              SourceStatus.RUNNING, {"image": "nginx:1.27", "state": "running"}),
    LogSource("file:/var/log/auth.log", SourceKind.FILE, "Auth log", "compose:shop",
              metadata={"path": "/var/log/auth.log", "readable": False}),
)  # fmt: skip
ISSUE = DiscoveryIssue("docker", "docker_permission_denied", "Socket denied.", hint="Join docker.")
DISCOVERERS = [
    FakeDiscoverer(
        "d",
        [DiscoveryResult((ServiceGroup("compose:shop", "shop", GroupKind.DOCKER_COMPOSE, SOURCES),),
                         (ISSUE,))],
    )
]  # fmt: skip


def test_version() -> None:
    assert __version__


def test_table_output() -> None:
    out = io.StringIO()
    assert cmd_sources(DISCOVERERS, as_json=False, out=out) == 0
    text = out.getvalue()
    assert "shop  [docker_compose, 2 sources]" in text
    assert "nginx:1.27  (running)" in text
    assert "/var/log/auth.log  [not readable]" in text
    assert "[warning] docker: Socket denied." in text
    assert "-> Join docker." in text


def test_json_output() -> None:
    out = io.StringIO()
    cmd_sources(DISCOVERERS, as_json=True, out=out)
    data = json.loads(out.getvalue())
    (group,) = data["groups"]
    assert group["kind"] == "docker_compose"
    web = group["sources"][0]
    assert web["kind"] == "docker_container"
    assert web["status"] == "running"
    assert web["metadata"]["image"] == "nginx:1.27"
    assert web["discovered_at"].endswith("+00:00")
    assert data["issues"][0]["severity"] == "warning"
    assert data["issues"][0]["hint"] == "Join docker."


def test_empty_machine() -> None:
    out = io.StringIO()
    cmd_sources([FakeDiscoverer("d", [DiscoveryResult()])], as_json=False, out=out)
    assert out.getvalue() == "No log sources found.\n"


def test_table_neutralizes_terminal_escapes() -> None:
    evil = LogSource("docker:x", SourceKind.DOCKER_CONTAINER, "x\x1b]0;pwned\x07", "g",
                     metadata={"image": "img\x1b[2J\x9b31m", "state": "running"})  # fmt: skip
    group = ServiceGroup("g", "grp\x1b[1m", GroupKind.DOCKER_STANDALONE, (evil,))
    out = io.StringIO()
    cmd_sources([FakeDiscoverer("d", [DiscoveryResult((group,))])], as_json=False, out=out)
    text = out.getvalue()
    assert "\x1b" not in text
    assert "\x9b" not in text
    assert "\x07" not in text
    assert "grp?[1m" in text


# --- Phase 2: tail / search / helpers ---------------------------------------------------

NOW = datetime(2026, 11, 17, 12, 0, tzinfo=UTC)


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("10m", NOW - timedelta(minutes=10)),
        ("2h", NOW - timedelta(hours=2)),
        ("1d", NOW - timedelta(days=1)),
        (" 30s", NOW - timedelta(seconds=30)),
        ("2026-11-17T10:00:00+00:00", datetime(2026, 11, 17, 10, tzinfo=UTC)),
    ],
)
def test_parse_since(text: str, expected: datetime) -> None:
    assert parse_since(text, now=NOW) == expected


def test_parse_since_naive_is_local_and_invalid_raises() -> None:
    assert parse_since("2026-11-17 10:00").tzinfo is not None
    with pytest.raises(ValueError, match="invalid time"):
        parse_since("yesterday-ish")


def test_source_from_id() -> None:
    assert source_from_id("systemd:nginx.service").metadata["unit"] == "nginx.service"
    assert source_from_id("docker:web-1").metadata["container_name"] == "web-1"
    assert source_from_id("file:/var/log/x.log").metadata["path"] == "/var/log/x.log"
    for bad in ["nginx", "file:relative.log", "ftp:x", "docker:"]:
        with pytest.raises(ValueError, match="source"):
            source_from_id(bad)


def test_format_entry() -> None:
    e = LogEntry(1, "docker:web", NOW, Severity.ERROR, "bad\x1b[31m", "", {"stream": "stderr"})
    line = format_entry(e, with_source=True)
    assert line.endswith(" ERROR    [docker:web] (stderr) bad?[31m\n")
    assert "\x1b" not in line


async def test_cmd_tail_prints_collector_output() -> None:
    collector = FakeCollector([RawRecord("docker:web", "hello")], hang=False)
    out = io.StringIO()
    rc = await cmd_tail(
        "docker:web", {SourceKind.DOCKER_CONTAINER: collector},
        since=None, lines=3, follow=False, out=out,
    )  # fmt: skip
    assert rc == 0
    assert out.getvalue().rstrip().endswith("INFO     hello")
    assert collector.calls[0]["lines"] == 3
    assert collector.calls[0]["follow"] is False


async def test_cmd_tail_reports_errors() -> None:
    collector = FakeCollector([PermissionError("denied")], hang=False)
    rc = await cmd_tail(
        "docker:web", {SourceKind.DOCKER_CONTAINER: collector},
        since=None, lines=3, follow=False, out=io.StringIO(),
    )  # fmt: skip
    assert rc == 1


def test_cmd_search(tmp_path: Path) -> None:
    db = tmp_path / "x.db"
    assert cmd_search("x", db, source_ids=[], limit=5, out=io.StringIO()) == 1  # no db yet
    with Storage(db) as s:
        s.write_batch([LogEntry(0, "file:/a", NOW, Severity.INFO, "denied 10.0.0.5", "")], {})
    out = io.StringIO()
    assert cmd_search("10.0.0.5", db, source_ids=[], limit=5, out=out) == 0
    assert "[file:/a] denied 10.0.0.5" in out.getvalue()


def test_main_rejects_bad_source_id(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["tail", "not-a-source"]) == 2
    assert "invalid source id" in capsys.readouterr().err


async def test_cmd_tail_parses_and_prints_fields() -> None:
    lines = [
        "Nov 17 22:50:09 kali sshd[1301]: Failed password for invalid user admin from "
        "203.0.113.9 port 51234 ssh2",
        "Nov 17 22:50:10 kali sshd[1302]: error: boom",
        "  continued",
    ]
    collector = FakeCollector([RawRecord("file:/var/log/auth.log", m) for m in lines], hang=False)
    out = io.StringIO()
    rc = await cmd_tail(
        "file:/var/log/auth.log", {SourceKind.FILE: collector},
        since=None, lines=3, follow=False, out=out, fields=True,
    )  # fmt: skip
    assert rc == 0
    text = out.getvalue().splitlines()
    assert text[0].endswith(
        "WARNING  Failed password for invalid user admin from 203.0.113.9 port 51234 ssh2"
    )
    assert text[1] == (
        "    {auth_method=password event=failed host=kali invalid_user=true parser=sshd "
        "pid=1301 program=sshd src_ip=203.0.113.9 src_port=51234 user=admin}"
    )
    assert text[2].endswith("error: boom")
    assert text[3] == "      continued"  # continuation lines indented by 4 more
    assert "lines=2" in text[4]


async def test_cmd_tail_flushes_pending_line_when_source_goes_idle() -> None:
    collector = FakeCollector([RawRecord("docker:web", "hello")], hang=True)
    out = io.StringIO()
    task = asyncio.create_task(cmd_tail(
        "docker:web", {SourceKind.DOCKER_CONTAINER: collector},
        since=None, lines=1, follow=True, out=out,
    ))  # fmt: skip
    async with asyncio.timeout(5):
        while "hello" not in out.getvalue():
            await asyncio.sleep(0.02)
    task.cancel()
    with contextlib.suppress(asyncio.CancelledError):
        await task


def test_format_entry_neutralizes_escapes_in_every_part() -> None:
    entry = LogEntry(
        1, "docker:\x1b]0;pwned\x07", datetime(2026, 1, 1, tzinfo=UTC), Severity.INFO,
        "a\x1b[2Jb\nc\x1b[31m", "raw", {"k": "\x1b[1m"},
    )  # fmt: skip
    text = format_entry(entry, with_source=True, with_fields=True)
    assert "\x1b" not in text and "\x07" not in text
    assert text.count("\n") == 3  # head line, one continuation, fields line
