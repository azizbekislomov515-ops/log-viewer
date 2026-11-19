import asyncio
import os
import shutil
from pathlib import Path

import pytest

from loglens.collectors import source_from_id
from loglens.collectors.files import FileCollector, _tail_offset
from loglens.core.models import RawRecord
from tests.fakes import take

FAST = {"poll_interval": 0.05, "rotation_grace": 0.3, "backoff_max": 0.05}


def _source(path: Path):  # type: ignore[no-untyped-def]
    return source_from_id(f"file:{path}")


def _append(path: Path, text: str) -> None:
    with path.open("a") as f:
        f.write(text)


def _msgs(records: list[RawRecord]) -> list[str]:
    return [r.message for r in records]


async def _collect_while(stream, actions, n: int, timeout: float = 5.0):  # type: ignore[no-untyped-def]
    """Consume ``stream`` in the background while running ``actions``; return n records."""
    task = asyncio.create_task(take(stream, n, timeout))
    await asyncio.sleep(0.1)  # let the collector open the file and reach EOF
    await actions()
    return await task


@pytest.mark.parametrize(
    ("content", "lines", "start"),
    [
        (b"", 3, 0),
        (b"a\nb\nc\n", 2, 2),
        (b"a\nb\nc\n", 10, 0),
        (b"a\nb\nc", 1, 4),  # no trailing newline
        (b"a\nb\nc\n", 0, 6),
    ],
)
def test_tail_offset(tmp_path: Path, content: bytes, lines: int, start: int) -> None:
    p = tmp_path / "f.log"
    p.write_bytes(content)
    with p.open("rb") as f:
        assert _tail_offset(f, lines) == start  # type: ignore[arg-type]


async def test_backlog_and_partial_last_line(tmp_path: Path) -> None:
    p = tmp_path / "app.log"
    p.write_text("one\ntwo\nthree\nfour")
    records = await take(FileCollector(**FAST).stream(_source(p), lines=2, follow=False), 10)
    assert _msgs(records) == ["three", "four"]


async def test_follow_assembles_partial_lines(tmp_path: Path) -> None:
    p = tmp_path / "app.log"
    p.write_text("old\n")

    async def write() -> None:
        _append(p, "hel")
        await asyncio.sleep(0.1)
        _append(p, "lo\nworld\n")

    records = await _collect_while(FileCollector(**FAST).stream(_source(p)), write, 2)
    assert _msgs(records) == ["hello", "world"]


@pytest.mark.parametrize("use_inotify", [True, False])
async def test_rename_rotation_loses_nothing(tmp_path: Path, use_inotify: bool) -> None:
    """Acceptance: logrotate 'create' mode, writer keeps writing to the old file briefly."""
    p = tmp_path / "access.log"
    p.write_text("")
    writer = p.open("a", buffering=1)  # the daemon's long-lived file handle

    async def rotate() -> None:
        writer.write("a\nb\n")
        await asyncio.sleep(0.1)
        p.rename(tmp_path / "access.log.1")  # logrotate renames ...
        writer.write("c\n")  # ... daemon still writes to the old inode
        p.write_text("")  # ... logrotate creates the new file
        await asyncio.sleep(0.1)
        writer.write("d\n")  # still old inode, after the new file exists (within grace)
        writer.close()
        with p.open("a") as new:  # daemon reopens (postrotate)
            new.write("e\nf\n")

    collector = FileCollector(use_inotify=use_inotify, **FAST)
    records = await _collect_while(collector.stream(_source(p)), rotate, 6)
    assert sorted(_msgs(records)) == ["a", "b", "c", "d", "e", "f"]
    assert _msgs(records)[:3] == ["a", "b", "c"]


async def test_copytruncate_rotation(tmp_path: Path) -> None:
    p = tmp_path / "app.log"
    p.write_text("")

    async def rotate() -> None:
        _append(p, "a\nb\n")
        await asyncio.sleep(0.15)
        shutil.copy(p, tmp_path / "app.log.1")
        os.truncate(p, 0)
        await asyncio.sleep(0.15)
        _append(p, "c\n")

    records = await _collect_while(FileCollector(**FAST).stream(_source(p)), rotate, 3)
    assert _msgs(records) == ["a", "b", "c"]


async def test_resume_from_cursor_has_no_duplicates(tmp_path: Path) -> None:
    p = tmp_path / "app.log"
    p.write_text("1\n2\n3\n")
    collector = FileCollector(**FAST)
    first = await take(collector.stream(_source(p), lines=10, follow=False), 2)
    _append(p, "4\n")
    rest = await take(collector.stream(_source(p), cursor=first[-1].cursor, follow=False), 10)
    assert _msgs(first) + _msgs(rest) == ["1", "2", "3", "4"]


async def test_resume_after_rotation_while_stopped(tmp_path: Path) -> None:
    p = tmp_path / "app.log"
    p.write_text("1\n2\n")
    collector = FileCollector(**FAST)
    first = await take(collector.stream(_source(p), lines=10, follow=False), 2)
    _append(p, "3\n")  # written while LogLens was not running ...
    p.rename(tmp_path / "app.log.1")  # ... then rotated
    p.write_text("4\n")
    rest = await take(collector.stream(_source(p), cursor=first[-1].cursor), 2)
    assert _msgs(rest) == ["3", "4"]


@pytest.mark.skipif(os.geteuid() == 0, reason="root ignores file permissions")
async def test_permission_error_is_reported_and_retried(tmp_path: Path) -> None:
    p = tmp_path / "secret.log"
    p.write_text("x\n")
    p.chmod(0)
    errors: list[BaseException] = []
    stream = FileCollector(**FAST).stream(
        _source(p), lines=5, on_error=lambda _, e: errors.append(e)
    )

    async def grant() -> None:
        await asyncio.sleep(0.2)
        p.chmod(0o644)

    records = await _collect_while(stream, grant, 1)
    assert _msgs(records) == ["x"]
    assert errors
    assert all(isinstance(e, PermissionError) for e in errors)


async def test_missing_file_is_waited_for(tmp_path: Path) -> None:
    p = tmp_path / "later.log"

    async def create() -> None:
        await asyncio.sleep(0.1)
        p.write_text("hello\n")

    stream = FileCollector(**FAST).stream(_source(p), lines=10)
    assert _msgs(await _collect_while(stream, create, 1)) == ["hello"]


async def test_overlong_line_truncated(tmp_path: Path) -> None:
    p = tmp_path / "app.log"
    p.write_bytes(b"x" * 200_000 + b"\nok\n")
    records = await take(FileCollector().stream(_source(p), lines=5, follow=False), 5)
    assert records[0].fields == {"truncated": True}
    assert len(records[0].message) == 64 * 1024
    assert _msgs(records)[1] == "ok"
