"""Tail-follow plain log files, surviving logrotate.

Rotation handling:

* **rename** (``create`` mode): the path gets a new inode. We keep reading the old file
  descriptor to EOF, switch to the new file from offset 0, and keep draining the old
  descriptor for ``rotation_grace`` seconds because daemons often write a few more lines
  to the renamed file before they reopen (e.g. until nginx gets USR1).
* **copytruncate**: same inode, size drops below our offset -> restart at 0.
* **restart while rotated**: the cursor stores ``dev:ino:offset``; if the path now has
  another inode we look for the old inode in the same directory (``access.log.1``),
  finish it, then continue with the current file.

Cursor: ``<st_dev>:<st_ino>:<byte offset after the line>``.

Limitations: lines written between the last read and a copytruncate are lost (inherent
to copytruncate); a rotated file that was already compressed cannot be resumed; files
have no parsed timestamps yet, so ``since`` is ignored and ``lines`` is used instead.
"""

from __future__ import annotations

import asyncio
import contextlib
import io
import logging
import os
import time
from collections.abc import AsyncIterator
from datetime import datetime
from pathlib import Path
from typing import BinaryIO

from inotify_simple import INotify
from inotify_simple import flags as inotify_flags

from loglens.collectors.base import Backoff, ErrorCallback, LineSplitter, decode, reconnecting
from loglens.core.models import LogSource, RawRecord

log = logging.getLogger(__name__)

_READ_SIZE = 64 * 1024
_WATCH_MASK = (
    inotify_flags.MODIFY
    | inotify_flags.CREATE
    | inotify_flags.MOVED_TO
    | inotify_flags.MOVED_FROM
    | inotify_flags.DELETE
    | inotify_flags.ATTRIB
)


class FileCollector:
    """Follows one file; inotify on its directory, polling as safety net and fallback."""

    def __init__(
        self,
        *,
        poll_interval: float = 1.0,
        rotation_grace: float = 5.0,
        use_inotify: bool = True,
        backoff_max: float = 30.0,
    ) -> None:
        self._poll_interval = poll_interval
        self._rotation_grace = rotation_grace
        self._use_inotify = use_inotify
        self._backoff_max = backoff_max

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
        """Stream lines of ``source``'s file (see ``Collector``). ``since`` is ignored."""
        path = Path(str(source.metadata.get("path") or source.id.removeprefix("file:")))

        def open_stream(cur: str | None) -> AsyncIterator[RawRecord]:
            return self._follow(source.id, path, cur, lines, follow)

        return reconnecting(
            open_stream,
            source.id,
            cursor=cursor,
            follow=follow,
            backoff=Backoff(maximum=self._backoff_max),
            on_error=on_error,
        )

    async def _follow(  # noqa: PLR0912 - one state machine, clearer in one place
        self, source_id: str, path: Path, cursor: str | None, lines: int, follow: bool
    ) -> AsyncIterator[RawRecord]:
        current = _Tail(*_open_at(path, cursor, lines))
        old: _Tail | None = None
        old_deadline = 0.0
        watcher = _Watcher(path, self._use_inotify) if follow else None
        try:
            while True:
                if chunk := current.read():
                    for record in current.records(source_id, chunk, with_cursor=True):
                        yield record
                    continue
                if old is not None:  # rotated-away file still being written to?
                    while chunk := old.read():
                        for record in old.records(source_id, chunk, with_cursor=False):
                            yield record
                    if time.monotonic() >= old_deadline:
                        for record in old.finish(source_id, with_cursor=False):
                            yield record
                        old.close()
                        old = None
                if watcher is None:
                    for record in current.finish(source_id, with_cursor=True):
                        yield record
                    return

                match _rotation(path, current):
                    case "renamed":
                        if old is not None:
                            old.close()
                        old, old_deadline = current, time.monotonic() + self._rotation_grace
                        current = _Tail(_open(path), 0)
                        log.info("file rotated (rename)", extra={"path": str(path)})
                        continue
                    case "truncated":
                        for record in current.finish(source_id, with_cursor=True):
                            yield record
                        current.restart()
                        log.info("file truncated (copytruncate)", extra={"path": str(path)})
                        continue
                await watcher.wait(0.2 if old is not None else self._poll_interval)
        finally:
            current.close()
            if old is not None:
                old.close()
            if watcher is not None:
                watcher.close()


class _Tail:
    """An open file plus its line splitter and the offset the splitter started at."""

    def __init__(self, file: BinaryIO, offset: int) -> None:
        self.file = file
        stat = os.fstat(file.fileno())
        self.dev, self.ino = stat.st_dev, stat.st_ino
        self.base = offset
        self.splitter = LineSplitter()

    def read(self) -> bytes:
        # ponytail: blocking read on the event loop; fine for local disks (page cache),
        # move to a thread if network filesystems show up.
        return self.file.read(_READ_SIZE) or b""

    def records(self, source_id: str, chunk: bytes, *, with_cursor: bool) -> list[RawRecord]:
        return [
            self._record(source_id, line, truncated, consumed, with_cursor)
            for line, truncated, consumed in self.splitter.feed(chunk)
        ]

    def finish(self, source_id: str, *, with_cursor: bool) -> list[RawRecord]:
        """Emit the trailing partial line, if any."""
        rest = self.splitter.flush()
        return [] if rest is None else [self._record(source_id, *rest, with_cursor)]

    def restart(self) -> None:
        self.file.seek(0)
        self.base = 0
        self.splitter = LineSplitter()

    def close(self) -> None:
        self.file.close()

    def _record(
        self, source_id: str, line: bytes, truncated: bool, consumed: int, with_cursor: bool
    ) -> RawRecord:
        return RawRecord(
            source_id=source_id,
            message=decode(line),
            fields={"truncated": True} if truncated else {},
            cursor=f"{self.dev}:{self.ino}:{self.base + consumed}" if with_cursor else None,
        )


def _open(path: Path) -> BinaryIO:
    return path.open("rb", buffering=0)


def _open_at(path: Path, cursor: str | None, lines: int) -> tuple[BinaryIO, int]:
    """Open the file to read from: resume at the cursor, else the last ``lines`` lines."""
    parsed = _parse_cursor(cursor)
    if parsed is not None:
        dev, ino, offset = parsed
        stat = path.stat()
        target = path
        if (stat.st_dev, stat.st_ino) != (dev, ino):
            rotated = _find_inode(path.parent, dev, ino)
            if rotated is None:
                log.warning("resume file rotated away; restarting at the current file",
                            extra={"path": str(path)})  # fmt: skip
                return _open(path), 0
            target = rotated
        f = _open(target)
        size = os.fstat(f.fileno()).st_size
        offset = offset if offset <= size else 0  # truncated while we were away
        f.seek(offset)
        return f, offset
    f = _open(path)
    offset = _tail_offset(f, lines)
    f.seek(offset)
    return f, offset


def _parse_cursor(cursor: str | None) -> tuple[int, int, int] | None:
    parts = (cursor or "").split(":")
    if len(parts) == 3 and all(p.isdigit() for p in parts):
        return int(parts[0]), int(parts[1]), int(parts[2])
    return None


def _find_inode(directory: Path, dev: int, ino: int) -> Path | None:
    try:
        with os.scandir(directory) as entries:
            for entry in entries:
                if entry.inode() == ino and entry.is_file() and entry.stat().st_dev == dev:
                    return Path(entry.path)
    except OSError:
        return None
    return None


def _tail_offset(f: BinaryIO, lines: int) -> int:
    """Offset where the last ``lines`` lines start (end of file for 0)."""
    size = os.fstat(f.fileno()).st_size
    if lines <= 0 or size == 0:
        return size
    fd = f.fileno()
    end = size - 1 if os.pread(fd, 1, size - 1) == b"\n" else size  # ignore final newline
    found = 0
    while end > 0:
        start = max(0, end - _READ_SIZE)
        block = os.pread(fd, end - start, start)
        idx = len(block)
        while (idx := block.rfind(b"\n", 0, idx)) >= 0:
            found += 1
            if found == lines:
                return start + idx + 1
        end = start
    return 0


def _rotation(path: Path, tail: _Tail) -> str | None:
    """'renamed', 'truncated' or None, comparing the path with the open descriptor."""
    try:
        stat = path.stat()
    except OSError:
        return None  # moved away and not recreated yet: keep reading the open fd
    if (stat.st_dev, stat.st_ino) != (tail.dev, tail.ino):
        return "renamed"
    if stat.st_size < tail.file.tell():
        return "truncated"
    return None


class _Watcher:
    """Waits for activity on the file (via its directory), with a timeout as safety net."""

    def __init__(self, path: Path, use_inotify: bool) -> None:
        self._name = path.name
        self._inotify: INotify | None = None
        if use_inotify:
            try:
                self._inotify = INotify()
                self._inotify.add_watch(str(path.parent), _WATCH_MASK)
            except OSError as exc:
                log.info("inotify unavailable, polling", extra={"path": str(path), "error": exc})
                self.close()

    async def wait(self, timeout: float) -> None:
        if self._inotify is None:
            await asyncio.sleep(timeout)
            return
        loop = asyncio.get_running_loop()
        ready = asyncio.Event()
        fd = self._inotify.fileno()
        loop.add_reader(fd, ready.set)
        deadline = loop.time() + timeout
        try:
            while (remaining := deadline - loop.time()) > 0:
                try:
                    await asyncio.wait_for(ready.wait(), remaining)
                except TimeoutError:
                    return
                ready.clear()
                events = self._inotify.read(timeout=0)
                # name "" = event on the directory itself or queue overflow: wake too.
                if any(e.name in (self._name, "") for e in events):
                    return
        finally:
            loop.remove_reader(fd)

    def close(self) -> None:
        if self._inotify is not None:
            with contextlib.suppress(OSError, io.UnsupportedOperation):
                self._inotify.close()
            self._inotify = None
