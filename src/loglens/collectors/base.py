"""Collector protocol plus the shared pieces every collector uses.

A collector turns one ``LogSource`` into an async stream of ``RawRecord``s.

* **start/stop**: iterate the stream to start; cancel the consuming task (or ``aclose()``
  the iterator) to stop. Collectors release processes/sockets/files in ``finally``.
* **backpressure**: streams are pull-based. If the consumer stops pulling, the collector
  stops reading its pipe/socket/file and the producer (journalctl, dockerd, the OS) blocks
  or buffers on its side. No collector holds an unbounded buffer.
* **reconnect**: ``reconnecting()`` restarts a broken or ended stream with exponential
  backoff, resuming from the cursor of the last record it yielded, so reconnects neither
  duplicate nor skip lines.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import AsyncIterator, Callable
from dataclasses import dataclass, field
from datetime import datetime
from typing import Protocol

from loglens.core.models import LogSource, RawRecord

log = logging.getLogger(__name__)

#: Longest line any collector buffers. Longer lines are cut and tagged ``truncated``.
MAX_LINE_BYTES = 64 * 1024

ErrorCallback = Callable[[str, BaseException], None]


class CollectorError(RuntimeError):
    """A collector's backend failed (non-zero exit, bad response)."""


class Collector(Protocol):
    """Streams records for one source.

    Start position precedence: ``cursor`` (resume exactly after it) > ``since``
    (time) > ``lines`` (last N lines; 0 = only new lines). With ``follow=False`` the
    stream ends at the current end of the log and errors are raised; with
    ``follow=True`` it never ends on its own and errors go to ``on_error``.
    """

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
        """Return an async iterator of records for ``source``."""
        ...


@dataclass
class Backoff:
    """Exponential backoff: initial, initial*factor, ... capped at maximum."""

    initial: float = 0.5
    maximum: float = 30.0
    factor: float = 2.0
    _next: float = field(init=False, repr=False)

    def __post_init__(self) -> None:
        self.reset()

    def next_delay(self) -> float:
        """Return the delay to wait now and advance."""
        delay = self._next
        self._next = min(delay * self.factor, self.maximum)
        return delay

    def reset(self) -> None:
        """Back to the initial delay (call after a success)."""
        self._next = min(self.initial, self.maximum)


OpenStream = Callable[[str | None], AsyncIterator[RawRecord]]


async def reconnecting(
    open_stream: OpenStream,
    source_id: str,
    *,
    cursor: str | None,
    follow: bool,
    backoff: Backoff,
    on_error: ErrorCallback | None,
) -> AsyncIterator[RawRecord]:
    """Run ``open_stream(cursor)`` forever (follow mode), resuming from the latest cursor.

    A stream that ends cleanly (container stopped, process exited) is reopened after the
    backoff delay too; that is how collectors "wait" for a source to come back.
    """
    while True:
        try:
            async for record in open_stream(cursor):
                if record.cursor is not None:
                    cursor = record.cursor
                backoff.reset()
                yield record
            if not follow:
                return
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            if not follow:
                raise
            log.warning("collector error, will retry", extra={"source": source_id, "error": exc})
            if on_error is not None:
                on_error(source_id, exc)
        await asyncio.sleep(backoff.next_delay())


class LineSplitter:
    """Turns a byte stream into lines, never buffering more than ``max_bytes``.

    ``feed()`` returns ``(line, truncated, consumed)`` tuples where ``consumed`` is the
    total number of input bytes consumed up to the end of that line (for offset cursors).
    An over-long line is emitted as soon as it exceeds ``max_bytes`` (cut, ``truncated``)
    and the rest of it is dropped up to the next newline.
    """

    def __init__(self, max_bytes: int = MAX_LINE_BYTES) -> None:
        self._max = max_bytes
        self._buf = b""
        self._discarding = False
        self.consumed = 0

    @property
    def pending(self) -> int:
        """Bytes buffered that do not form a complete line yet."""
        return len(self._buf)

    def feed(self, data: bytes) -> list[tuple[bytes, bool, int]]:
        """Add bytes; return the complete lines they finish."""
        *lines, self._buf = (self._buf + data).split(b"\n")
        out: list[tuple[bytes, bool, int]] = []
        for line in lines:
            self.consumed += len(line) + 1
            if self._discarding:  # tail of an over-long line we already emitted
                self._discarding = False
                continue
            out.append(
                (line[: self._max].removesuffix(b"\r"), len(line) > self._max, self.consumed)
            )
        if len(self._buf) > self._max:
            self.consumed += len(self._buf)
            if not self._discarding:
                out.append((self._buf[: self._max], True, self.consumed))
            self._discarding = True
            self._buf = b""
        return out

    def flush(self) -> tuple[bytes, bool, int] | None:
        """Emit a trailing partial line (at EOF or when the file is rotated away)."""
        line, discarding = self._buf, self._discarding
        self._buf, self._discarding = b"", False
        self.consumed += len(line)
        if not line or discarding:
            return None
        return (line.removesuffix(b"\r"), False, self.consumed)


def decode(line: bytes) -> str:
    """Bytes to text: UTF-8, invalid sequences replaced (logs are not always UTF-8)."""
    return line.decode("utf-8", "replace")
