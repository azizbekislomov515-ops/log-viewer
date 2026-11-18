"""Multi-line event assembly (stack traces, indented continuations) and exception fields.

Collectors emit one record per physical line. ``MultilineAssembler`` merges a line into
the previous record of the same source when it looks like a continuation:

* it starts with whitespace (frames, wrapped text), or
* it is a Python traceback header / chain marker, a Java ``Caused by:`` or a
  fully-qualified Java exception line, or
* it is the final ``SomeError: msg`` line of a Python traceback, or a blank line inside one,

and, when both lines carry timestamps, it is at most ``max_gap`` seconds after the
previous line. An event is emitted when a non-continuation line arrives, when its source
has been idle for ``idle`` seconds, or when it hits ``max_lines`` / ``max_chars``.

The merged record keeps the first line's timestamp/fields and the *last* line's cursor,
so storing it advances the resume position past every line it contains; lines still
pending are never covered by a stored cursor and are re-read after a crash.
"""

from __future__ import annotations

import asyncio
import contextlib
import re
from collections.abc import AsyncIterator
from dataclasses import dataclass, replace
from datetime import timedelta
from typing import Any

from loglens.core.models import RawRecord

#: Hard cap on an assembled event (same as the normalizer's message cap).
MAX_EVENT_CHARS = 64 * 1024
MAX_EVENT_LINES = 500

PY_TRACEBACK = "Traceback (most recent call last):"
_PY_CHAIN = frozenset(
    {
        "During handling of the above exception, another exception occurred:",
        "The above exception was the direct cause of the following exception:",
    }
)
_PY_EXCEPTION = re.compile(r"([A-Za-z_][\w.]*)(?::\s?(.*))?", re.DOTALL)
_JAVA_EXCEPTION = re.compile(
    r"(?:Exception in thread \"[^\"]*\" )?"
    r"((?:[a-z_$][\w$]*\.)+[A-Z][\w$]*(?:Exception|Error|Throwable)[\w$]*)(?::\s?(.*))?",
    re.DOTALL,
)


@dataclass(slots=True)
class _Pending:
    records: list[RawRecord]
    chars: int
    arrived: float
    in_traceback: bool = False
    last_indented: bool = False

    def add(self, record: RawRecord, now: float) -> None:
        line = record.message
        self.records.append(record)
        self.chars += len(line) + 1
        self.arrived = now
        self.in_traceback = self.in_traceback or line.startswith(PY_TRACEBACK)
        self.last_indented = bool(line) and line[0] in " \t"

    def merged(self) -> RawRecord:
        first = self.records[0]
        if len(self.records) == 1:
            return first
        fields = dict(first.fields)
        fields["lines"] = len(self.records)
        if any(r.fields.get("truncated") for r in self.records):
            fields["truncated"] = True
        return replace(
            first,
            message="\n".join(r.message for r in self.records),
            fields=fields,
            cursor=self.records[-1].cursor or first.cursor,
        )


class MultilineAssembler:
    """Merges continuation lines per source. Feed records in arrival order.

    ``now`` arguments are a monotonic clock (``loop.time()``); they drive the idle flush.
    """

    def __init__(
        self,
        *,
        max_gap: float = 2.0,
        idle: float = 0.5,
        max_lines: int = MAX_EVENT_LINES,
        max_chars: int = MAX_EVENT_CHARS,
    ) -> None:
        self._max_gap = timedelta(seconds=max_gap)
        self.idle = idle
        self._max_lines = max_lines
        self._max_chars = max_chars
        self._pending: dict[str, _Pending] = {}

    @property
    def pending(self) -> bool:
        """True while any event is waiting for possible continuation lines."""
        return bool(self._pending)

    def feed(self, record: RawRecord, now: float) -> list[RawRecord]:
        """Add one line; return the events this completes (0 or 1)."""
        current = self._pending.get(record.source_id)
        if current is not None and self._continues(current, record):
            current.add(record, now)
            return []
        out = [current.merged()] if current is not None else []
        self._pending[record.source_id] = _Pending([], 0, now)
        self._pending[record.source_id].add(record, now)
        return out

    def flush_idle(self, now: float) -> list[RawRecord]:
        """Emit events whose source has been quiet for ``idle`` seconds."""
        quiet = [sid for sid, p in self._pending.items() if now - p.arrived >= self.idle]
        return [self._pending.pop(sid).merged() for sid in quiet]

    def flush(self) -> list[RawRecord]:
        """Emit everything pending (end of stream / shutdown)."""
        out = [p.merged() for p in self._pending.values()]
        self._pending.clear()
        return out

    def _continues(self, pending: _Pending, record: RawRecord) -> bool:
        line = record.message
        if (
            len(pending.records) >= self._max_lines
            or pending.chars + len(line) + 1 > self._max_chars
        ):
            return False
        last = pending.records[-1].timestamp
        if (
            last is not None
            and record.timestamp is not None
            and record.timestamp - last > self._max_gap
        ):
            return False
        return is_continuation(line, in_traceback=pending.in_traceback,
                               after_indented=pending.last_indented)  # fmt: skip


def is_continuation(line: str, *, in_traceback: bool, after_indented: bool) -> bool:
    """Whether ``line`` continues the previous event (see the module docstring)."""
    if not line:
        return in_traceback
    if line[0] in " \t" or line.startswith(PY_TRACEBACK) or line in _PY_CHAIN:
        return True
    if line.startswith("Caused by: "):
        return True
    if _JAVA_EXCEPTION.fullmatch(line) and not line.startswith("Exception in thread "):
        return True
    return in_traceback and after_indented and _PY_EXCEPTION.fullmatch(line) is not None


def exception_fields(text: str) -> dict[str, Any]:
    """Exception type/message/frame count from an assembled Python or Java stack trace.

    Python: the final ``Type: message`` line (the exception actually raised). Java: the
    root cause (last ``Caused by:``), else the first exception line. ``{}`` if neither.
    """
    lines = text.split("\n")
    if len(lines) < 2:
        return {}
    if any(line.startswith(PY_TRACEBACK) for line in lines):
        for line in reversed(lines):
            if line and line[0] not in " \t" and (m := _PY_EXCEPTION.fullmatch(line)):
                return {
                    "exception_type": m[1],
                    "exception_message": m[2] or "",
                    "stack_language": "python",
                    "stack_frames": sum(line.startswith('  File "') for line in lines),
                }
        return {}
    frames = sum(line.lstrip().startswith("at ") for line in lines)
    if not frames:
        return {}
    causes = [line.removeprefix("Caused by: ") for line in lines if line.startswith("Caused by: ")]
    for candidate in [*reversed(causes), *lines]:
        if m := _JAVA_EXCEPTION.search(candidate):
            return {
                "exception_type": m[1],
                "exception_message": (m[2] or "").strip(),
                "stack_language": "java",
                "stack_frames": frames,
            }
    return {}


async def assemble_stream(
    records: AsyncIterator[RawRecord], assembler: MultilineAssembler
) -> AsyncIterator[RawRecord]:
    """Apply ``assembler`` to a live stream, emitting a pending event once the stream has
    been idle for ``assembler.idle`` seconds (used by ``tail``; the pipeline does the same
    in its writer loop without a task per record)."""
    loop = asyncio.get_running_loop()
    pending_next: asyncio.Task[RawRecord | None] | None = None
    try:
        while True:
            if pending_next is None:
                pending_next = asyncio.create_task(_next_or_none(records))
            if assembler.pending:
                done, _ = await asyncio.wait({pending_next}, timeout=assembler.idle)
                if not done:
                    for event in assembler.flush():
                        yield event
                    continue
            record = await pending_next
            pending_next = None
            if record is None:
                break
            for event in assembler.feed(record, loop.time()):
                yield event
        for event in assembler.flush():
            yield event
    finally:
        if pending_next is not None:
            pending_next.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):  # already reported
                await pending_next


async def _next_or_none(records: AsyncIterator[RawRecord]) -> RawRecord | None:
    try:
        return await anext(records)
    except StopAsyncIteration:
        return None
