"""Collect systemd journal entries via ``journalctl -o json --follow``."""

from __future__ import annotations

import asyncio
import json
import logging
import re
from collections import deque
from collections.abc import AsyncIterator, Sequence
from datetime import UTC, datetime, timedelta
from typing import Any

from loglens.collectors.base import Backoff, CollectorError, ErrorCallback, reconnecting
from loglens.core.models import LogSource, RawRecord, Severity

log = logging.getLogger(__name__)

#: journalctl JSON line limit. journald caps messages (~48 KiB by default), but binary
#: payloads are emitted as JSON int arrays (~4 bytes per byte). Longer lines are skipped.
MAX_JSON_LINE = 1024 * 1024
_EPOCH = datetime(1970, 1, 1, tzinfo=UTC)
_MATCH_RE = re.compile(r"^[A-Z0-9_]+=")
_STDERR_TAIL_LINES = 20


class JournaldCollector:
    """One ``journalctl`` process per source.

    The source is matched with ``--unit=<unit>`` (which also includes systemd's own
    messages about the unit), or with explicit ``FIELD=value`` matches from
    ``source.metadata["journal_match"]``.
    """

    def __init__(self, *, journalctl: str = "journalctl", backoff_max: float = 30.0) -> None:
        self._journalctl = journalctl
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
        """Stream journal entries for ``source`` (see ``Collector``)."""
        match = match_args(source)

        def open_stream(cur: str | None) -> AsyncIterator[RawRecord]:
            argv = [self._journalctl, *build_args(match, cur, since, lines, follow)]
            return self._run(source.id, argv)

        return reconnecting(
            open_stream,
            source.id,
            cursor=cursor,
            follow=follow,
            backoff=Backoff(maximum=self._backoff_max),
            on_error=on_error,
        )

    async def _run(self, source_id: str, argv: list[str]) -> AsyncIterator[RawRecord]:
        proc = await asyncio.create_subprocess_exec(
            *argv,
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            limit=MAX_JSON_LINE,
        )
        if proc.stdout is None or proc.stderr is None:  # pragma: no cover - PIPE requested
            raise CollectorError("journalctl pipes missing")
        stderr_tail: deque[str] = deque(maxlen=_STDERR_TAIL_LINES)
        # Always drain stderr: a full stderr pipe would block journalctl.
        drain = asyncio.create_task(_drain(proc.stderr, stderr_tail))
        try:
            while True:
                try:
                    line = await proc.stdout.readline()
                except ValueError:  # longer than MAX_JSON_LINE; asyncio already dropped it
                    log.warning("skipping oversized journal entry", extra={"source": source_id})
                    continue
                if not line:
                    break
                record = parse_entry(source_id, line)
                if record is not None:
                    yield record
            returncode = await proc.wait()
            await drain
            if returncode != 0:
                detail = " | ".join(stderr_tail) or f"exit status {returncode}"
                raise CollectorError(f"journalctl failed: {detail}")
        finally:
            drain.cancel()
            await _terminate(proc)


def match_args(source: LogSource) -> list[str]:
    """journalctl arguments selecting ``source``'s entries.

    Raises:
        ValueError: if ``journal_match`` contains something that is not ``FIELD=value``.
    """
    matches = source.metadata.get("journal_match")
    if matches:
        if isinstance(matches, str) or not all(
            isinstance(m, str) and _MATCH_RE.match(m) for m in matches
        ):
            raise ValueError(f"invalid journal_match for {source.id}: {matches!r}")
        return list(matches)
    unit = source.metadata.get("unit") or source.id.removeprefix("systemd:")
    return [f"--unit={unit}"]


def build_args(
    match: Sequence[str], cursor: str | None, since: datetime | None, lines: int, follow: bool
) -> list[str]:
    """Build journalctl arguments (without the executable). Start: cursor > since > lines."""
    args = ["--output=json", "--all", "--no-pager", "--quiet"]
    if follow:
        args.append("--follow")
    if cursor:
        args.append(f"--after-cursor={cursor}")
    elif since is not None:
        args.append(f"--since=@{int(since.timestamp())}")
    else:
        args.append(f"--lines={max(lines, 0)}")
    return [*args, *match]


def parse_entry(source_id: str, line: bytes) -> RawRecord | None:
    """Turn one ``journalctl -o json`` line into a RawRecord; None if it is not an entry.

    Field values may be strings, null (field too large), byte arrays (non-UTF-8 data,
    emitted as a list of ints) or lists of those (a field that occurs several times).
    """
    try:
        obj = json.loads(line)
    except ValueError:
        return None
    if not isinstance(obj, dict):
        return None

    timestamp = None
    realtime = obj.get("__REALTIME_TIMESTAMP")
    if isinstance(realtime, str) and realtime.isdigit():
        timestamp = _EPOCH + timedelta(microseconds=int(realtime))
    priority = _first_text(obj.get("PRIORITY"))
    cursor = obj.get("__CURSOR")
    fields = {
        key: _field_value(value)
        for key, value in obj.items()
        if not key.startswith("__") and key != "MESSAGE"
    }
    return RawRecord(
        source_id=source_id,
        message=_first_text(obj.get("MESSAGE")),
        timestamp=timestamp,
        severity=Severity.from_level(priority) if priority else None,
        fields=fields,
        cursor=cursor if isinstance(cursor, str) else None,
    )


def _is_bytes(value: list[Any]) -> bool:
    return all(isinstance(b, int) and 0 <= b <= 255 for b in value)


def _field_value(value: Any) -> str | list[str]:
    if isinstance(value, list) and value and not _is_bytes(value):
        return [_first_text(v) for v in value]  # repeated field
    return _first_text(value)


def _first_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        if _is_bytes(value):
            return bytes(value).decode("utf-8", "replace")
        return _first_text(value[0]) if value else ""
    return str(value)


async def _drain(stream: asyncio.StreamReader, tail: deque[str]) -> None:
    while True:
        try:
            line = await stream.readline()
        except ValueError:
            continue
        if not line:
            return
        tail.append(line.decode("utf-8", "replace").strip())


async def _terminate(proc: asyncio.subprocess.Process) -> None:
    if proc.returncode is not None:
        return
    try:
        proc.terminate()
        await asyncio.wait_for(proc.wait(), timeout=2)
    except ProcessLookupError:
        return
    except TimeoutError:
        proc.kill()
        await proc.wait()
