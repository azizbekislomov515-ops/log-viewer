"""Timestamp parsing for the formats logs actually use. Everything returns tz-aware UTC.

Naive timestamps (no offset in the text) are taken as the machine's local time, which is
what syslog, nginx, squid and clamav write. Every function returns ``None`` instead of
raising; callers report it with ``warn_unparseable`` and fall back.
"""

from __future__ import annotations

import logging
from collections import Counter
from datetime import UTC, datetime, timedelta, timezone, tzinfo
from functools import lru_cache

log = logging.getLogger(__name__)

MONTHS = {
    m: i
    for i, m in enumerate(
        ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"), 1
    )
}
#: A year-less timestamp more than this far in the future belongs to last year.
_FUTURE_SLACK = timedelta(days=7)

# ponytail: process-wide counter so a broken source can't flood the app log; per-source
# counters if the GUI ever needs to show them.
_bad: Counter[str] = Counter()


def warn_unparseable(parser: str, text: str) -> None:
    """Log an unparseable timestamp: the first one per parser, then every 1000th."""
    _bad[parser] += 1
    n = _bad[parser]
    if n == 1 or n % 1000 == 0:
        log.warning(
            "unparseable timestamp, falling back",
            extra={"parser": parser, "timestamp": text[:64], "count": n},
        )


@lru_cache(maxsize=256)
def _local_tz(year: int, month: int, day: int, hour: int) -> tzinfo:
    # DST changes on hour boundaries, so the offset is constant within one local hour.
    offset = datetime(year, month, day, hour).astimezone().utcoffset() or timedelta(0)
    return timezone(offset)


def to_utc(moment: datetime) -> datetime:
    """Aware -> UTC; naive -> interpreted as local time -> UTC."""
    if moment.tzinfo is None:
        moment = moment.replace(
            tzinfo=_local_tz(moment.year, moment.month, moment.day, moment.hour)
        )
    return moment.astimezone(UTC)


def parse_iso(text: str) -> datetime | None:
    """ISO 8601 / RFC 3339, ``T`` or space, ``.``/``,`` fractions, ``Z``/offset/none.

    Also accepts ``YYYY/MM/DD HH:MM:SS`` (nginx error log, squid cache.log).
    """
    if len(text) > 10 and text[4] == "/" and text[7] == "/":
        text = text.replace("/", "-", 2)
    try:
        return to_utc(datetime.fromisoformat(text))
    except (ValueError, OverflowError):
        return None


@lru_cache(maxsize=4096)
def _rfc3164(text: str, year: int) -> datetime | None:
    parts = text.split()
    if len(parts) != 3 or (month := MONTHS.get(parts[0])) is None:
        return None
    try:
        hh, mm, ss = parts[2].split(":")
        return to_utc(datetime(year, month, int(parts[1]), int(hh), int(mm), int(ss)))
    except (ValueError, OverflowError):
        return None


def parse_rfc3164(text: str, reference: datetime) -> datetime | None:
    """``Nov 17 22:50:01`` / ``Nov  7 22:50:01`` (no year: the year of ``reference``,
    or the year before if that would put the line more than a week in the future)."""
    moment = _rfc3164(text, reference.year)
    if moment is not None and moment - reference > _FUTURE_SLACK:
        moment = _rfc3164(text, reference.year - 1)
    return moment


@lru_cache(maxsize=4096)
def parse_ctime(text: str) -> datetime | None:
    """``Tue Nov 17 22:50:01 2026`` (ClamAV), local time."""
    parts = text.split()
    if len(parts) != 5 or (month := MONTHS.get(parts[1])) is None:
        return None
    try:
        hh, mm, ss = parts[3].split(":")
        moment = datetime(int(parts[4]), month, int(parts[2]), int(hh), int(mm), int(ss))
    except (ValueError, OverflowError):
        return None
    return to_utc(moment)


@lru_cache(maxsize=4096)
def parse_clf(text: str) -> datetime | None:
    """Common Log Format ``17/Nov/2026:22:50:01 +0000`` (nginx/apache access logs)."""
    try:
        date, _, offset = text.partition(" ")
        day, mon, rest = date.split("/")
        year, hh, mm, ss = rest.split(":")
        tz: tzinfo | None = None
        if offset:
            sign = -1 if offset[0] == "-" else 1
            tz = timezone(sign * timedelta(hours=int(offset[1:3]), minutes=int(offset[3:5])))
        moment = datetime(int(year), MONTHS[mon], int(day), int(hh), int(mm), int(ss), tzinfo=tz)
    except (ValueError, KeyError, IndexError, OverflowError):
        return None
    return to_utc(moment)


def parse_epoch(value: float | int | str) -> datetime | None:
    """Unix time in s, ms, us or ns (picked by magnitude), as number or string."""
    try:
        number = float(value)
        for threshold, scale in ((1e17, 1e9), (1e14, 1e6), (1e11, 1e3)):  # ns, us, ms
            if abs(number) >= threshold:
                number /= scale
                break
        return datetime.fromtimestamp(number, UTC)
    except (ValueError, OverflowError, OSError):
        return None
