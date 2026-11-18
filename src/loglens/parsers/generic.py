"""Format-generic parsers: JSON lines, syslog (RFC 3164 / RFC 5424), logfmt, ISO-stamped text.

They match every source and are the fallback chain behind service parsers. Each one does
a cheap first-character / regex check before any real work so a miss costs little.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any

from loglens.core.models import LogSource, RawRecord, Severity, utc_now
from loglens.parsers.base import ParsedFields, unparsed
from loglens.parsers.timestamps import parse_epoch, parse_iso, parse_rfc3164, warn_unparseable

LEVEL_KEYS = ("level", "severity", "lvl", "loglevel", "log.level", "levelname", "@l")
MESSAGE_KEYS = ("msg", "message", "@m", "event")  # event: structlog
TIME_KEYS = ("ts", "time", "timestamp", "@timestamp", "@t", "datetime", "asctime", "t")
#: Numeric times before this are not epoch timestamps (counters, durations, ...).
_MIN_EPOCH = datetime(2000, 1, 1, tzinfo=UTC)

#: Bunyan/pino numeric levels.
_NUMERIC_LEVELS = {
    10: Severity.TRACE,
    20: Severity.DEBUG,
    30: Severity.INFO,
    40: Severity.WARNING,
    50: Severity.ERROR,
    60: Severity.CRITICAL,
}


def level_to_severity(value: Any) -> Severity | None:
    """Severity from a level value: names ("warn"), syslog numbers (0-7), bunyan (10-60)."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return Severity.from_level(value) if 0 <= value <= 7 else _NUMERIC_LEVELS.get(value)
    if isinstance(value, str):
        return Severity.from_level(value) if len(value) < 32 else None
    return None


def reference_time(record: RawRecord) -> datetime:
    """Best guess of "now" for the record: its collector timestamp, else the host clock."""
    return record.timestamp or utc_now()


def structured(parser: str, obj: Mapping[str, Any]) -> ParsedFields:
    """Shared by JSON and logfmt: pull level/message/time out of a key-value object."""
    fields = dict(obj)
    result = ParsedFields(parsed=True, fields=fields)
    for key in LEVEL_KEYS:
        if key in fields:
            result.severity = level_to_severity(fields[key])
            if result.severity is not None:
                fields["level"] = fields.pop(key)
                break
    for key in MESSAGE_KEYS:
        if key in fields:
            value = fields.pop(key)
            result.message = value if isinstance(value, str) else json.dumps(value, default=str)
            break
    for key in TIME_KEYS:
        if key in fields:
            value = fields[key]
            if isinstance(value, bool):
                continue
            stamp = parse_iso(value) if isinstance(value, str) else None
            if stamp is None and (isinstance(value, int | float) or _is_number(str(value))):
                stamp = parse_epoch(value)
                if stamp is not None and stamp < _MIN_EPOCH:
                    stamp = None
            if stamp is None:
                warn_unparseable(parser, str(value))
                fields["bad_timestamp"] = str(value)[:64]
            else:
                result.timestamp = stamp
                del fields[key]
            break
    return result


def _is_number(text: str) -> bool:
    return text.replace(".", "", 1).isdigit()


class JsonParser:
    """One JSON object per line (zap, logrus JSON, pino, bunyan, structlog, ECS, ...)."""

    name = "json"

    def matches(self, source: LogSource) -> bool:
        """Every source."""
        return True

    def parse(self, record: RawRecord) -> ParsedFields:
        """Parse ``record.message`` if it is a JSON object."""
        text = record.message.strip()
        if not text.startswith("{") or not text.endswith("}"):
            return unparsed()
        try:
            obj = json.loads(text)
        except (ValueError, RecursionError):
            return unparsed()
        if not isinstance(obj, dict):
            return unparsed()
        return structured(self.name, obj)


# key=value or key="quoted \" value"; the whole line must be pairs (strict logfmt).
_LOGFMT_PAIR = r'[^\s="]+=(?:"(?:[^"\\]|\\.)*"|[^\s"]*)'
_LOGFMT_LINE = re.compile(rf"\s*{_LOGFMT_PAIR}(?:\s+{_LOGFMT_PAIR})+\s*")
_LOGFMT_PAIRS = re.compile(r'([^\s="]+)=("(?:[^"\\]|\\.)*"|[^\s"]*)')


def parse_logfmt(text: str) -> dict[str, str] | None:
    """``a=1 b="x y"`` -> dict, or None unless the whole line is >= 2 pairs."""
    if "=" not in text or not _LOGFMT_LINE.fullmatch(text):
        return None
    return {key: _unquote(value) for key, value in _LOGFMT_PAIRS.findall(text)}


def _unquote(value: str) -> str:
    if not value.startswith('"'):
        return value
    try:
        result = json.loads(value)
    except ValueError:  # Go-style escapes JSON doesn't know (\x..): keep the inner text
        return value[1:-1]
    return result if isinstance(result, str) else value[1:-1]


class LogfmtParser:
    """logfmt (Go: logrus text, dockerd, containerd, Grafana/Loki tools, ...)."""

    name = "logfmt"

    def matches(self, source: LogSource) -> bool:
        """Every source."""
        return True

    def parse(self, record: RawRecord) -> ParsedFields:
        """Parse ``record.message`` if the whole line is key=value pairs."""
        pairs = parse_logfmt(record.message)
        return unparsed() if pairs is None else structured(self.name, pairs)


_RFC5424 = re.compile(
    r"<(?P<pri>\d{1,3})>(?P<version>\d{1,2}) (?P<ts>\S+) (?P<host>\S+) (?P<app>\S+)"
    r" (?P<pid>\S+) (?P<msgid>\S+) (?P<sd>-|(?:\[(?:[^\]\\]|\\.)*\])+)(?: (?P<msg>.*))?",
    re.DOTALL,
)
_HOST_TAG = r"(?:(?P<host>[^\s:\[\]]+) )?(?:(?P<tag>[^\s:\[\]]+)(?:\[(?P<pid>\d+)\])?: ?)"
#: Classic BSD syslog: ``Nov 17 22:50:01 host tag[pid]: msg`` (host and tag optional).
_RFC3164 = re.compile(
    r"(?:<(?P<pri>\d{1,3})>)?(?P<ts>[A-Z][a-z]{2} [ \d]\d \d{2}:\d{2}:\d{2}) "
    rf"{_HOST_TAG}?(?P<msg>.*)",
    re.DOTALL,
)
#: rsyslog's high-precision variant (Debian 12+ default). The ``tag:`` is required here,
#: otherwise any ``<ISO time> WORD rest`` line would read as host=WORD.
_RFC3164_ISO = re.compile(
    r"(?:<(?P<pri>\d{1,3})>)?"
    r"(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})) "
    rf"{_HOST_TAG}(?P<msg>.*)",
    re.DOTALL,
)


_RFC5424_FIELDS = (
    ("host", "host"),
    ("program", "app"),
    ("pid", "pid"),
    ("msgid", "msgid"),
    ("structured_data", "sd"),
)


def parse_syslog(record: RawRecord, parser: str = "syslog") -> ParsedFields:
    """RFC 5424, RFC 3164 (BSD) or rsyslog's ISO-stamped variant; ``unparsed()`` otherwise.

    Fields: ``host``, ``program``, ``pid``, ``facility`` (when a PRI is present);
    RFC 5424 adds ``msgid`` and ``structured_data`` (raw).
    """
    text = record.message
    if not text or not (text[0] == "<" or text[0].isupper() or text[0].isdigit()):
        return unparsed()
    if match := _RFC5424.fullmatch(text):
        stamp = None if match["ts"] == "-" else match["ts"]
        msg = (match["msg"] or "").removeprefix("\ufeff")
        result = _syslog_result(parser, match["pri"], stamp, record, msg)
        if result.parsed:
            for key, group in _RFC5424_FIELDS:
                if match[group] != "-":
                    result.fields[key] = match[group]
        return result
    after_pri = text.find(">") + 1 if text[0] == "<" else 0
    bsd = _RFC3164_ISO if text[after_pri : after_pri + 1].isdigit() else _RFC3164
    if match := bsd.fullmatch(text):
        result = _syslog_result(parser, match["pri"], match["ts"], record, match["msg"].lstrip())
        for key, group in (("host", "host"), ("program", "tag"), ("pid", "pid")):
            if match[group]:
                result.fields[key] = match[group]
        return result
    return unparsed()


def _syslog_result(
    parser: str, pri: str | None, stamp: str | None, record: RawRecord, msg: str
) -> ParsedFields:
    result = ParsedFields(parsed=True, message=msg)
    if pri is not None:
        value = int(pri)
        if value > 191:  # facility 23 x 8 + severity 7
            return unparsed()
        result.fields["facility"] = value // 8
        result.severity = Severity.from_syslog_priority(value % 8)
    if stamp is not None:
        if stamp[0].isdigit():
            result.timestamp = parse_iso(stamp)
        else:
            result.timestamp = parse_rfc3164(stamp, reference_time(record))
        if result.timestamp is None:
            warn_unparseable(parser, stamp)
            result.fields["bad_timestamp"] = stamp
    return result


class SyslogParser:
    """RFC 5424 / RFC 3164 syslog lines (``/var/log/syslog``, ``messages``, forwarded)."""

    name = "syslog"

    def matches(self, source: LogSource) -> bool:
        """Every source."""
        return True

    def parse(self, record: RawRecord) -> ParsedFields:
        """See ``parse_syslog``."""
        return parse_syslog(record, self.name)


_ISO_TEXT = re.compile(
    r"\[?(?P<ts>\d{4}[-/]\d{2}[-/]\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?)"
    r"\]?(?:[\s|:-]+(?P<rest>.*))?",
    re.DOTALL,
)
_LEVELS = (
    r"TRACE|DEBUG|INFO|NOTICE|WARN|WARNING|ERROR|ERR|CRIT|CRITICAL|FATAL|SEVERE|PANIC|ALERT|EMERG"
)
#: ``ERROR``/``[ERROR]`` in upper case, or ``[Warning]``/``[notice]`` in brackets, any case.
_LEVEL_TOKEN = re.compile(rf"(?<![\w])(?:\[?({_LEVELS})\]?|\[(?i:({_LEVELS}))\])(?![\w])")
#: A level token must appear this early after the timestamp to count.
_LEVEL_WINDOW = 48


class IsoTextParser:
    """Plain text starting with an ISO-8601 timestamp, optionally followed by a level.

    ``2026-11-17 22:50:01,123 ERROR [main] App - boom`` -> level ERROR, message after it.
    """

    name = "iso_text"

    def matches(self, source: LogSource) -> bool:
        """Every source."""
        return True

    def parse(self, record: RawRecord) -> ParsedFields:
        """Parse a leading timestamp and level; the rest is the message."""
        text = record.message
        if not text or not (text[0].isdigit() or text[0] == "["):
            return unparsed()
        match = _ISO_TEXT.match(text)
        if match is None or (match.end() != len(text) and match["rest"] is None):
            return unparsed()
        rest = match["rest"] or ""
        result = ParsedFields(parsed=True, message=rest, timestamp=parse_iso(match["ts"]))
        if result.timestamp is None:
            warn_unparseable(self.name, match["ts"])
            result.fields["bad_timestamp"] = match["ts"]
        level = _LEVEL_TOKEN.search(rest, 0, _LEVEL_WINDOW)
        if level is not None:
            name = level[1] or level[2]
            result.severity = Severity.from_level(name)
            result.fields["level"] = name
            if level.start() == 0:  # level leads the message: strip it
                result.message = rest[level.end() :].lstrip(" :|-")
        return result
