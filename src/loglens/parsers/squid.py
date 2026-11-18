"""Squid access.log (native and combined formats) and cache.log."""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlsplit

from loglens.core.models import LogSource, RawRecord, Severity
from loglens.parsers.base import ParsedFields, SourceMatch, unparsed
from loglens.parsers.nginx import parse_access, status_severity
from loglens.parsers.timestamps import parse_epoch, parse_iso, warn_unparseable

# logformat squid: %ts.%03tu %6tr %>a %Ss/%03>Hs %<st %rm %ru %[un %Sh/%<a %mt
_NATIVE = re.compile(
    r"(?P<ts>\d+\.\d{3})\s+(?P<elapsed>-?\d+) (?P<client>\S+)"
    r" (?P<result>[A-Z_]+)/(?P<status>\d{3}) (?P<bytes>\d+) (?P<method>\S+) (?P<url>\S+)"
    r" (?P<user>\S+) (?P<hierarchy>[A-Z_]+)/(?P<peer>\S+) (?P<content_type>\S+)(?P<extra>.*)",
    re.DOTALL,
)
_CACHE = re.compile(
    r"(?P<ts>\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2})(?:\.\d+)?(?: (?P<kid>kid\d+))?\| ?(?P<msg>.*)",
    re.DOTALL,
)
_CACHE_LEVEL = re.compile(r"(WARNING|ERROR|FATAL|SECURITY ALERT|BUG \d+)\b")
_CACHE_SEVERITY = {
    "WARNING": Severity.WARNING,
    "ERROR": Severity.ERROR,
    "FATAL": Severity.CRITICAL,
    "SECURITY ALERT": Severity.WARNING,
}


def url_domain(method: str, url: str) -> str | None:
    """Host of a request target: ``host:443`` for CONNECT, else the absolute URL's host.

    Squid's pseudo-URLs (``error:invalid-request``) have no host and give None.
    """
    if method == "CONNECT":
        host, _, port = url.rpartition(":")
        return (host if port.isdigit() else url).strip("[]").lower() or None
    if "://" not in url:
        return None
    try:
        return urlsplit(url).hostname
    except ValueError:  # malformed IPv6 literal etc.
        return None


def _native(text: str, parser: str) -> ParsedFields:
    if not (m := _NATIVE.fullmatch(text)):
        return unparsed()
    status, result_code = int(m["status"]), m["result"]
    fields: dict[str, Any] = {
        "elapsed_ms": int(m["elapsed"]),
        "client_ip": m["client"],
        "cache_result": result_code,
        "status": status,
        "bytes": int(m["bytes"]),
        "method": m["method"],
        "url": m["url"],
        "hierarchy": m["hierarchy"],
    }
    if domain := url_domain(m["method"], m["url"]):
        fields["domain"] = domain
    for key in ("user", "peer", "content_type"):
        if m[key] != "-":
            fields[key] = m[key]
    if extra := m["extra"].strip():
        fields["extra"] = extra
    severity = status_severity(status)
    if "DENIED" in result_code:
        severity = max(severity, Severity.WARNING)
    timestamp = parse_epoch(m["ts"])
    if timestamp is None:
        warn_unparseable(parser, m["ts"])
        fields["bad_timestamp"] = m["ts"]
    return ParsedFields(True, timestamp=timestamp, severity=severity, fields=fields)


def _cache(text: str, parser: str) -> ParsedFields:
    if not (m := _CACHE.fullmatch(text)):
        return unparsed()
    msg = m["msg"]
    result = ParsedFields(True, message=msg, timestamp=parse_iso(m["ts"]))
    if m["kid"]:
        result.fields["kid"] = m["kid"]
    if level := _CACHE_LEVEL.match(msg):
        result.fields["level"] = level[1]
        result.severity = _CACHE_SEVERITY.get(level[1], Severity.ERROR)  # BUG nnn
    if result.timestamp is None:
        warn_unparseable(parser, m["ts"])
        result.fields["bad_timestamp"] = m["ts"]
    return result


class SquidParser:
    """Squid proxy: access.log (native or combined) and cache.log, files or containers."""

    name = "squid"
    match = SourceMatch(
        units=("squid.service", "squid3.service"),
        paths=("/var/log/squid/*", "/var/log/squid3/*"),
        images=("*squid*",),
        services=("*squid*",),
    )

    def matches(self, source: LogSource) -> bool:
        """Squid-looking sources (see ``match``)."""
        return self.match(source)

    def parse(self, record: RawRecord) -> ParsedFields:
        """Native access line, cache.log line, or combined-format access line."""
        text = record.message
        if not text[:1].isdigit():
            return parse_access(text, self.name)
        if text[4:5] == "/":
            return _cache(text, self.name)
        result = _native(text, self.name)
        return result if result.parsed else parse_access(text, self.name)
