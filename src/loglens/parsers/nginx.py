"""Nginx access (combined / common) and error log lines."""

from __future__ import annotations

import re
from typing import Any

from loglens.core.models import LogSource, RawRecord, Severity
from loglens.parsers.base import ParsedFields, SourceMatch, unparsed
from loglens.parsers.timestamps import parse_clf, parse_iso, warn_unparseable


def _q(name: str) -> str:
    """A double-quoted field; \\-escapes allowed (apache style)."""
    return rf'"(?P<{name}>(?:[^"\\]|\\.)*)"'


_ACCESS = re.compile(
    rf"(?P<client>\S+) (?P<ident>\S+) (?P<user>\S+) \[(?P<ts>[^\]]+)\] {_q('request')}"
    rf" (?P<status>\d{{3}}) (?P<bytes>\d+|-)(?: {_q('referer')} {_q('agent')})?(?P<extra>.*)",
    re.DOTALL,
)
_REQUEST = re.compile(r"(?P<method>[A-Z][A-Z_-]*) (?P<path>\S+)(?: (?P<protocol>[A-Z]+/[\d.]+))?")
_ERROR = re.compile(
    r"(?P<ts>\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}) \[(?P<level>[a-z]+)\]"
    r" (?P<pid>\d+)#(?P<tid>\d+): (?:\*(?P<connection>\d+) )?(?P<msg>.*)",
    re.DOTALL,
)
#: What the nginx binary prints itself (config test, startup failure; seen in journald).
_BINARY = re.compile(r"nginx: \[(?P<level>[a-z]+)\] (?P<msg>.*)", re.DOTALL)
_CONTEXT_START = re.compile(r", (?:client|server): ")
_CONTEXT = re.compile(
    r", (client|server|request|upstream|host|referrer|subrequest): ("
    r'"(?:[^"\\]|\\.)*"|[^,]*)'
)


def status_severity(status: int) -> Severity:
    """HTTP status -> severity: 5xx error, 4xx warning, else info."""
    if status >= 500:
        return Severity.ERROR
    return Severity.WARNING if status >= 400 else Severity.INFO


def parse_access(text: str, parser: str) -> ParsedFields:
    """Combined/common log format (nginx, apache, squid ``logformat combined``)."""
    if not text or not (m := _ACCESS.fullmatch(text)):
        return unparsed()
    status = int(m["status"])
    fields: dict[str, Any] = {"client_ip": m["client"], "status": status}
    if m["user"] != "-":
        fields["user"] = m["user"]
    request = m["request"]
    if req := _REQUEST.fullmatch(request):
        fields.update((k, v) for k, v in req.groupdict().items() if v is not None)
    elif request != "-":
        fields["request"] = request  # TLS handshakes, scanners: keep it verbatim
    if m["bytes"] != "-":
        fields["bytes"] = int(m["bytes"])
    if m["referer"] not in (None, "-"):
        fields["referer"] = m["referer"]
    if m["agent"] not in (None, "-"):
        fields["user_agent"] = m["agent"]
    if extra := m["extra"].strip():
        fields["extra"] = extra
    result = ParsedFields(True, severity=status_severity(status), fields=fields)
    result.timestamp = parse_clf(m["ts"])
    if result.timestamp is None:
        warn_unparseable(parser, m["ts"])
        fields["bad_timestamp"] = m["ts"]
    return result


def parse_error(text: str, parser: str) -> ParsedFields:
    """``2026/11/17 22:50:01 [error] 12#12: *5 msg, client: ..., server: ...``."""
    if not text or not (m := _ERROR.fullmatch(text)):
        return unparsed()
    msg = m["msg"]
    fields: dict[str, Any] = {"level": m["level"], "pid": int(m["pid"]), "tid": int(m["tid"])}
    if m["connection"]:
        fields["connection"] = int(m["connection"])
    if start := _CONTEXT_START.search(msg):
        for key, value in _CONTEXT.findall(msg, start.start()):
            fields["client_ip" if key == "client" else key] = value.strip('"')
        msg = msg[: start.start()]
    result = ParsedFields(True, message=msg, severity=Severity.from_level(m["level"]))
    result.fields = fields
    result.timestamp = parse_iso(m["ts"])
    if result.timestamp is None:
        warn_unparseable(parser, m["ts"])
        fields["bad_timestamp"] = m["ts"]
    return result


class NginxParser:
    """Nginx access and error logs: files, the nginx unit, nginx containers."""

    name = "nginx"
    match = SourceMatch(
        units=("nginx.service", "openresty.service"),
        paths=("/var/log/nginx/*",),
        images=("*nginx*", "*openresty*"),
        services=("*nginx*",),
    )

    def matches(self, source: LogSource) -> bool:
        """Nginx-looking sources (see ``match``)."""
        return self.match(source)

    def parse(self, record: RawRecord) -> ParsedFields:
        """Error format if the line starts with a date, else access format."""
        text = record.message
        if text[:1].isdigit() and text[4:5] == "/":
            return parse_error(text, self.name)
        if text.startswith("nginx: [") and (m := _BINARY.fullmatch(text)):
            level = Severity.from_level(m["level"])
            return ParsedFields(True, m["msg"], severity=level, fields={"level": m["level"]})
        return parse_access(text, self.name)
