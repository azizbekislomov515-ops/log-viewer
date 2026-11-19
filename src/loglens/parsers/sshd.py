"""OpenSSH server lines from auth.log/secure (syslog-wrapped) or the ssh unit (journald)."""

from __future__ import annotations

from typing import Any

from loglens.core.models import LogSource, RawRecord, Severity
from loglens.parsers.base import ParsedFields, SourceMatch, events, match_event, unparsed
from loglens.parsers.generic import parse_syslog

_KEY = r"(?: ssh2)?(?:: (?P<key>.+))?"
_FROM = r"(?P<src_ip>[\da-fA-F.:]+) port (?P<src_port>\d+)"
_WHO = r"(?:(?P<phase>invalid|authenticating) user (?P<user>\S*) |user (?P<user_>\S+) )?"
W, INFO, N = Severity.WARNING, Severity.INFO, Severity.NOTICE
_EVENTS = events(
    (
        "accepted",
        rf"Accepted (?P<auth_method>\S+) for (?P<user>\S+) from {_FROM}{_KEY}",
        N,
    ),
    (
        "failed",
        rf"Failed (?P<auth_method>\S+) for (?:(?P<invalid>invalid) user )?(?P<user>\S*)"
        rf" from {_FROM}",
        W,
    ),
    (
        "invalid_user",
        r"Invalid user (?P<user>.*?) from (?P<src_ip>\S+)(?: port (?P<src_port>\d+))?$",
        W,
    ),
    ("disconnected", rf"Disconnected from {_WHO}{_FROM}", INFO),
    ("connection_closed", rf"Connection closed by {_WHO}{_FROM}", INFO),
    ("connection_reset", rf"Connection reset by {_WHO}{_FROM}", INFO),
    (
        "disconnecting",
        rf"Disconnecting {_WHO}{_FROM}: (?P<reason>.*?)(?: \[preauth\])?$",
        W,
    ),
    (
        "disconnect_received",
        rf"Received disconnect from {_FROM}:(?P<code>\d+): (?P<reason>.*?)(?: \[preauth\])?$",
        INFO,
    ),
    ("session_opened", r"pam_unix\(sshd:session\): session opened for user (?P<user>[^\s(]+)", N),
    ("session_closed", r"pam_unix\(sshd:session\): session closed for user (?P<user>\S+)", INFO),
    (
        "auth_failure",
        r"(?:pam_unix\(sshd:auth\): authentication failure;|PAM \d+ more authentication failures?;)"
        r".*?rhost=(?P<src_ip>\S*)(?:\s+user=(?P<user>\S+))?",
        W,
    ),
    (
        "max_auth_exceeded",
        rf"error: maximum authentication attempts exceeded for (?:(?P<invalid>invalid) user )?"
        rf"(?P<user>\S+) from {_FROM}",
        W,
    ),
    ("auth_timeout", r"Timeout before authentication for (?:connection from )?(?P<src_ip>\S+)", W),
    ("bad_banner", rf"banner exchange: Connection from {_FROM}: (?P<reason>.*)", W),
    ("no_ident", r"Did not receive identification string from (?P<src_ip>\S+)", W),
    ("listening", rf"Server listening on {_FROM}", INFO),
    ("stopping", r"Received signal (?P<signal>\d+); terminating", N),
)


class SshdParser:
    """sshd events: logins, failures, invalid users, disconnects, PAM sessions.

    For syslog-formatted files only ``sshd``/``sshd-session`` lines are claimed; other
    programs (sudo, cron, ...) fall through to the generic syslog parser.
    """

    name = "sshd"
    match = SourceMatch(
        units=("ssh.service", "sshd.service", "ssh@*.service", "sshd@*.service"),
        paths=("/var/log/auth.log*", "/var/log/secure*"),
    )

    def matches(self, source: LogSource) -> bool:
        """sshd/auth sources (see ``match``)."""
        return self.match(source)

    def parse(self, record: RawRecord) -> ParsedFields:
        """Syslog header (if any), then the sshd message shapes."""
        result = parse_syslog(record, self.name)
        if result.parsed:
            if not str(result.fields.get("program", "")).startswith("sshd"):
                return unparsed()
            body = result.message or ""
        else:
            body = record.message
        found = match_event(body, _EVENTS)
        if found is None:
            return result  # sshd line of an unknown shape: syslog fields only (or unparsed)
        pattern, groups = found
        result.parsed = True
        result.message = body
        result.severity = pattern.severity
        result.fields.update(_fields(pattern.event, groups, body))
        return result


def _fields(event: str, groups: dict[str, Any], body: str) -> dict[str, Any]:
    fields: dict[str, Any] = {"event": event}
    if "user_" in groups:
        groups["user"] = groups.pop("user_")
    phase = groups.pop("phase", None)
    if groups.pop("invalid", None) or phase == "invalid" or event == "invalid_user":
        fields["invalid_user"] = True
    if "src_port" in groups:
        groups["src_port"] = int(groups["src_port"])
    if body.endswith("[preauth]"):
        fields["preauth"] = True
    fields.update(groups)
    return fields
