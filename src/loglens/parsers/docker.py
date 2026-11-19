"""dockerd / containerd daemon lines (logfmt), classified into lifecycle events."""

from __future__ import annotations

from loglens.core.models import LogSource, RawRecord, Severity
from loglens.parsers.base import ParsedFields, SourceMatch, events, match_event, unparsed
from loglens.parsers.generic import parse_logfmt, parse_syslog, structured

_EVENTS = events(
    ("daemon_starting", r"Starting up$", Severity.NOTICE),
    ("daemon_ready", r"Daemon has completed initialization", Severity.NOTICE),
    ("api_listening", r"API listen on (?P<socket>\S+)", None),
    ("loading_containers", r"Loading containers: (?P<phase>start|done)", None),
    ("daemon_signal", r"Processing signal '(?P<signal>\w+)'", Severity.NOTICE),
    ("daemon_stopped", r"Daemon shutdown complete", Severity.NOTICE),
    ("daemon_start_failed", r"(?:failed to start daemon|Error starting daemon)", Severity.CRITICAL),
    (
        "container_kill_forced",
        r"Container failed to exit within (?P<timeout_s>\d+)s of signal (?P<signal>\d+)",
        Severity.WARNING,
    ),
    ("container_stopped", r"stopping event stream following graceful shutdown", None),
    ("shim_exited", r"shim disconnected", None),
    ("shim_started", r"starting signal loop", None),
    ("shim_cleanup", r"cleaning up dead shim", None),
    (
        "healthcheck_error",
        r"Health check for container (?P<container_id>[0-9a-f]+) error: (?P<error>.*)",
        Severity.WARNING,
    ),
    ("container_oom", r"(?i).*\boom\b", Severity.ERROR),
)
#: containerd event topics dockerd logs as "ignoring event".
_TOPICS = {
    "/tasks/delete": ("container_exited", None),
    "/tasks/exit": ("container_exited", None),
    "/tasks/oom": ("container_oom", Severity.ERROR),
    "/tasks/start": ("container_started", None),
}


class DockerDaemonParser:
    """``time="..." level=info msg="..." container=...`` from dockerd and containerd."""

    name = "dockerd"
    match = SourceMatch(
        units=("docker.service", "containerd.service"),
        paths=("/var/log/docker.log", "/var/log/containerd.log"),
    )

    def matches(self, source: LogSource) -> bool:
        """Docker/containerd daemon sources (see ``match``)."""
        return self.match(source)

    def parse(self, record: RawRecord) -> ParsedFields:
        """logfmt body (optionally syslog-wrapped) -> fields + lifecycle ``event``."""
        text = record.message
        wrapper = unparsed() if text.startswith("time=") else parse_syslog(record, self.name)
        pairs = parse_logfmt((wrapper.message or "") if wrapper.parsed else text)
        if pairs is None:
            return unparsed()
        result = structured(self.name, pairs)
        if wrapper.parsed:  # /var/log/docker.log via rsyslog: keep host/program/pid
            result.fields = {**wrapper.fields, **result.fields}
        for key in ("container", "id", "container_id"):
            if key in pairs:
                result.fields["container_id"] = pairs[key]
                break
        msg = result.message or ""
        if msg == "ignoring event" and pairs.get("topic") in _TOPICS:
            event, severity = _TOPICS[pairs["topic"]]
        elif found := match_event(msg, _EVENTS):
            event, severity = found[0].event, found[0].severity
            result.fields.update(found[1])
        else:
            return result
        result.fields["event"] = event
        if severity is not None:  # an event can raise the logged level, never lower it
            result.severity = max(severity, result.severity or Severity.TRACE)
        return result
