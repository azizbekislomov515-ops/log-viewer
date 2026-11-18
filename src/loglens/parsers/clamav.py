"""ClamAV: clamd scan results and status, freshclam database updates."""

from __future__ import annotations

import re

from loglens.core.models import LogSource, RawRecord, Severity
from loglens.parsers.base import ParsedFields, SourceMatch, events, match_event, unparsed
from loglens.parsers.timestamps import parse_ctime, warn_unparseable

# "Tue Nov 17 22:50:01 2026 -> msg" (LogTime yes); without LogTime only "msg".
_PREFIX = re.compile(r"(?P<ts>[A-Z][a-z]{2} [A-Z][a-z]{2} [ \d]?\d \d{2}:\d{2}:\d{2} \d{4}) -> ")
_DB = r"(?P<database>[\w.-]+\.c[lv]d)"
_SIGS = r"\(version: (?P<version>\d+), sigs: (?P<signatures>\d+)"

E, W, INFO = Severity.ERROR, Severity.WARNING, Severity.INFO
_EVENTS = events(
    ("virus_found", r"(?P<file>.+?): (?P<signature>\S+) FOUND$", E),
    ("scan_error", r"(?P<file>.+?): (?P<error>.+) ERROR$", E),
    ("scan_clean", r"(?P<file>.+?): OK$", INFO),
    ("error", r"(?:ERROR: |!|LibClamAV Error: )(?P<error>.*)", E),
    ("warning", r"(?:WARNING: |\^|LibClamAV Warning: )(?P<warning>.*)", W),
    ("selfcheck_ok", r"SelfCheck: Database status OK", INFO),
    ("db_changed", r"SelfCheck: Database modification detected", INFO),
    ("db_loading", r"Reading databases from (?P<path>.+)", INFO),
    ("db_reloaded", r"Database correctly reloaded \((?P<signatures>\d+) signatures\)", INFO),
    ("db_loaded", r"Loaded (?P<signatures>\d+) signatures", INFO),
    ("db_up_to_date", rf"{_DB} (?:database )?is up[- ]to[- ]date {_SIGS}", INFO),
    ("db_updated", rf"{_DB} updated {_SIGS}", Severity.NOTICE),
    (
        "db_update_available",
        r"(?P<database>\w+) database available for update"
        r" \(local version: (?P<local_version>\d+), remote version: (?P<version>\d+)\)",
        INFO,
    ),
    (
        "db_update_done",
        r"Database updated \((?P<signatures>\d+) signatures\) from (?P<mirror>\S+)",
        Severity.NOTICE,
    ),
    ("update_started", r"ClamAV update process started", INFO),
    ("db_testing", r"Testing database: '(?P<path>[^']+)'", INFO),
    ("db_test_passed", r"Database test passed", INFO),
    ("daemon_started", r"\+\+\+ Started at", Severity.NOTICE),
    ("daemon_stopped", r"--- Stopped at", Severity.NOTICE),
    ("separator", r"-{8,}$", Severity.DEBUG),
    ("clamd_notified", r"Clamd successfully notified", INFO),
    ("clamd_notify_failed", r"Clamd was NOT notified", W),
    ("outdated_help", r"DON'T PANIC!", INFO),  # follows the OUTDATED warning
)
_INT_FIELDS = ("signatures", "version", "local_version")


class ClamavParser:
    """clamd and freshclam log lines (files, units, containers)."""

    name = "clamav"
    match = SourceMatch(
        units=("clamav-daemon.service", "clamav-freshclam.service", "clamd*", "freshclam*"),
        paths=("/var/log/clamav/*", "/var/log/clamd*", "/var/log/freshclam*"),
        images=("*clamav*",),
        services=("*clam*",),
    )

    def matches(self, source: LogSource) -> bool:
        """ClamAV-looking sources (see ``match``)."""
        return self.match(source)

    def parse(self, record: RawRecord) -> ParsedFields:
        """A timestamped line always parses; an unstamped one only if its shape is known."""
        text = record.message
        prefix = _PREFIX.match(text)
        body = text[prefix.end() :] if prefix else text
        found = match_event(body, _EVENTS)
        if prefix is None and found is None:
            return unparsed()
        result = ParsedFields(True, message=body)
        if found is not None:
            pattern, fields = found
            for key in _INT_FIELDS:
                if key in fields:
                    fields[key] = int(fields[key])
            result.fields = {"event": pattern.event, **fields}
            result.severity = pattern.severity
        if prefix is not None:
            result.timestamp = parse_ctime(prefix["ts"])
            if result.timestamp is None:
                warn_unparseable(self.name, prefix["ts"])
                result.fields["bad_timestamp"] = prefix["ts"]
        return result
