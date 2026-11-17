"""Core domain model: log sources, service groups, severities, entries and discovery issues.

All models are frozen dataclasses. Mapping fields are wrapped in ``MappingProxyType``
so instances are immutable all the way down and safe to share across threads.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import IntEnum, StrEnum
from types import MappingProxyType
from typing import Any


def _freeze(mapping: Mapping[str, Any]) -> Mapping[str, Any]:
    if type(mapping) is MappingProxyType:  # already frozen by us (e.g. dataclasses.replace)
        return mapping
    return MappingProxyType(dict(mapping))


def utc_now() -> datetime:
    """Return the current time as a tz-aware UTC datetime."""
    return datetime.now(UTC)


class SourceKind(StrEnum):
    """Where a log source's lines come from."""

    SYSTEMD = "systemd"
    DOCKER_CONTAINER = "docker_container"
    FILE = "file"


class SourceStatus(StrEnum):
    """Coarse health of the thing producing the logs."""

    RUNNING = "running"
    STOPPED = "stopped"
    FAILED = "failed"
    UNKNOWN = "unknown"


class GroupKind(StrEnum):
    """How sources are grouped in the UI."""

    SYSTEM = "system"
    DOCKER_COMPOSE = "docker_compose"
    DOCKER_STANDALONE = "docker_standalone"
    FILES = "files"


class Severity(IntEnum):
    """Normalized log severity. Ordered: a higher value is more severe."""

    TRACE = 0
    DEBUG = 1
    INFO = 2
    NOTICE = 3
    WARNING = 4
    ERROR = 5
    CRITICAL = 6

    @classmethod
    def from_syslog_priority(cls, priority: int) -> Severity:
        """Map a syslog/journald PRIORITY (0=emerg .. 7=debug) to a Severity.

        Raises:
            ValueError: if ``priority`` is outside 0..7.
        """
        if not 0 <= priority <= 7:
            raise ValueError(f"syslog priority must be 0..7, got {priority}")
        return _SYSLOG_PRIORITY[priority]

    @classmethod
    def from_level(cls, level: str | int) -> Severity | None:
        """Map a level as found in logs ("WARN", "err", "Fatal", "3", 3, ...) to a Severity.

        Integers and digit strings are treated as syslog priorities (journald's
        ``PRIORITY`` field is a string). Returns ``None`` for unrecognized input so the
        caller decides the fallback.
        """
        if isinstance(level, int):
            return cls.from_syslog_priority(level) if 0 <= level <= 7 else None
        text = level.strip().lower()
        if text.isdigit():
            return cls.from_level(int(text))
        return _LEVEL_NAMES.get(text)


_SYSLOG_PRIORITY: tuple[Severity, ...] = (
    Severity.CRITICAL,  # 0 emerg
    Severity.CRITICAL,  # 1 alert
    Severity.CRITICAL,  # 2 crit
    Severity.ERROR,  # 3 err
    Severity.WARNING,  # 4 warning
    Severity.NOTICE,  # 5 notice
    Severity.INFO,  # 6 info
    Severity.DEBUG,  # 7 debug
)

_LEVEL_NAMES: dict[str, Severity] = {
    "trace": Severity.TRACE,
    "verbose": Severity.TRACE,
    "debug": Severity.DEBUG,
    "dbg": Severity.DEBUG,
    "info": Severity.INFO,
    "information": Severity.INFO,
    "informational": Severity.INFO,
    "notice": Severity.NOTICE,
    "warn": Severity.WARNING,
    "warning": Severity.WARNING,
    "err": Severity.ERROR,
    "error": Severity.ERROR,
    "fail": Severity.ERROR,
    "failure": Severity.ERROR,
    "severe": Severity.ERROR,
    "crit": Severity.CRITICAL,
    "critical": Severity.CRITICAL,
    "fatal": Severity.CRITICAL,
    "alert": Severity.CRITICAL,
    "emerg": Severity.CRITICAL,
    "emergency": Severity.CRITICAL,
    "panic": Severity.CRITICAL,
}


@dataclass(frozen=True, slots=True)
class LogSource:
    """One stream of log lines: a systemd unit, a container, or a file.

    ``id`` is deterministic (``systemd:nginx.service``, ``docker:web-1``,
    ``file:/var/log/squid/access.log``) so it is stable across refreshes and restarts.
    """

    id: str
    kind: SourceKind
    display_name: str
    group_id: str
    status: SourceStatus = SourceStatus.UNKNOWN
    metadata: Mapping[str, Any] = field(default_factory=dict)
    discovered_at: datetime = field(default_factory=utc_now)

    def __post_init__(self) -> None:
        object.__setattr__(self, "metadata", _freeze(self.metadata))


@dataclass(frozen=True, slots=True)
class ServiceGroup:
    """A set of sources shown together (a Compose project, the systemd units, Squid's files)."""

    id: str
    name: str
    kind: GroupKind
    sources: tuple[LogSource, ...] = ()


@dataclass(frozen=True, slots=True)
class RawRecord:
    """One line as a collector produced it, before normalization.

    ``cursor`` is an opaque, collector-specific resume position *after* this record
    (journald ``__CURSOR``, Docker ``<ts_ns>:<n>``, file ``<dev>:<ino>:<offset>``).
    Persisting it together with the record is what makes restarts duplicate-free.
    ``fields`` is not frozen: records are short-lived and on the hot path.
    """

    source_id: str
    message: str
    timestamp: datetime | None = None
    severity: Severity | None = None
    fields: Mapping[str, Any] = field(default_factory=dict)
    cursor: str | None = None


@dataclass(frozen=True, slots=True)
class LogEntry:
    """A single log line after collection. ``timestamp`` is always tz-aware UTC.

    ``id`` is assigned by storage (monotonically increasing); 0 means "not stored yet",
    negative ids mean storage was unavailable and the entry lives only in memory.
    """

    id: int
    source_id: str
    timestamp: datetime
    severity: Severity
    message: str
    raw: str
    fields: Mapping[str, Any] = field(default_factory=dict)
    parsed: bool = False

    def __post_init__(self) -> None:
        if self.timestamp.tzinfo is None or self.timestamp.utcoffset() is None:
            raise ValueError("LogEntry.timestamp must be timezone-aware")
        object.__setattr__(self, "timestamp", self.timestamp.astimezone(UTC))
        object.__setattr__(self, "fields", _freeze(self.fields))


@dataclass(frozen=True, slots=True)
class DiscoveryIssue:
    """Something that limited discovery, phrased so the GUI can show it to the user as-is.

    ``code`` is machine-readable (e.g. ``docker_permission_denied``); ``hint`` is the
    actionable next step, if any.
    """

    discoverer: str
    code: str
    message: str
    severity: Severity = Severity.WARNING
    hint: str | None = None


@dataclass(frozen=True, slots=True)
class DiscoveryResult:
    """What a single discoverer found in one run."""

    groups: tuple[ServiceGroup, ...] = ()
    issues: tuple[DiscoveryIssue, ...] = ()
