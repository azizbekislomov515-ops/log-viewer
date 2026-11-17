from datetime import UTC, datetime, timedelta, timezone

import pytest

from loglens.core.models import LogEntry, LogSource, Severity, SourceKind


@pytest.mark.parametrize(
    ("priority", "expected"),
    [
        (0, Severity.CRITICAL),
        (1, Severity.CRITICAL),
        (2, Severity.CRITICAL),
        (3, Severity.ERROR),
        (4, Severity.WARNING),
        (5, Severity.NOTICE),
        (6, Severity.INFO),
        (7, Severity.DEBUG),
    ],
)
def test_syslog_priority_mapping(priority: int, expected: Severity) -> None:
    assert Severity.from_syslog_priority(priority) is expected


@pytest.mark.parametrize("priority", [-1, 8])
def test_syslog_priority_out_of_range(priority: int) -> None:
    with pytest.raises(ValueError, match=r"0\.\.7"):
        Severity.from_syslog_priority(priority)


@pytest.mark.parametrize(
    ("level", "expected"),
    [
        ("TRACE", Severity.TRACE),
        ("debug", Severity.DEBUG),
        ("Info", Severity.INFO),
        ("notice", Severity.NOTICE),
        ("WARN", Severity.WARNING),
        ("warning", Severity.WARNING),
        ("err", Severity.ERROR),
        ("ERROR", Severity.ERROR),
        ("fatal", Severity.CRITICAL),
        ("emerg", Severity.CRITICAL),
        ("panic", Severity.CRITICAL),
        ("  crit ", Severity.CRITICAL),
        ("3", Severity.ERROR),  # journald PRIORITY is a string
        (6, Severity.INFO),
    ],
)
def test_level_mapping(level: str | int, expected: Severity) -> None:
    assert Severity.from_level(level) is expected


@pytest.mark.parametrize("level", ["bogus", "", "42", 9, -1])
def test_unknown_level_is_none(level: str | int) -> None:
    assert Severity.from_level(level) is None


def test_severity_is_ordered() -> None:
    assert Severity.TRACE < Severity.INFO < Severity.WARNING < Severity.CRITICAL


def test_log_entry_requires_tz_aware_and_normalizes_to_utc() -> None:
    plus3 = timezone(timedelta(hours=3))
    entry = LogEntry("1", "s", datetime(2026, 1, 1, 12, tzinfo=plus3), Severity.INFO, "m", "r")
    assert entry.timestamp == datetime(2026, 1, 1, 9, tzinfo=UTC)
    assert entry.timestamp.tzinfo is UTC
    with pytest.raises(ValueError, match="timezone-aware"):
        LogEntry("1", "s", datetime(2026, 1, 1), Severity.INFO, "m", "r")


def test_models_are_deeply_immutable() -> None:
    meta = {"unit": "a.service"}
    src = LogSource("systemd:a.service", SourceKind.SYSTEMD, "a", "g", metadata=meta)
    meta["unit"] = "changed"  # caller's dict is copied, not aliased
    assert src.metadata["unit"] == "a.service"
    with pytest.raises(TypeError):
        src.metadata["x"] = "y"  # type: ignore[index]
    with pytest.raises(AttributeError):
        src.display_name = "b"  # type: ignore[misc]
