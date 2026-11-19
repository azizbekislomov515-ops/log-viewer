"""Phase 4 insights: rates, error spikes, top values, restarts, repeats and the summary."""

from datetime import UTC, datetime, timedelta

from loglens.core.models import Category, Explanation, LogEntry, Severity
from loglens.explain.insights import analyze

NOW = datetime(2026, 11, 18, 12, 0, tzinfo=UTC)
SRC = "file:/var/log/squid/access.log"


def at(
    seconds_ago: float,
    message: str = "ok",
    severity: Severity = Severity.INFO,
    source: str = SRC,
    **fields: object,
) -> LogEntry:
    stamp = NOW - timedelta(seconds=seconds_ago)
    return LogEntry(0, source, stamp, severity, message, message, fields)


def restart_tagger(entry: LogEntry) -> Explanation | None:
    if entry.message != "started":
        return None
    return Explanation(
        "t", "t", Severity.NOTICE, Category.AVAILABILITY, "x.start", tags=("restart",)
    )


def test_empty_input() -> None:
    assert analyze([]) == {}


def test_rate_errors_top_values_and_summary(local_tz: None) -> None:
    entries = [at(i * 10, client_ip=f"10.0.0.{i % 3}", domain="example.com") for i in range(20)]
    entries += [at(5, "boom", Severity.ERROR, client_ip="10.0.0.0", status=502)]
    entries += [at(400, "too old for the window")]
    (insight,) = analyze(entries, now=NOW, repeat_threshold=100).values()
    assert insight.total == 21  # 20 + the error; the 400 s old entry is outside 5 min
    assert insight.events_per_min == 21 / 5
    assert insight.errors == 1 and insight.error_rate == 1 / 21
    assert insight.top["client_ip"][0] == ("10.0.0.0", 8)
    assert insight.top["domain"] == (("example.com", 20),)
    assert insight.top["status"] == (("502", 1),)
    assert "user" not in insight.top
    assert insight.spike is None and insight.restarts == 0 and insight.repeated == ()
    assert insight.summary == (
        f"{SRC}: 21 events in the last 5 min (4.2/min). 1 error (5% of events). "
        "Most frequent client: 10.0.0.0 (8 events). Most frequent domain: example.com "
        "(20 events). Most frequent status code: 502 (1 event)."
    )


def test_now_defaults_to_the_newest_entry_and_sources_are_separate() -> None:
    entries = [at(60), at(30, source="docker:web-1"), at(0, source="docker:web-1")]
    result = analyze(entries)
    assert list(result) == ["docker:web-1", SRC]
    assert result["docker:web-1"].end == NOW and result[SRC].total == 1
    assert result["docker:web-1"].summary.endswith("No errors. Looks healthy.")


def test_quiet_source() -> None:
    (insight,) = analyze([at(3600)], now=NOW).values()
    assert insight.total == 0 and insight.events_per_min == 0 and insight.error_rate == 0
    assert insight.summary == f"{SRC}: quiet, no events in the last 5 min."


def test_error_spike_against_baseline(local_tz: None) -> None:
    # One error per minute for 30 minutes, then 12 errors in the last minute.
    entries = [at(60 * m + 30, "db timeout", Severity.ERROR) for m in range(1, 31)]
    entries += [at(i, "db timeout", Severity.ERROR) for i in range(12)]
    (insight,) = analyze(entries, now=NOW).values()
    spike = insight.spike
    assert spike is not None
    assert spike.errors_last_minute == 12
    assert spike.baseline_mean == 1.0 and spike.baseline_stdev == 0.0
    assert spike.z_score == 11.0  # stdev floor of 1
    assert "Error spike: 12 errors in the last minute against a usual 1.0 per minute." in (
        insight.summary
    )
    assert '"db timeout" (or similar) repeated 16 times in 5 min.' in insight.summary


def test_no_spike_without_enough_history_or_errors() -> None:
    burst = [at(i, "x", Severity.ERROR) for i in range(12)]
    (insight,) = analyze(burst, now=NOW).values()
    assert insight.spike is None  # no baseline yet
    steady = [at(60 * m + 30, "x", Severity.ERROR) for m in range(1, 31) for _ in range(5)]
    steady += [at(i, "x", Severity.ERROR) for i in range(6)]
    (insight,) = analyze(steady, now=NOW).values()
    assert insight.spike is None  # 6 vs a usual 5 is not a spike
    warnings = [at(60 * m, "w", Severity.WARNING) for m in range(30)] + [
        at(i, "w", Severity.WARNING) for i in range(20)
    ]
    assert analyze(warnings, now=NOW)[SRC].spike is None  # only ERROR+ counts


def test_restarts_use_the_restart_tag(local_tz: None) -> None:
    entries = [at(200, "started"), at(100, "stopped"), at(50, "started"), at(10)]
    (insight,) = analyze(entries, now=NOW, explain=restart_tagger).values()
    assert insight.restarts == 2
    assert insight.last_restart == NOW - timedelta(seconds=50)
    assert "Restarted 2 times, most recently at 11:59:10." in insight.summary
    assert analyze(entries, now=NOW)[SRC].restarts == 0  # no explainer, no restart info


def test_repeated_messages_collapse_numbers_and_ids() -> None:
    entries = [
        at(i, f"Failed password for root from 203.0.113.{i} port {50000 + i}") for i in range(12)
    ]
    entries += [at(i, f"container {i:012x}abcdef exited") for i in range(10)]
    entries += [at(1, "unique line")]
    (insight,) = analyze(entries, now=NOW, repeat_threshold=10).values()
    assert [(r.count, r.example[:20]) for r in insight.repeated] == [
        (12, "Failed password for "),
        (10, "container 0000000000"),
    ]
    first = insight.repeated[0]
    assert first.first == NOW and first.last == NOW - timedelta(seconds=11)


def test_long_repeated_message_is_shortened_in_summary() -> None:
    entries = [at(i, "x" * 200) for i in range(10)]
    (insight,) = analyze(entries, now=NOW).values()
    assert f'"{"x" * 79}…" (or similar) repeated 10 times' in insight.summary
