# ruff: noqa: E501  (real log lines from the demo stack are long)
"""Phase 6 logic without a display: overview reports and cards (from rule-pack metadata),
notification policy, the rule editor, and exports."""

import csv
import io
import json
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from loglens.collectors import source_from_id
from loglens.core.models import (
    Category,
    Explanation,
    LogEntry,
    LogSource,
    RawRecord,
    Severity,
    SourceKind,
    SourceStatus,
)
from loglens.explain import ExplanationEngine, load_rules
from loglens.explain.editor import (
    EditorError,
    RuleDraft,
    preview,
    save,
    selector_for,
    suggest,
    suggest_regex,
)
from loglens.explain.overview import applicable_packs, build_report, card_result, value_of
from loglens.explain.rules import CardSpec
from loglens.export import incident_report, write_entries
from loglens.gui.notify import DesktopNotifier, Notification, NotificationCenter
from loglens.parsers import Normalizer
from loglens.storage import Storage

NOW = datetime(2026, 11, 19, 12, 0, tzinfo=UTC)
SQUID = LogSource(
    "docker:loglens-demo-squid-1",
    SourceKind.DOCKER_CONTAINER,
    "squid",
    "g",
    SourceStatus.RUNNING,
    {"container_name": "loglens-demo-squid-1", "image": "loglens-demo/squid"},
)
CLAM = LogSource(
    "docker:loglens-demo-clamav-1",
    SourceKind.DOCKER_CONTAINER,
    "clamav",
    "g",
    SourceStatus.RUNNING,
    {"container_name": "loglens-demo-clamav-1", "image": "loglens-demo/clamav"},
)
SQUID_LINES = [
    "1795076810.563      0 172.18.0.6 TCP_DENIED/403 3431 CONNECT www.facebook.com:443 - HIER_NONE/- text/html",
    "1795076810.570      0 172.18.0.6 TCP_DENIED/403 3451 GET http://ads.doubleclick.net/pixel.gif - HIER_NONE/- text/html",
    "1795076810.584      0 172.18.0.6 TCP_MISS_ABORTED/503 3597 GET http://no-such-host.invalid/ - HIER_NONE/- text/html",
    "1795076811.470      0 172.18.0.5 TCP_MEM_HIT/200 353 GET http://web/ - HIER_NONE/- text/html",
    "1795076811.482      0 172.18.0.5 TCP_MISS/404 403 GET http://web/missing-page - HIER_DIRECT/172.18.0.4 text/html",
    "1795076811.496      0 172.18.0.5 TCP_DENIED/403 3431 CONNECT www.facebook.com:443 - HIER_NONE/- text/html",
]
CLAM_LINES = [
    "Thu Nov 19 08:26:10 2026 -> instream(172.18.0.7@33516): Eicar-Test-Signature.UNOFFICIAL FOUND",
    "Thu Nov 19 08:26:10 2026 -> instream(172.18.0.7@33510): OK",
    "ERROR: Thu Nov 19 08:26:15 2026 -> Update failed for database: daily",
    "ERROR: Thu Nov 19 08:26:15 2026 -> remote_cvdhead: Download failed (6) ERROR: Thu Nov 19 08:26:15 2026 ->  Message: Could not resolve hostname",
]


@pytest.fixture(scope="module")
def engine() -> ExplanationEngine:
    return ExplanationEngine(load_rules())


def entries_for(source: LogSource, lines: list[str], start_id: int = 1) -> list[LogEntry]:
    normalize = Normalizer()
    out = []
    for i, line in enumerate(lines):
        stamp = NOW - timedelta(seconds=len(lines) - i)
        entry = normalize(
            source,
            RawRecord(source.id, line, stamp),
        )
        out.append(replace(entry, id=start_id + i))
    return out


def test_demo_lines_are_explained_correctly(engine: ExplanationEngine) -> None:
    got = [engine.explain(e, SQUID) for e in entries_for(SQUID, SQUID_LINES)]
    assert [x.rule_id if x else None for x in got] == [
        "squid.access.denied_connect",
        "squid.access.denied",
        "squid.access.no_route",
        "squid.access.hit",
        "squid.access.not_found",
        "squid.access.denied_connect",
    ]
    assert "no-such-host.invalid" in got[2].plain_text  # DNS failure, not "client gave up"
    clam = [engine.explain(e, CLAM) for e in entries_for(CLAM, CLAM_LINES)]
    assert [x.rule_id if x else None for x in clam] == [
        "clamav.scan.stream_eicar",
        "clamav.scan.stream_clean",
        "clamav.update.db_failed",
        "clamav.update.download_error",
    ]
    assert clam[0].extracted["client"] == "172.18.0.7" and "detection" in clam[0].tags
    assert "harmless" in clam[0].plain_text


def test_overview_cards_come_from_rule_packs(engine: ExplanationEngine) -> None:
    entries = entries_for(SQUID, SQUID_LINES)
    explanations = {e.id: engine.explain(e, SQUID) for e in entries}
    histogram = [(e.timestamp.replace(second=0, microsecond=0), e.severity, 1) for e in entries]
    report = build_report(
        "squid",
        [SQUID],
        entries,
        explanations,
        histogram,
        packs=engine.packs,
        now=NOW,
        window=timedelta(hours=1),
        bucket=timedelta(minutes=1),
    )
    assert report.packs == ("squid", "docker")  # the service's own cards first
    cards = {c.title: c for c in report.cards}
    assert cards["Blocked sites"].rows[0] == ("www.facebook.com", "2")
    assert cards["Blocked sites"].total == 3
    assert cards["Top clients"].rows[0][0] in ("172.18.0.6", "172.18.0.5")
    assert cards["Sites that failed"].rows == (("no-such-host.invalid", "1"),)
    assert cards["Served from cache"].kind == "count" and cards["Served from cache"].total == 1
    assert cards["Proxy errors"].rows[0][1].startswith("Could not reach")
    assert len(report.timeline) == 60 and sum(b.total for b in report.timeline) == 6
    assert report.health.state in ("healthy", "degraded", "failing")
    assert "squid:" in report.summary and "Most frequent client" in report.summary


def test_clamav_detection_card_warns_and_health_reflects_errors(engine: ExplanationEngine) -> None:
    entries = entries_for(CLAM, CLAM_LINES)
    explanations = {e.id: engine.explain(e, CLAM) for e in entries}
    report = build_report(
        "clamav",
        [CLAM],
        entries,
        explanations,
        [],
        packs=engine.packs,
        now=NOW,
        window=timedelta(hours=1),
        bucket=timedelta(minutes=1),
    )
    detections = next(c for c in report.cards if c.title == "Detections")
    assert detections.warn and detections.rows[0][1] == "Antivirus test file from 172.18.0.7"
    assert detections.headers == ("time", "what", "signature", "file", "client")
    assert detections.rows[0][2] == "Eicar-Test-Signature.UNOFFICIAL"
    updates = next(c for c in report.cards if c.title == "Signature updates")
    assert updates.total == 2
    assert report.health.last_error is not None
    assert report.health.state == "degraded"  # 3 of 4 errors; the pack's limit is 50%
    assert any("errors" in r for r in report.health.reasons)


def test_docker_cards_for_container_lifecycle(engine: ExplanationEngine) -> None:
    flaky = LogSource(
        "docker:loglens-demo-flaky-1",
        SourceKind.DOCKER_CONTAINER,
        "flaky",
        "g",
        SourceStatus.RUNNING,
        {"container_name": "loglens-demo-flaky-1"},
    )
    lines = []
    for i in range(4):
        lines += [
            f"2026-11-19T11:5{i}:00.000+00:00 container die abc (exitCode=1, image=alpine, name=loglens-demo-flaky-1)",
            f"2026-11-19T11:5{i}:01.000+00:00 container start abc (image=alpine, name=loglens-demo-flaky-1)",
        ]
    entries = entries_for(flaky, lines)
    explanations = {e.id: engine.explain(e, flaky) for e in entries}
    report = build_report(
        "flaky",
        [flaky],
        entries,
        explanations,
        [],
        packs=engine.packs,
        now=NOW,
        window=timedelta(hours=1),
        bucket=timedelta(minutes=1),
    )
    cards = {c.title: c for c in report.cards}
    assert cards["Exit codes"].rows == (("1", "4"),)
    assert len(cards["Restart history"].rows) == 4
    assert report.health.restarts == 4 and report.health.last_restart is not None


def test_applicable_packs_and_card_kinds(engine: ExplanationEngine) -> None:
    file_src = source_from_id("file:/var/log/auth.log")
    assert [p.name for p in applicable_packs(engine.packs, [file_src], [])] == ["sshd"]
    assert applicable_packs(engine.packs, [source_from_id("docker:random")], [])[0].name == "docker"
    entry = entries_for(SQUID, SQUID_LINES[:1])[0]
    exp = engine.explain(entry, SQUID)
    assert value_of("domain", entry, exp) == "www.facebook.com"
    assert value_of("nope", entry, None) is None
    empty = card_result(CardSpec("X", "recent", limit=3, rules=frozenset({"x.y"})), [(entry, exp)])
    assert empty.rows == () and not empty.warn and empty.empty


def test_timeline_marks_spikes() -> None:
    from loglens.explain.insights import Thresholds  # noqa: PLC0415
    from loglens.explain.overview import _timeline  # noqa: PLC0415

    start = NOW - timedelta(minutes=20)
    hist = [(start + timedelta(minutes=m), Severity.ERROR, 1) for m in range(19)]
    hist += [
        (start + timedelta(minutes=19), Severity.ERROR, 30),
        (start + timedelta(minutes=19), Severity.INFO, 5),
    ]
    buckets = _timeline(hist, start, NOW, timedelta(minutes=1), Thresholds())
    assert len(buckets) == 20 and buckets[-1].spike and not buckets[5].spike
    assert buckets[-1].counts == (0, 30, 0, 5) and buckets[-1].errors == 30


# ---------------------------------------------------------------- notifications


def pair(source: str, severity: Severity, tags: tuple[str, ...] = (), t: int = 0) -> tuple:
    entry = LogEntry(1, source, NOW + timedelta(seconds=t), severity, "msg", "msg")
    exp = (
        Explanation(
            "Title",
            "Plain.",
            severity,
            Category.SECURITY,
            "x.y",
            tags=tags,
        )
        if tags
        else None
    )
    return entry, exp


def test_notification_conditions_mutes_and_rate_limits() -> None:
    clock = [0.0]
    center = NotificationCenter(
        ["critical", "detection", "restart_loop"], muted=["docker:muted"], clock=lambda: clock[0]
    )
    names = {"docker:clam": "clamav"}
    notes = center.consider([pair("docker:clam", Severity.ERROR, ("detection",))], names)
    assert notes == [
        Notification("clamav: Title", "Plain.", "docker:clam", "detection", "critical")
    ]
    assert center.consider([pair("docker:clam", Severity.ERROR, ("detection",))], names) == []
    assert center.consider([pair("docker:muted", Severity.CRITICAL)], names) == []
    assert center.consider([pair("docker:info", Severity.INFO)], names) == []
    clock[0] = 61
    again = center.consider([pair("docker:clam", Severity.ERROR, ("detection",))], names)
    assert again and "+1 more" in again[0].body
    loops = [pair("docker:flaky", Severity.INFO, ("restart",), t=i * 30) for i in range(3)]
    loop_notes = center.consider(loops, {})
    assert len(loop_notes) == 1 and loop_notes[0].summary == "docker:flaky keeps restarting"
    burst = [pair(f"docker:s{i}", Severity.CRITICAL) for i in range(10)]
    assert len(center.consider(burst, {})) <= 5  # global cap
    assert NotificationCenter([]).consider([pair("a", Severity.CRITICAL)], {}) == []


def test_desktop_notifier_passes_text_as_arguments() -> None:
    calls: list[tuple[str, list[str]]] = []
    notifier = DesktopNotifier(starter=lambda prog, args: calls.append((prog, args)) or True)
    note = Notification("-rf $(evil)", "body", "s", "critical", "critical")
    if notifier.available:
        assert notifier.send(note)
        args = calls[0][1]
        assert args[-3:] == ["--", "-rf $(evil)", "body"]  # never parsed as options
    notifier.program = None
    assert notifier.send(note) is False


# ---------------------------------------------------------------- rule editor


def test_editor_suggest_preview_and_save(tmp_path: Path) -> None:
    source = source_from_id("docker:loglens-demo-flaky-1")
    line = "fatal: lost connection to db:5432 (connection refused) from 10.0.0.5"
    entry = Normalizer()(
        source,
        RawRecord(source.id, line, NOW),
    )
    draft = suggest(entry, source)
    assert draft.rule_id.startswith("user.") and draft.applies_to == {
        "services": ["loglens-demo-flaky-1"]
    }
    assert "(?P<ip>" in draft.regex
    first = preview(draft, entry, source)
    assert "add a counter-example" in " ".join(first.problems)
    draft.counter_example = "worker started, connecting to db:5432"
    draft.template = "The worker lost its database at db port {{ ip }}."
    counter = Normalizer()(
        source,
        RawRecord(source.id, draft.counter_example, NOW),
    )
    result = preview(draft, entry, source, counter)
    assert result.ok, result.problems
    assert result.groups == {"ip": "10.0.0.5"}
    assert result.explanation.plain_text == "The worker lost its database at db port 10.0.0.5."
    path = save(draft, result.explanation, tmp_path)
    reloaded = ExplanationEngine(load_rules([tmp_path]))
    assert reloaded.issues == ()
    assert reloaded.explain(entry, source).rule_id == draft.rule_id
    draft.title = "Second save replaces"
    save(draft, result.explanation, tmp_path)
    assert path.read_text().count("id: user.") == 1


def test_editor_reports_problems() -> None:
    source = source_from_id("systemd:x.service")
    entry = Normalizer()(
        source,
        RawRecord(source.id, "boom 42", NOW),
    )
    base = RuleDraft(
        "user.boom", "Boom", "It went boom.", r"boom \d+", "boom 42", source.id, "fine"
    )
    assert preview(replace(base, regex="(bad"), entry, source).problems[0].startswith("regex")
    assert "does not match" in preview(replace(base, regex="nope"), entry, source).problems[0]
    assert "must start with" in " ".join(
        preview(replace(base, rule_id="x.boom"), entry, source).problems
    )
    bad_tpl = preview(replace(base, template="{{ unknown }}"), entry, source)
    assert any("unknown" in p for p in bad_tpl.problems)
    same = Normalizer()(
        source,
        RawRecord(source.id, "boom 7", NOW),
    )
    assert any("counter-example matches" in p for p in preview(base, entry, source, same).problems)
    unquoted = preview(replace(base, action="run rm {{ message }}"), entry, source)
    assert any("shquote" in p for p in unquoted.problems)
    with pytest.raises(EditorError):
        save(
            replace(base, regex="nope"),
            Explanation("t", "x", Severity.INFO, "info", "user.boom"),
            Path("/nonexistent-dir-for-test"),
        )  # type: ignore[arg-type]
    assert selector_for(source) == {"units": ["x.service"]}
    assert selector_for(source_from_id("file:/var/log/x.log")) == {"paths": ["/var/log/x.log"]}
    assert suggest_regex("size 104857600") == r"size \d+"  # a number, not a hex id
    assert suggest_regex("from 1.2.3.4 to 5.6.7.8 id deadbeef00 n=3") == (
        r"from (?P<ip>\d{1,3}(?:\.\d{1,3}){3}) to (?P<ip2>\d{1,3}(?:\.\d{1,3}){3}) id [0-9a-f]+ n=\d+"
    )


# ---------------------------------------------------------------- export


def _entries() -> list[LogEntry]:
    return [
        LogEntry(
            1, "docker:a", NOW, Severity.ERROR, "=cmd|' /C calc'!A0", "=cmd|' /C calc'!A0", {"k": 1}
        ),
        LogEntry(2, "docker:a", NOW, Severity.INFO, "multi\nline", "multi\nline"),
    ]


def test_exports() -> None:
    out = io.StringIO()
    assert write_entries(_entries(), "csv", out) == 2
    rows = list(csv.reader(io.StringIO(out.getvalue())))
    assert rows[0][0] == "time" and rows[1][3].startswith("'=")  # formula neutralized
    out = io.StringIO()
    write_entries(_entries(), "json", out)
    data = json.loads(out.getvalue())
    assert data[0]["fields"] == {"k": 1} and data[1]["message"] == "multi\nline"
    out = io.StringIO()
    write_entries([], "json", out)
    assert json.loads(out.getvalue()) == []
    out = io.StringIO()
    write_entries(_entries(), "txt", out)
    assert out.getvalue().count("\n") == 3 and "ERROR" in out.getvalue()
    with pytest.raises(ValueError, match="unknown export format"):
        write_entries([], "xml", io.StringIO())


def test_incident_report_markdown(engine: ExplanationEngine) -> None:
    entries = entries_for(SQUID, SQUID_LINES[:2])
    pairs = [(e, engine.explain(e, SQUID)) for e in entries] + [(_entries()[1], None)]
    report = incident_report(pairs, {SQUID.id: "squid"})
    assert report.startswith("# Incident report")
    assert "## " in report and "Blocked HTTPS site: www.facebook.com" in report
    assert "**Next step:**" in report and "No explanation available" in report
    assert "```\n1795076810.563" in report
    assert incident_report([], {}).endswith("No entries selected.\n")


def test_storage_histogram() -> None:
    db = Storage(":memory:")
    db.write_batch(
        [
            LogEntry(0, "a", NOW + timedelta(seconds=s), sev, "m", "m")
            for s, sev in ((0, Severity.ERROR), (10, Severity.ERROR), (70, Severity.INFO))
        ],
        {},
    )
    rows = db.severity_histogram(["a"], NOW, timedelta(minutes=1))
    assert rows == [(NOW, Severity.ERROR, 2), (NOW + timedelta(minutes=1), Severity.INFO, 1)]
    assert db.severity_histogram(["missing"], NOW, timedelta(minutes=1)) == []


def test_restarts_make_a_service_degraded(engine: ExplanationEngine) -> None:
    flaky = LogSource(
        "docker:f",
        SourceKind.DOCKER_CONTAINER,
        "f",
        "g",
        SourceStatus.RUNNING,
        {"container_name": "f"},
    )
    lines = [f"2026-11-19T11:5{i}:01.000+00:00 container start abc (name=f)" for i in range(3)]
    entries = entries_for(flaky, lines)
    explanations = {e.id: engine.explain(e, flaky) for e in entries}
    report = build_report(
        "f",
        [flaky],
        entries,
        explanations,
        [],
        packs=engine.packs,
        now=NOW,
        window=timedelta(hours=1),
        bucket=timedelta(minutes=1),
    )
    assert report.health.state == "degraded"
    assert report.health.reasons == ("it restarted 3 times in this period",)
