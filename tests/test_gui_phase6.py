# ruff: noqa: E501  (real log lines from the demo stack are long)
"""Phase 6 GUI wiring (pytest-qt, offscreen): Explain panel, inline explanations, Overview
and Compose dashboard models/pages, notifications, rule editor, export, incident report."""

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from PySide6.QtCore import QObject, Signal
from PySide6.QtWidgets import QApplication
from pytestqt.qtbot import QtBot

from loglens.config import Settings
from loglens.core.models import (
    GroupKind,
    LogEntry,
    LogSource,
    RawRecord,
    ServiceGroup,
    Severity,
    SourceKind,
    SourceStatus,
)
from loglens.gui import analyst as analyst_mod
from loglens.gui.analyst import (
    Analyst,
    LiveExplainer,
    OverviewModel,
    make_engine,
    parse_depends_on,
)
from loglens.gui.dialogs import ExportDialog, RuleEditorDialog
from loglens.gui.insight_widgets import ComposeDashboard, OverviewPage
from loglens.gui.log_model import Column, LogTableModel, Role
from loglens.gui.main_window import LogTab, MainWindow
from loglens.gui.notify import DesktopNotifier, NotificationCenter
from loglens.gui.widgets import SettingsDialog
from loglens.gui.workers import SyncWorker
from loglens.parsers import Normalizer
from loglens.storage import EntryQuery, Storage

NOW = datetime.now(UTC)


def src(sid: str, name: str, gid: str, **meta: str) -> LogSource:
    return LogSource(
        sid,
        SourceKind.DOCKER_CONTAINER,
        name,
        gid,
        SourceStatus.RUNNING,
        {"container_name": sid.partition(":")[2], **meta},
    )


SQUID = src(
    "docker:loglens-demo-squid-1",
    "squid",
    "compose:loglens-demo",
    image="loglens-demo/squid",
    compose_service="squid",
    compose_depends_on="web:service_healthy:false",
)
WEB = src(
    "docker:loglens-demo-web-1",
    "web",
    "compose:loglens-demo",
    image="loglens-demo/nginx",
    compose_service="web",
)
FLAKY = src("docker:loglens-demo-flaky-1", "flaky", "compose:loglens-demo", compose_service="flaky")
GROUPS = (
    ServiceGroup(
        "compose:loglens-demo", "loglens-demo", GroupKind.DOCKER_COMPOSE, (SQUID, WEB, FLAKY)
    ),
)
LINES = [
    (
        SQUID,
        [
            "1795076810.563      0 172.18.0.6 TCP_DENIED/403 3431 CONNECT www.facebook.com:443 - HIER_NONE/- text/html",
            "1795076811.470      0 172.18.0.5 TCP_MEM_HIT/200 353 GET http://web/ - HIER_NONE/- text/html",
            "squid: something no rule knows",
        ],
    ),
    (
        FLAKY,
        [
            "2026-11-19T11:50:00.000+00:00 container die abc (exitCode=1, image=alpine, name=loglens-demo-flaky-1)",
            "2026-11-19T11:50:01.000+00:00 container start abc (image=alpine, name=loglens-demo-flaky-1)",
        ],
    ),
]


def stored(storage: Storage) -> list[LogEntry]:
    normalize = Normalizer()
    entries = []
    for source, lines in LINES:
        for i, line in enumerate(lines):
            fields = {"stream": "events"} if " container " in line else {}
            record = RawRecord(source.id, line, NOW - timedelta(seconds=30 - i), fields=fields)
            entries.append(normalize(source, record))
    return storage.write_batch(entries, {})


class StubBackend(QObject):
    sourcesChanged = Signal(object, object)
    statsChanged = Signal(object)
    failed = Signal(str)

    def __init__(self) -> None:
        super().__init__()
        self.queue: list[LogEntry] = []

    def follow(self, source: LogSource) -> None: ...
    def unfollow(self, source_id: str) -> None: ...
    def refresh_discovery(self) -> None: ...

    def take_entries(self, limit: int = 0) -> list[LogEntry]:
        out, self.queue = self.queue, []
        return out

    @property
    def backlog(self) -> int:
        return 0


@pytest.fixture
def env(
    qtbot: QtBot, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> tuple[MainWindow, StubBackend, Storage]:
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    storage = Storage(":memory:")
    stored(storage)
    backend = StubBackend()
    window = MainWindow(
        backend,
        SyncWorker(storage),
        Settings(theme="dark", notify_on=()),
        settings_path=tmp_path / "config.toml",
    )
    qtbot.addWidget(window)
    window.show()
    backend.sourcesChanged.emit(GROUPS, ())
    return window, backend, storage


def test_explain_panel_shows_explanation_fields_and_honest_no_match(
    env: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    window, *_ = env
    opened: list[RuleEditorDialog] = []
    monkeypatch.setattr(RuleEditorDialog, "exec", lambda self: opened.append(self) or 0)
    tab = window.open_source(SQUID.id)
    view = tab.views[0]
    panel = window.insights.explain_panel
    view.tree.setCurrentIndex(view.model.index(0, Column.MESSAGE))
    assert panel.title.text() == "Blocked HTTPS site: www.facebook.com"
    assert "172.18.0.6" in panel.text.text() and panel.category_chip.text() == "Security"
    assert panel.action.isVisibleTo(panel) and "grep -nF www.facebook.com" in panel.action.text()
    fields = {
        panel.fields.item(r, 0).text(): panel.fields.item(r, 1).text()
        for r in range(panel.fields.rowCount())
    }
    assert fields["domain"] == "www.facebook.com" and fields["client_ip"] == "172.18.0.6"
    assert panel.raw.toPlainText().startswith("1795076810.563")
    view.tree.setCurrentIndex(view.model.index(2, Column.MESSAGE))
    assert panel.no_rule.isVisibleTo(panel) and panel.create_btn.isVisibleTo(panel)
    assert not panel.title.isVisibleTo(panel)
    seen: list[LogEntry] = []
    panel.createRule.connect(seen.append)
    panel.create_btn.click()
    assert seen and seen[0].message == "squid: something no rule knows"
    assert opened and opened[0].regex.text().startswith("squid: something")  # editor opened


def test_inline_explanations_modes(env: Any) -> None:
    window, *_ = env
    view = window.open_source(SQUID.id).views[0]
    assert view.model.index(0, Column.MESSAGE).data(Role.EXPLANATION) is None  # off
    window.insights.set_inline_mode("full")
    exp = view.model.index(0, Column.MESSAGE).data(Role.EXPLANATION)
    assert exp is not None and exp.rule_id == "squid.access.denied_connect"
    assert view.delegate.inline == "full" and view.delegate.variable_rows
    assert view.tree.rowHeight(0) > view.tree.rowHeight(2)  # explained row: two lines
    assert window.inline_btn.isChecked()
    window.insights.set_inline_mode("compact")
    assert view.tree.rowHeight(0) == view.tree.rowHeight(2)
    window.inline_btn.setChecked(False)
    assert window.settings.inline_explanations == "off"


def test_overview_page_from_rule_pack_cards(env: Any, qtbot: QtBot) -> None:
    window, *_ = env
    page = window.insights.open_overview([SQUID.id])
    assert isinstance(page, OverviewPage)
    report = page.model.report
    assert report is not None and report.packs[0] == "squid"
    titles = [c.title for c in report.cards]
    assert "Blocked sites" in titles and "Exit codes" in titles  # squid, then docker lifecycle
    assert page.summary.text().startswith("squid:")
    assert page.cards.count() == len(report.cards)
    assert window.tabs.tabText(window.tabs.currentIndex()) == "Overview: squid"
    assert window.insights.open_overview([SQUID.id]) is page  # focus, not a second page
    tabs_before = window.tabs.count()
    bucket = report.timeline[-1]
    page.chart.intervalClicked.emit(bucket.start, bucket.end)
    opened = window._tab()
    assert isinstance(opened, LogTab) and opened.state.range_key == "custom"
    assert opened.state.since == bucket.start and window.tabs.count() == tabs_before + 1
    window.close_tab(window.tabs.indexOf(page))
    assert page not in window.insights._pages
    assert window.insights.open_overview(["nope"]) is None


def test_overview_model_refreshes_only_when_dirty(qapp: Any) -> None:
    storage = Storage(":memory:")
    stored(storage)
    analyst = Analyst(lambda: make_engine(Settings()))
    model = OverviewModel(SyncWorker(storage), analyst, "flaky", [FLAKY])
    model.refresh()
    assert model.refreshes == 1 and model.report is not None
    cards = {c.title: c for c in model.report.cards}
    assert cards["Exit codes"].rows == (("1", "1"),) and model.report.health.restarts == 1
    model._tick()
    assert model.refreshes == 1
    model.mark_dirty()
    model._tick()
    assert model.refreshes == 2
    model.set_window("15m")
    assert len(model.report.timeline) == 30
    model.set_sources([FLAKY])
    model.stop()
    analyst.reload()
    assert analyst.engine is not None


def test_compose_dashboard(env: Any) -> None:
    window, *_ = env
    page = window.insights.open_dashboard("compose:loglens-demo")
    assert isinstance(page, ComposeDashboard)
    by_name = {s.source.display_name: s for s in page.model.services}
    assert by_name["flaky"].restarts == 1
    assert by_name["squid"].depends_on == (("web", "service_healthy"),)
    assert by_name["squid"].hints == ("starts after web is healthy",)
    assert page.grid.count() == 3 and "3 services" in page.counts.text()
    opened: list[str] = []
    page.openLogs.connect(opened.append)
    page.grid.itemAt(0).widget().openLogs.emit(SQUID.id)
    assert opened == [SQUID.id]
    assert window.insights.open_dashboard("compose:loglens-demo") is page
    assert window.insights.open_dashboard("nope") is None
    assert parse_depends_on("db:service_healthy:false,cache") == (
        ("db", "service_healthy"),
        ("cache", "service_started"),
    )


def test_live_explainer_notifies(qapp: Any, qtbot: QtBot) -> None:
    storage = Storage(":memory:")
    sent: list[Any] = []
    notifier = DesktopNotifier(starter=lambda prog, args: sent.append(args) or True)
    notifier.program = "/usr/bin/notify-send"
    explainer = LiveExplainer(
        SyncWorker(storage),
        Analyst(lambda: make_engine(Settings())),
        NotificationCenter(["detection"]),
        notifier,
        sources=lambda: {},
    )
    clam = LogSource(
        "docker:clam",
        SourceKind.DOCKER_CONTAINER,
        "clam",
        "g",
        SourceStatus.RUNNING,
        {"container_name": "clam", "image": "loglens-demo/clamav"},
    )
    line = "Thu Nov 19 08:26:10 2026 -> instream(172.18.0.7@1): Win.Trojan.Agent-1 FOUND"
    entry = storage.write_batch([Normalizer()(clam, RawRecord(clam.id, line, NOW))], {})
    notes: list[Any] = []
    explainer.notified.connect(notes.append)
    explainer.feed(entry)
    assert (
        notes
        and notes[0].condition == "detection"
        and "Malware sent by 172.18.0.7" in notes[0].summary
    )
    assert sent and sent[0][-3] == "--"
    notifier.program = None
    warned: list[str] = []
    explainer.unavailable.connect(warned.append)
    explainer.center.conditions = {"critical"}
    explainer.feed([LogEntry(99, "x", NOW, Severity.CRITICAL, "boom", "boom")])
    assert warned and "notify-send" in warned[0]
    explainer.center.conditions = set()
    explainer.feed([LogEntry(100, "x", NOW, Severity.CRITICAL, "boom", "boom")])  # ignored
    assert explainer.send_test().summary == "LogLens"


def test_live_explainer_budget(qapp: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(analyst_mod, "LIVE_BUDGET", 2)
    explainer = LiveExplainer(
        SyncWorker(Storage(":memory:")),
        Analyst(lambda: make_engine(Settings())),
        NotificationCenter(["critical"]),
        DesktopNotifier(lambda *_: True),
        sources=lambda: {},
    )
    explainer.feed([LogEntry(i, "x", NOW, Severity.INFO, "m", "m") for i in range(1, 6)])
    assert explainer.skipped == 3


def test_rule_editor_dialog_saves_to_user_pack(env: Any, qtbot: QtBot, tmp_path: Path) -> None:
    window, *_ = env
    tab = window.open_source(SQUID.id)
    entry = tab.views[0].model.entry_at(2)
    dialog = RuleEditorDialog(
        entry,
        SQUID,
        "1795076811.470 0 1.2.3.4 TCP_MEM_HIT/200 1 GET http://x/ - HIER_NONE/- -",
        directory=tmp_path / "rules",
    )
    qtbot.addWidget(dialog)
    assert dialog.regex.text().startswith("squid: something")
    dialog.template.setPlainText("Squid printed a message LogLens does not know yet.")
    dialog.refresh()
    assert dialog.outcome is not None and dialog.outcome.ok, dialog.outcome.problems
    assert "Ready to save" in dialog.problems.text()
    saved: list[Path] = []
    dialog.saved.connect(saved.append)
    dialog._save()
    assert saved and saved[0].exists() and "user.squid_something_no_rule" in saved[0].read_text()
    dialog2 = RuleEditorDialog(entry, SQUID, "", directory=tmp_path / "rules")
    qtbot.addWidget(dialog2)
    dialog2.refresh()
    assert not dialog2.outcome.ok and "counter-example" in dialog2.problems.text()
    window.insights._rules_changed(saved[0])
    assert window.statusBar().currentMessage().startswith("Rule saved")


def test_export_and_incident_report(env: Any, qtbot: QtBot, tmp_path: Path) -> None:
    window, *_ = env
    view = window.open_source(SQUID.id).views[0]
    target = tmp_path / "out.json"
    window.insights.export_to(view, target, fmt="json", scope="view")
    assert len(json.loads(target.read_text())) == 3
    view.tree.selectRow(0)
    window.insights.export_to(view, tmp_path / "sel.csv", fmt="csv", scope="selected")
    assert (tmp_path / "sel.csv").read_text().count("\n") == 2
    window.insights.export_to(
        view,
        tmp_path / "r.txt",
        fmt="txt",
        scope="range",
        since=NOW - timedelta(hours=1),
        until=NOW,
    )
    assert (tmp_path / "r.txt").read_text().count("\n") == 3
    window.insights.copy_incident_report()
    text = QApplication.clipboard().text()
    assert text.startswith("# Incident: squid") and "Blocked HTTPS site" in text
    dialog = ExportDialog(3, 1)
    qtbot.addWidget(dialog)
    fmt, scope, since, until = dialog.choice()
    assert fmt == "txt" and scope == "selected" and since < until
    actions = [a.text() for a in window.insights._log_view_actions(view)]
    assert "Copy incident report (Markdown)" in actions and "Export…" in actions


def test_mute_and_settings(env: Any, qtbot: QtBot) -> None:
    window, *_ = env
    window.insights.set_muted(SQUID.id, True)
    assert SQUID.id in window.settings.muted and SQUID.id in window.insights.center.muted
    window.insights.set_muted(SQUID.id, False)
    assert SQUID.id not in window.insights.center.muted
    dialog = SettingsDialog(Settings(notify_on=("critical",), muted=("docker:x",)))
    qtbot.addWidget(dialog)
    dialog.notify["detection"].setChecked(True)
    dialog.inline.setCurrentIndex(1)
    result = dialog.result_settings()
    assert result.notify_on == ("critical", "detection") and result.inline_explanations == "compact"
    assert result.muted == ("docker:x",)


def test_inline_model_cache(qapp: Any) -> None:
    storage = Storage(":memory:")
    stored(storage)
    calls: list[int] = []

    def explain(entry: LogEntry) -> None:
        calls.append(entry.id)

    model = LogTableModel(SyncWorker(storage), EntryQuery((SQUID.id,)))
    model.reload()
    model.set_explainer(explain, "full")
    model.index(0, Column.MESSAGE).data(Role.EXPLANATION)
    model.index(0, Column.MESSAGE).data(Role.EXPLANATION)
    assert calls == [1]  # cached
    model.set_explainer(None, "off")
    assert model.index(0, Column.MESSAGE).data(Role.EXPLANATION) is None
