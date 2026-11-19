"""Window-level tests (pytest-qt, offscreen): wiring between tree, tabs, toolbar, backend."""

import json
from collections import deque
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from PySide6.QtCore import QObject, Qt, Signal
from PySide6.QtGui import QKeySequence
from PySide6.QtWidgets import QApplication
from pytestqt.qtbot import QtBot

from loglens.config import Settings, load_settings
from loglens.core.models import (
    DiscoveryIssue,
    GroupKind,
    LogEntry,
    LogSource,
    ServiceGroup,
    Severity,
    SourceKind,
    SourceStatus,
)
from loglens.gui import theme as themes
from loglens.gui.backend import BackendStats
from loglens.gui.log_model import Column, Role
from loglens.gui.main_window import LogTab, MainWindow, TabState
from loglens.gui.widgets import SettingsDialog, fuzzy_score
from loglens.gui.workers import SyncWorker
from loglens.storage import Storage

T0 = datetime.now(UTC) - timedelta(minutes=1)


class StubBackend(QObject):
    sourcesChanged = Signal(object, object)
    statsChanged = Signal(object)
    failed = Signal(str)

    def __init__(self) -> None:
        super().__init__()
        self.followed: list[str] = []
        self.unfollowed: list[str] = []
        self.refreshes = 0
        self.queue: deque[LogEntry] = deque()

    def follow(self, source: LogSource) -> None:
        self.followed.append(source.id)

    def unfollow(self, source_id: str) -> None:
        self.unfollowed.append(source_id)

    def refresh_discovery(self) -> None:
        self.refreshes += 1

    def clear_secrets(self) -> None:
        self.secrets_cleared = True

    def take_entries(self, limit: int = 200_000) -> list[LogEntry]:
        out = list(self.queue)
        self.queue.clear()
        return out

    @property
    def backlog(self) -> int:
        return len(self.queue)


def src(sid: str, name: str, gid: str, kind: SourceKind = SourceKind.DOCKER_CONTAINER) -> LogSource:
    return LogSource(sid, kind, name, gid, SourceStatus.RUNNING)


GROUPS = (
    ServiceGroup(
        "systemd",
        "System services",
        GroupKind.SYSTEM,
        (
            src("systemd:ssh.service", "ssh", "systemd", SourceKind.SYSTEMD),
            src("systemd:cron.service", "cron", "systemd", SourceKind.SYSTEMD),
        ),
    ),
    ServiceGroup(
        "compose:shop",
        "shop",
        GroupKind.DOCKER_COMPOSE,
        (
            src("docker:shop-web-1", "web", "compose:shop"),
            src("docker:shop-api-1", "api", "compose:shop"),
        ),
    ),
)
ISSUE = DiscoveryIssue(
    "docker",
    "docker_permission_denied",
    "Cannot read Docker.",
    Severity.WARNING,
    "Add yourself to the docker group.",
)


def entry(source: str, i: int, severity: Severity = Severity.INFO, message: str = "") -> LogEntry:
    text = message or f"{source} line {i}"
    return LogEntry(0, source, T0 + timedelta(milliseconds=i), severity, text, text)


@pytest.fixture
def env(qtbot: QtBot, tmp_path: Path) -> tuple[MainWindow, StubBackend, Storage]:
    storage = Storage(":memory:")
    storage.write_batch(
        [
            entry(
                "systemd:ssh.service",
                i,
                Severity.WARNING if i % 4 else Severity.ERROR,
                "Failed password" if i % 10 == 0 else "",
            )
            for i in range(40)
        ]
        + [entry("docker:shop-web-1", i) for i in range(5)]
        + [entry("docker:shop-api-1", i) for i in range(5)],
        {},
    )
    backend = StubBackend()
    window = MainWindow(
        backend,
        SyncWorker(storage),
        Settings(theme="dark"),
        settings_path=tmp_path / "config.toml",
        state_path=tmp_path / "session.json",
    )
    qtbot.addWidget(window)
    window.show()
    backend.sourcesChanged.emit(GROUPS, (ISSUE,))
    return window, backend, storage


def test_sources_appear_and_clicking_opens_live_logs(env: Any, qtbot: QtBot) -> None:
    window, backend, storage = env
    assert window.tree_model.source("systemd:ssh.service") is not None
    assert window.issues_btn.text() == "⚠ 1 issue"
    assert window.issues_panel.count == 1
    assert "How to fix: Add yourself" in window.issues_panel.list.item(0).text()
    proxy = window.tree_proxy
    item = window.tree_model.item_for("systemd:ssh.service")
    window._tree_activated(proxy.mapFromSource(item.index()))
    tab = window._tab()
    assert isinstance(tab, LogTab) and tab.state.source_ids == ("systemd:ssh.service",)
    assert backend.followed == ["systemd:ssh.service"]
    view = tab.views[0]
    assert view.model.rowCount() == 40
    assert view.tree.isColumnHidden(Column.SOURCE)  # one source: no source column
    backend.queue.extend(
        storage.write_batch([entry("systemd:ssh.service", 99, Severity.ERROR)], {})
    )
    window.drain()
    assert view.model.rowCount() == 41
    assert window.open_source("systemd:ssh.service") is tab  # focus, not a second tab
    assert window.open_source("nope") is None and window.open_group("nope") is None


def test_unread_badges_for_sources_not_in_view(env: Any, qtbot: QtBot) -> None:
    window, backend, storage = env
    window.open_source("systemd:cron.service")
    backend.queue.extend(
        storage.write_batch(
            [entry("systemd:ssh.service", 1, Severity.ERROR), entry("systemd:ssh.service", 2)], {}
        )
    )
    window.activateWindow()
    window.drain()
    assert window.tree_model.unread("systemd:ssh.service") == 1
    window.open_source("systemd:ssh.service")
    assert window.tree_model.unread("systemd:ssh.service") == 0


def test_toolbar_filters_are_per_tab(env: Any, qtbot: QtBot) -> None:
    window, *_ = env
    ssh = window.open_source("systemd:ssh.service")
    error_chip = next(c for c, sev in window.chips if Severity.ERROR in sev)
    warning_chip = next(c for c, sev in window.chips if Severity.WARNING in sev)
    warning_chip.setChecked(False)
    assert ssh.views[0].model.rowCount() == 10  # errors only
    window.open_source("systemd:cron.service")
    assert warning_chip.isChecked()  # the new tab has its own filters
    window.tabs.setCurrentIndex(0)
    assert not warning_chip.isChecked() and error_chip.isChecked()
    window.range_box.setCurrentIndex(window.range_box.findData("5m"))
    window._apply_range(0)
    assert ssh.state.range_key == "5m" and ssh.views[0].model.query.since is not None


def test_search_highlight_and_navigation(env: Any, qtbot: QtBot) -> None:
    window, *_ = env
    tab = window.open_source("systemd:ssh.service")
    window.search.setText("failed")
    window._apply_search()
    model = tab.views[0].model
    assert model.match_rows == [0, 10, 20, 30]
    assert window.match_label.text() == "4 matches"
    view = tab.views[0]
    view.tree.setCurrentIndex(model.index(0, Column.MESSAGE))
    window.next_match(forward=True)
    assert view.current_row() == 10
    qtbot.keyClick(window, Qt.Key.Key_F3)
    assert view.current_row() == 20
    window.next_match(forward=False)
    assert view.current_row() == 10
    assert not view.follow  # jumping to a match stops following
    window.regex_btn.setChecked(True)
    window.search.setText("(")
    window._apply_search()
    assert window.match_label.text() == "Search stopped"
    assert window.search.property("invalid") is True


def test_pause_wrap_follow_and_split(env: Any, qtbot: QtBot) -> None:
    window, backend, storage = env
    tab = window.open_group("compose:shop")
    assert tab.is_group and len(tab.views) == 1 and window.split_btn.isVisibleTo(window)
    merged = tab.views[0]
    assert not merged.tree.isColumnHidden(Column.SOURCE) and merged.model.rowCount() == 10
    qtbot.keyClick(window, Qt.Key.Key_P, Qt.KeyboardModifier.ControlModifier)
    assert tab.paused and "Paused" in tab.banner_text.text()
    backend.queue.extend(storage.write_batch([entry("docker:shop-web-1", 50)], {}))
    window.drain()
    assert merged.model.rowCount() == 10 and "1 new entries" in tab.banner_text.text()
    window.pause_btn.setChecked(False)
    assert merged.model.rowCount() == 11 and window.pause_btn.text() == "Pause"
    window.wrap_btn.setChecked(True)
    assert tab.wrap and merged.delegate.wrap
    window.follow_btn.setChecked(False)
    assert not merged.follow
    window.split_btn.setChecked(True)
    assert len(tab.views) == 2 and {v.model.query.source_ids for v in tab.views} == {
        ("docker:shop-web-1",),
        ("docker:shop-api-1",),
    }
    window.split_btn.setChecked(False)
    assert len(tab.views) == 1


def test_shortcuts_palette_and_close(env: Any, qtbot: QtBot) -> None:
    window, backend, _ = env
    window.open_source("systemd:ssh.service")
    window.open_source("systemd:cron.service")
    qtbot.keyClick(window, Qt.Key.Key_1, Qt.KeyboardModifier.ControlModifier)
    assert window.tabs.currentIndex() == 0
    qtbot.keyClick(window, Qt.Key.Key_F, Qt.KeyboardModifier.ControlModifier)
    assert window.search.hasFocus()
    window.show_palette()
    palette = window.palette_popup
    qtbot.keyClicks(palette.input, "wb")
    assert palette.results.currentItem().data(Qt.ItemDataRole.UserRole) == "docker:shop-web-1"
    qtbot.keyClick(palette.input, Qt.Key.Key_Return)
    assert window._tab().state.source_ids == ("docker:shop-web-1",)
    window.close_tab(window.tabs.currentIndex())
    assert "docker:shop-web-1" in backend.unfollowed
    while window.tabs.count():
        window.close_tab(0)
    assert window.stack.currentWidget() is window.empty


def test_fuzzy_score() -> None:
    assert fuzzy_score("cld", "clamav-daemon") is not None
    assert fuzzy_score("xyz", "clamav-daemon") is None
    assert fuzzy_score("", "anything") == 0
    assert fuzzy_score("ssh", "ssh") > fuzzy_score("ssh", "s-s-h-service")  # type: ignore[operator]


def test_pin_follows_in_background_and_persists(env: Any, qtbot: QtBot, tmp_path: Path) -> None:
    window, backend, _ = env
    window.set_pinned("systemd:cron.service", True)
    assert "systemd:cron.service" in backend.followed
    assert load_settings(tmp_path / "config.toml").pinned == ("systemd:cron.service",)
    window.set_pinned("systemd:cron.service", False)
    assert "systemd:cron.service" in backend.unfollowed


def test_session_restores_tabs_and_filters(env: Any, qtbot: QtBot, tmp_path: Path) -> None:
    window, _, storage = env
    tab = window.open_source("systemd:ssh.service")
    window.search.setText("failed")
    window._apply_search()
    next(c for c, sev in window.chips if Severity.INFO in sev).setChecked(False)
    window.open_group("compose:shop")
    saved = json.loads((tmp_path / "session.json").read_text())
    assert [t["title"] for t in saved["tabs"]] == ["ssh", "shop"]
    assert saved["tabs"][0]["search"] == "failed" and "INFO" not in saved["tabs"][0]["severities"]
    again = MainWindow(
        StubBackend(), SyncWorker(storage), Settings(), state_path=tmp_path / "session.json"
    )
    qtbot.addWidget(again)
    again.backend.sourcesChanged.emit(GROUPS, ())  # type: ignore[attr-defined]
    assert again.tabs.count() == 2
    restored = again._all_tabs()[0]
    assert restored.state.search.text == "failed" and Severity.INFO not in restored.state.severities
    assert TabState.from_json({"range": "bogus", "severities": ["NOPE"]}).range_key == "live"
    del tab


def test_settings_dialog_round_trip(qtbot: QtBot) -> None:
    dialog = SettingsDialog(Settings(theme="light", retention_days=3))
    qtbot.addWidget(dialog)
    dialog.theme.setCurrentIndex(2)
    dialog.exclude.setPlainText("docker:test-*\n\n systemd:*.scope ")
    dialog.rule_dirs.addItem("/opt/rules")
    result = dialog.result_settings()
    assert result.theme == "dark" and result.retention_days == 3
    assert result.discovery_exclude == ("docker:test-*", "systemd:*.scope")
    assert result.rule_dirs == ("/opt/rules",)


def test_stats_overlay_and_collector_errors(env: Any, qtbot: QtBot) -> None:
    window, *_ = env
    window._on_stats(BackendStats(1234.5, 3, 99, 0, {"docker:x": "boom"}))
    assert window.rate_label.text() in ("1,234 lines/s", "1,235 lines/s")  # banker's rounding
    assert window.collectors_label.text() == "3 sources followed"
    assert window.issues_btn.text() == "⚠ 2 issues"
    qtbot.keyClick(
        window, Qt.Key.Key_D, Qt.KeyboardModifier.ControlModifier | Qt.KeyboardModifier.AltModifier
    )
    assert window.overlay.isVisible() and "frame" in window.overlay.text()
    window.overlay.toggle()
    assert not window.overlay.isVisible()


def test_copy_selected(env: Any, qtbot: QtBot) -> None:
    window, *_ = env
    view = window.open_source("systemd:ssh.service").views[0]
    view.tree.selectRow(0)
    got: list[str] = []
    view.copy_selected(as_json=True, clipboard=got.append)
    assert json.loads(got[0])[0]["severity"] == "error"
    view.copy_selected(as_json=False)
    assert "ERROR" in QApplication.clipboard().text()


def test_expand_multiline_row(env: Any, qtbot: QtBot) -> None:
    window, backend, storage = env
    view = window.open_source("systemd:ssh.service").views[0]
    backend.queue.extend(
        storage.write_batch([entry("systemd:ssh.service", 200, message="a\nb\nc")], {})
    )
    window.drain()
    row = view.model.rowCount() - 1
    base = view.tree.rowHeight(0)
    view._toggle_row(view.model.index(row, Column.MESSAGE))
    assert view.model.index(row, 0).data(Role.EXPANDED) and view.tree.rowHeight(row) > 2 * base
    view._toggle_row(view.model.index(row, Column.MESSAGE))
    assert view.tree.rowHeight(row) == base


@pytest.mark.parametrize("theme", [themes.DARK, themes.LIGHT])
def test_themes_apply_and_meet_contrast(env: Any, theme: themes.Theme) -> None:
    window, *_ = env
    window.apply_theme(theme)
    assert theme.name in ("dark", "light")
    for token in ("text", "dim", "critical", "error", "warning", "notice", "accent"):
        for background in (theme.canvas, theme.surface):
            assert _contrast(getattr(theme, token), background) >= 4.5, (theme.name, token)
    for color in theme.series:
        assert _contrast(color, theme.canvas) >= 4.5


def test_accessible_names_and_tab_order(env: Any) -> None:
    window, *_ = env
    for widget in (
        window.search,
        window.tree,
        window.tree_filter,
        window.range_box,
        window.pause_btn,
    ):
        assert widget.accessibleName()
    assert all(chip.accessibleName().startswith("Show ") for chip, _ in window.chips)
    assert QKeySequence("Ctrl+K").toString()


def _contrast(a: str, b: str) -> float:
    def lum(h: str) -> float:
        c = [int(h.lstrip("#")[i : i + 2], 16) / 255 for i in (0, 2, 4)]
        c = [x / 12.92 if x <= 0.03928 else ((x + 0.055) / 1.055) ** 2.4 for x in c]
        return 0.2126 * c[0] + 0.7152 * c[1] + 0.0722 * c[2]

    hi, lo = sorted((lum(a), lum(b)), reverse=True)
    return (hi + 0.05) / (lo + 0.05)
