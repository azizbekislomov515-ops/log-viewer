"""Dashboard pages: the data model (pure), the navigation shell and each page's wiring."""

from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from PySide6.QtWidgets import QApplication
from pytestqt.qtbot import QtBot

from loglens.config import Settings, load_settings
from loglens.core.models import Category, Explanation, LogEntry, Severity
from loglens.explain.overview import Bucket
from loglens.gui.dashboard.access import command_in
from loglens.gui.dashboard.model import Dashboard, Moment, build_dashboard
from loglens.gui.dashboard.timeline import notable
from loglens.gui.main_window import MainWindow
from loglens.gui.notify import Notification
from loglens.gui.workers import SyncWorker
from loglens.storage import Storage
from tests.test_gui_window import GROUPS, ISSUE, StubBackend

NOW = datetime(2026, 11, 19, 12, 30, tzinfo=UTC)


def at(
    source: str, minutes_ago: float, severity: Severity = Severity.INFO, msg: str = "x"
) -> LogEntry:
    return LogEntry(0, source, NOW - timedelta(minutes=minutes_ago), severity, msg, msg)


def failed_login(entry: LogEntry) -> Explanation | None:
    if "Failed" not in entry.message:
        return None
    return Explanation(
        "Failed SSH login", "...", entry.severity, Category.SECURITY, "sshd.failed", tags=()
    )


@pytest.fixture
def storage() -> Storage:
    store = Storage(":memory:")
    store.write_batch(
        [at("systemd:ssh.service", m, Severity.ERROR, "Failed password") for m in (1, 2, 30)]
        + [at("systemd:ssh.service", m, Severity.WARNING, "Failed password") for m in (5,)]
        + [at("docker:shop-web-1", m) for m in range(0, 120, 2)]  # 60 entries over 2 h
        + [at("docker:shop-web-1", 60 * 26, Severity.ERROR)]  # yesterday's error
        + [at("file:/var/log/nginx/error.log", 3, Severity.NOTICE, "reload")],
        {},
    )
    return store


def test_storage_counts_per_source_and_lists_sources(storage: Storage) -> None:
    rows = storage.source_counts(NOW - timedelta(hours=1))
    per_source: dict[str, int] = {}
    for sid, _kind, _sev, n in rows:
        per_source[sid] = per_source.get(sid, 0) + n
    assert per_source == {
        "systemd:ssh.service": 4,
        "docker:shop-web-1": 31,  # 0, 2, ... 60 minutes ago: the bounds are inclusive
        "file:/var/log/nginx/error.log": 1,
    }
    assert storage.source_ids() == sorted(per_source)


def test_build_dashboard_counts_groups_and_explains(storage: Storage) -> None:
    d = build_dashboard(storage, failed_login, now=NOW)
    assert d.per_minute == pytest.approx(36 / 60)  # 31 docker + 4 ssh + 1 nginx in the last hour
    assert d.per_minute_before == pytest.approx(29 / 60)
    assert d.errors_24h == 3 and d.errors_before == 1
    assert len(d.hourly) == 24 and sum(e for _, _, e in d.hourly) == 3
    assert len(d.daily_errors) == 7 and sum(n for _, n in d.daily_errors) == 4
    assert d.total_24h == 65 and d.busiest[0] == ("docker:shop-web-1", 60)
    (moment,) = d.latest  # only the ssh lines are explained; grouped into one moment
    assert moment.title == "Failed SSH login" and moment.count == 4
    assert moment.severity == Severity.ERROR
    assert moment.when == NOW - timedelta(minutes=1)  # the newest, whatever the arrival order
    assert len(d.timeline) == 96  # 24 h in 15-minute bars


def test_notable_moments_keep_warnings_restarts_and_spikes() -> None:
    quiet = Moment("Reloaded", "s", NOW, Severity.NOTICE, 1)
    restart = Moment("Restarted", "s", NOW - timedelta(minutes=5), Severity.NOTICE, 2, ("restart",))
    failure = Moment("Disk full", "s", NOW - timedelta(minutes=9), Severity.ERROR, 1)
    spike = Bucket(NOW - timedelta(minutes=30), NOW - timedelta(minutes=15), (0, 50, 0, 0), True)
    d = Dashboard(NOW, 0, 0, 0, 0, (), (), {}, (), (quiet, restart, failure), (spike,), "24h")
    rows = notable(d)
    assert [r[2] for r in rows] == [
        "Restarted  (×2)",  # noqa: RUF001
        "Disk full",
        "Error spike: 50 errors in one interval",
    ]


@pytest.mark.parametrize(
    ("hint", "command"),
    [
        (
            "Add yourself to the group (sudo usermod -aG adm $USER), then log out.",
            "sudo usermod -aG adm $USER",
        ),
        (
            "Run sudo setfacl -m u:$USER:r /var/log/x.log && sudo setfacl -m u:$USER:rx /var/log",
            "sudo setfacl -m u:$USER:r /var/log/x.log && sudo setfacl -m u:$USER:rx /var/log",
        ),
        ("Check that the source still exists.", None),
    ],
)
def test_fix_hints_yield_the_command_to_copy(hint: str, command: str | None) -> None:
    assert command_in(hint) == command


# ---------------------------------------------------------------------- the window


@pytest.fixture
def env(qtbot: QtBot, tmp_path: Path, storage: Storage) -> tuple[MainWindow, StubBackend]:
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
    return window, backend


def test_navigation_shows_the_workspace_docks_only_on_sources(env: Any) -> None:
    window, _ = env
    assert window.page == "sources" and window.toolbar.isVisible()
    window.show_page("overview")
    assert window.pages.currentWidget() is window.page_widgets["overview"]
    assert not window.sources_dock.isVisible() and not window.toolbar.isVisible()
    assert window.nav.buttons["overview"].isChecked()
    window.nav.buttons["sources"].click()
    assert window.page == "sources" and window.sources_dock.isVisible()
    assert window.toolbar.isVisible()


def test_opening_logs_from_a_dashboard_page_switches_to_sources(env: Any) -> None:
    window, _ = env
    window.show_page("timeline")
    window.open_source("systemd:ssh.service")
    assert window.page == "sources" and window._tab() is not None


def test_overview_shows_figures_and_explanations_when_visible(env: Any, qtbot: QtBot) -> None:
    window, _ = env
    assert window.dashboard.dashboard is None  # nothing computed while hidden
    window.show_page("overview")
    qtbot.waitUntil(lambda: window.dashboard.dashboard is not None)
    page = window.page_widgets["overview"]
    assert page.healthy.value.text() == "4 / 4" and page.followed.value.text() == "0"
    assert page.latest.rowCount() >= 1
    window.dashboard.set_active(False)


def test_overview_summary_is_redacted(env: Any) -> None:
    window, _ = env
    secret = Moment("Login with password=hunter2", "systemd:ssh.service", NOW, Severity.ERROR, 1)
    window.dashboard.dashboard = Dashboard(
        NOW, 1.0, 0, 1, 0, (), (), {"systemd": 1}, (), (secret,), (), "24h"
    )
    text = window.page_widgets["overview"].summary_text()
    assert "hunter2" not in text and "Login with password=" in text


def test_header_search_opens_followed_sources_with_the_search(env: Any) -> None:
    window, _ = env
    window.open_source("systemd:ssh.service")
    window.show_page("overview")
    window.page_widgets["overview"].header.searched.emit("Failed")
    tab = window._tab()
    assert window.page == "sources" and tab.state.title == "Search: Failed"
    assert tab.state.search.text == "Failed"


def test_access_page_lists_the_issue_with_its_fix(env: Any) -> None:
    window, backend = env
    window.show_page("access")
    page = window.page_widgets["access"]
    assert page.fixes_card.caption.text() == "1 issue"
    page.header.action.click()
    assert backend.refreshes == 1
    window.issues_btn.click()  # the status bar's issue count leads here too
    assert window.page == "access"


def test_alert_toggles_save_conditions_and_history_lists_notes(env: Any, tmp_path: Path) -> None:
    window, _ = env
    window.show_page("alerts")
    page = window.page_widgets["alerts"]
    page.toggles["detection"].click()  # turn it off
    assert "detection" not in window.settings.notify_on
    assert "detection" not in window.insights.center.conditions
    assert "detection" not in load_settings(tmp_path / "config.toml").notify_on
    page.record(Notification("api: Critical entry", "fatal: out of memory", "docker:x", "critical"))
    assert len(page.history) == 1 and page.recent.count() == 1


def test_unmute_from_the_alerts_page(env: Any) -> None:
    window, _ = env
    window.insights.set_muted("systemd:cron.service", True)
    window.show_page("alerts")
    page = window.page_widgets["alerts"]
    assert page.muted_card.caption.text() == "1 muted"
    page._unmute("systemd:cron.service")
    assert window.settings.muted == ()


def test_settings_page_saves_and_keeps_alert_choices(env: Any, tmp_path: Path) -> None:
    window, _ = env
    window.apply_settings(replace(window.settings, notify_on=("critical",)))
    window.show_page("settings")
    page = window.page_widgets["settings"]
    page.retention_days.setValue(3)
    page.theme.setCurrentIndex(1)  # Light
    page.save()
    saved = load_settings(tmp_path / "config.toml")
    assert saved.retention_days == 3 and saved.theme == "light"
    assert saved.notify_on == ("critical",)
    assert window._theme.name == "light"
    QApplication.instance().setStyleSheet("")  # type: ignore[union-attr]


def test_settings_page_refuses_an_invalid_secret_pattern(env: Any, tmp_path: Path) -> None:
    window, _ = env
    window.show_page("settings")
    page = window.page_widgets["settings"]
    page.redact_patterns.setPlainText("(unclosed")
    page.save()
    assert "Not saved" in page.pattern_error.text()
    assert not (tmp_path / "config.toml").exists()


def test_ctrl_comma_opens_the_settings_page(env: Any) -> None:
    window, _ = env
    window.show_settings()
    assert window.page == "settings"
