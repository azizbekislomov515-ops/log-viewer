"""First-run onboarding: access summary, choices -> settings, and the wizard in the window."""

from __future__ import annotations

from pathlib import Path

from PySide6.QtWidgets import QLabel
from pytestqt.qtbot import QtBot

from loglens.config import Settings, load_settings
from loglens.core.models import DiscoveryIssue, GroupKind, ServiceGroup, Severity
from loglens.gui.main_window import MainWindow
from loglens.gui.onboarding import (
    MAX_FOLLOW_GROUP,
    access_summary,
    apply_choices,
    demo_app_command,
    followable,
)
from tests import test_gui_window
from tests.test_gui_window import GROUPS, ISSUE, StubBackend, src

env = test_gui_window.env  # the window fixture

JOURNAL = DiscoveryIssue("systemd", "journal_access_limited", "Only your journal.",
                         Severity.WARNING, "sudo usermod -aG systemd-journal $USER")  # fmt: skip


def test_access_summary_per_category() -> None:
    rows = {a.category: a for a in access_summary(GROUPS, (ISSUE, JOURNAL))}
    assert rows["system"].sources == 2 and rows["system"].state == "limited"
    assert rows["docker"].sources == 2 and rows["docker"].issues == (ISSUE,)
    assert rows["files"].sources == 0 and rows["files"].state == "ok"  # nothing, no problem
    nothing = access_summary((), (ISSUE,))
    assert next(a for a in nothing if a.category == "docker").state == "unavailable"


def test_choices_become_excludes_and_pins() -> None:
    settings = Settings(discovery_exclude=("systemd:*.scope", "docker:*"), pinned=("x",))
    out = apply_choices(settings, {"system": True, "docker": True, "files": False}, [GROUPS[1]])
    assert out.onboarded
    assert out.discovery_exclude == ("systemd:*.scope", "file:*")  # docker shown again
    assert set(out.pinned) == {"x", "docker:shop-web-1", "docker:shop-api-1"}


def test_only_small_compose_and_file_groups_are_offered_for_following() -> None:
    many = tuple(src(f"file:/l/{i}", str(i), "files:big") for i in range(MAX_FOLLOW_GROUP + 1))
    big = ServiceGroup("files:big", "Big", GroupKind.FILES, many)
    assert followable((*GROUPS, big)) == [GROUPS[1]]  # not systemd, not the huge group


def test_demo_command_is_an_argv_list() -> None:
    command = demo_app_command()
    assert command[-1].endswith("--demo") or "--demo" in command[-1]


def test_wizard_in_window_applies_and_saves_choices(
    env: tuple[MainWindow, StubBackend, object],
    qtbot: QtBot,
    tmp_path: Path,
) -> None:
    window, backend, _ = env
    window._settings_path = tmp_path / "config.toml"
    backend.sourcesChanged.emit(GROUPS, (ISSUE,))
    wizard = window.show_onboarding()
    qtbot.waitUntil(wizard.isVisible)
    labels = [label.text() for label in wizard.access.findChildren(QLabel)]
    assert any("Add yourself to the docker group." in t for t in labels)
    wizard.choose.shown["system"].setChecked(False)
    assert wizard.choose.follow["compose:shop"][0].isChecked()  # Compose followed by default
    wizard.accept()
    qtbot.waitUntil(lambda: window.settings.onboarded)
    assert "systemd:*" in window.settings.discovery_exclude
    assert "docker:shop-web-1" in window.settings.pinned
    assert window.tree_model.source("systemd:ssh.service") is None  # hidden right away
    assert load_settings(tmp_path / "config.toml").onboarded  # saved


def test_dismissing_the_wizard_still_marks_onboarded(
    env: tuple[MainWindow, StubBackend, object],
    qtbot: QtBot,
    tmp_path: Path,
) -> None:
    window, _, _ = env
    window._settings_path = tmp_path / "config.toml"
    wizard = window.show_onboarding()
    wizard.reject()
    qtbot.waitUntil(lambda: window.settings.onboarded)
    assert window.settings.pinned == ()


def test_reveal_action_copies_the_original_line_locally(
    env: tuple[MainWindow, StubBackend, object],
    qtbot: QtBot,
    tmp_path: Path,
    monkeypatch: object,
) -> None:
    from dataclasses import replace  # noqa: PLC0415

    from PySide6.QtGui import QGuiApplication  # noqa: PLC0415

    from loglens.gui import insights_ui  # noqa: PLC0415
    from loglens.security.redact import Redactor, SecretVault  # noqa: PLC0415
    from tests.test_gui_window import entry  # noqa: PLC0415

    window, _, _ = env
    monkeypatch.setattr(insights_ui, "data_dir", lambda: tmp_path)  # type: ignore[attr-defined]
    redacted = Redactor(vault=SecretVault(tmp_path / "vault")).redact_entry(
        entry("systemd:ssh.service", 1, message="login password=Hunter2x ok")
    )
    assert "Hunter2x" not in redacted.raw
    window.settings = replace(window.settings, redact_reversible=True)
    window.insights.copy_revealed(redacted)
    assert QGuiApplication.clipboard().text() == "login password=Hunter2x ok"
