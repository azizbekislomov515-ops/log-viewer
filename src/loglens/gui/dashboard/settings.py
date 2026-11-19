"""Settings as a page: the same editors as the Settings dialog, grouped in cards.

Notification conditions and mutes live on the Alerts page, so saving here keeps
whatever they are at that moment.
"""

from __future__ import annotations

from dataclasses import replace
from typing import TYPE_CHECKING

from PySide6.QtWidgets import QFormLayout, QGridLayout, QHBoxLayout, QPushButton, QWidget

from loglens.config import default_config_path
from loglens.gui.dashboard.base import DashPage
from loglens.gui.dashboard.widgets import Card, label
from loglens.gui.widgets import SettingsFields

if TYPE_CHECKING:
    from loglens.gui.main_window import MainWindow


def _form(card: Card, rows: list[tuple[str, QWidget]]) -> QFormLayout:
    form = QFormLayout()
    form.setHorizontalSpacing(24)
    form.setVerticalSpacing(12)
    for text, widget in rows:
        form.addRow(text, widget)
    card.body.addLayout(form)
    return form


class SettingsPage(DashPage, SettingsFields):
    """Every setting; Save applies and writes config.toml."""

    def __init__(self, window: MainWindow) -> None:
        path = window._settings_path or default_config_path()
        super().__init__(window, "Settings", f"Saved to {path}", "", "Save")
        self._build_fields(window.settings)
        self.header.action.clicked.connect(self.save)
        appearance = Card("Appearance")
        _form(appearance, [("Theme", self.theme), ("Explanations under rows", self.inline)])
        storage = Card("Storage")
        _form(
            storage,
            [
                ("Keep logs for", self.retention_days),
                ("Keep at most per source", self.max_rows),
                ("Disk budget", self.disk_mb),
                ("Memory budget", self.memory_mb),
            ],
        )
        rules = Card("Rule packs")
        intro = label(
            "Built-in packs explain Squid, ClamAV, Docker, sshd, Nginx, systemd and the "
            "kernel. Add folders with your own YAML packs:",
            role="hint",
        )
        intro.setWordWrap(True)
        rules.body.addWidget(intro)
        self.rule_dirs.setObjectName("ruleDirs")
        self.rule_dirs.setFixedHeight(96)
        rules.body.addWidget(self.rule_dirs)
        buttons = QHBoxLayout()
        buttons.addWidget(self.add_dir_btn)
        buttons.addWidget(self.remove_dir_btn)
        buttons.addStretch()
        rules.body.addLayout(buttons)
        discovery = Card("Discovery")
        _form(
            discovery,
            [
                ("Look for new sources every", self.interval),
                ("Follow at most", self.collectors),
                ("Hide sources matching", self.exclude),
            ],
        )
        discovery.body.addWidget(label("One pattern per line, e.g. docker:test-*", role="hint"))
        privacy = Card("Privacy")
        privacy.body.addWidget(self.redact)
        privacy.body.addWidget(self.reversible)
        _form(privacy, [("Also remove matches of", self.redact_patterns)])
        privacy.body.addWidget(self.pattern_error)
        danger = Card("Danger zone")
        danger.body.addWidget(
            label(
                "Delete every stored log entry and any kept secrets. Settings and rules stay.",
                role="hint",
            )
        )
        clear = QPushButton("Clear all data…")
        clear.setObjectName("danger")
        clear.clicked.connect(self._clear_data)
        row = QHBoxLayout()
        row.addWidget(clear)
        row.addStretch()
        danger.body.addLayout(row)
        danger.body.addWidget(
            label(
                "Retention, privacy and limit changes apply the next time LogLens starts.",
                role="hint",
            )
        )
        for card in (appearance, storage, rules, discovery, privacy, danger):
            card.body.addStretch()
        grid = QGridLayout()
        grid.setSpacing(20)
        grid.addWidget(appearance, 0, 0)
        grid.addWidget(storage, 1, 0)
        grid.addWidget(rules, 2, 0)
        grid.addWidget(discovery, 0, 1)
        grid.addWidget(privacy, 1, 1)
        grid.addWidget(danger, 2, 1)
        grid.setColumnStretch(0, 1)
        grid.setColumnStretch(1, 1)
        self.body.addLayout(grid)
        self.body.addStretch()

    def _clear_data(self) -> None:
        self.w.clear_all_data()

    def refresh(self) -> None:
        """Show the window's current settings (they may have changed elsewhere)."""
        if self.w.settings != self._settings:
            self._load_fields(self.w.settings)

    def save(self) -> None:
        """Apply and save, unless a custom secret pattern is invalid."""
        if self.pattern_errors():
            return
        current = self.w.settings
        self.w.apply_settings(
            replace(
                self.result_settings(),
                notify_on=current.notify_on,
                muted=current.muted,
                pinned=current.pinned,
                onboarded=current.onboarded,
            )
        )
        self._settings = self.w.settings
        self.w.statusBar().showMessage("Settings saved", 4000)
