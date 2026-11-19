"""Alerts: which events raise a desktop notification, muted sources, and the
notifications sent this session."""

from __future__ import annotations

from collections import deque
from dataclasses import replace
from datetime import datetime
from typing import TYPE_CHECKING

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QGridLayout, QHBoxLayout, QPushButton, QVBoxLayout, QWidget

from loglens.gui.dashboard.base import DashPage, clear_layout
from loglens.gui.dashboard.widgets import Card, Pill, Toggle, label
from loglens.gui.notify import CONDITIONS, GLOBAL_PER_MINUTE, Notification

if TYPE_CHECKING:
    from loglens.gui.main_window import MainWindow

HISTORY = 100
CONDITION_WORDS = {"critical": "Critical", "detection": "Detection", "restart_loop": "Restart loop",
                   "test": "Test"}  # fmt: skip
CONDITION_HINTS = {
    "critical": "A critical entry, or one a rule rates critical",
    "detection": "Malware, leaked secrets and other security detections",
    "restart_loop": "3 restarts within 5 minutes",
}


class AlertsPage(DashPage):
    """Notification conditions, mutes and history."""

    def __init__(self, window: MainWindow) -> None:
        super().__init__(
            window,
            "Alerts",
            "Desktop notifications for the things that need you",
            "",
            "Send a test alert",
        )
        self.history: deque[tuple[datetime, Notification]] = deque(maxlen=HISTORY)
        self.header.action.clicked.connect(self.send_test)
        window.insights.live_explainer.notified.connect(self.record)
        conditions = Card("Notify me about")
        self.toggles: dict[str, Toggle] = {}
        for key, text in CONDITIONS.items():
            row = QHBoxLayout()
            column = QVBoxLayout()
            column.setSpacing(2)
            column.addWidget(label(text, name="rowTitle"))
            column.addWidget(label(CONDITION_HINTS.get(key, ""), role="hint"))
            toggle = Toggle(text)
            toggle.toggled.connect(self._conditions_changed)
            self.toggles[key] = toggle
            row.addLayout(column, 1)
            row.addWidget(toggle, 0, Qt.AlignmentFlag.AlignVCenter)
            conditions.body.addLayout(row)
        conditions.body.addWidget(
            label(
                f"At most one per source and condition a minute, and {GLOBAL_PER_MINUTE} a "
                "minute in total.",
                role="hint",
            )
        )
        self.muted_card = Card("Muted sources")
        self.muted = QVBoxLayout()
        self.muted_card.body.addLayout(self.muted)
        self.muted_card.body.addStretch()
        self.muted_card.body.addWidget(
            label("Mute a source from its right-click menu on the Sources page.", role="hint")
        )
        self.recent_card = Card("Recent alerts", "This session")
        self.recent = QVBoxLayout()
        self.recent.setSpacing(16)
        self.recent_card.body.addLayout(self.recent)
        self.recent_card.body.addStretch()
        grid = QGridLayout()
        grid.setSpacing(20)
        grid.addWidget(conditions, 0, 0)
        grid.addWidget(self.muted_card, 1, 0)
        grid.addWidget(self.recent_card, 0, 1, 2, 1)
        grid.setRowStretch(1, 1)
        grid.setColumnStretch(0, 1)
        grid.setColumnStretch(1, 1)
        self.body.addLayout(grid, 1)

    def record(self, note: Notification) -> None:
        """A notification was sent (newest first in the list)."""
        self.history.appendleft((datetime.now().astimezone(), note))
        if self.isVisible():
            self.refresh()

    def send_test(self) -> None:
        """Show a sample desktop notification and list it."""
        self.record(self.w.insights.live_explainer.send_test())

    def _conditions_changed(self) -> None:
        chosen = tuple(k for k, toggle in self.toggles.items() if toggle.isChecked())
        if chosen != tuple(self.w.settings.notify_on):
            self.w.apply_settings(replace(self.w.settings, notify_on=chosen))

    def refresh(self) -> None:
        """Re-render from the settings and the history."""
        t, w = self.colors, self.w
        for key, toggle in self.toggles.items():
            toggle.blockSignals(True)
            toggle.setChecked(key in w.settings.notify_on)
            toggle.blockSignals(False)
            toggle.theme = t
            toggle.update()
        clear_layout(self.muted)
        names = w.tree_model.display_names()
        self.muted_card.caption.setText(f"{len(w.settings.muted)} muted")
        for source_id in w.settings.muted:
            row = QWidget()
            line = QHBoxLayout(row)
            line.setContentsMargins(0, 0, 0, 0)
            line.addWidget(label(names.get(source_id, source_id), name="rowTitle"), 1)
            unmute = QPushButton("Unmute")
            unmute.setAccessibleName(f"Unmute {source_id}")
            unmute.clicked.connect(lambda _=False, s=source_id: self._unmute(s))
            line.addWidget(unmute)
            self.muted.addWidget(row)
        if not w.settings.muted:
            self.muted.addWidget(label("No source is muted.", role="hint"))
        clear_layout(self.recent)
        for when, note in list(self.history)[:12]:
            item = QWidget()
            column = QVBoxLayout(item)
            column.setContentsMargins(0, 0, 0, 0)
            column.setSpacing(4)
            top = QHBoxLayout()
            top.addWidget(label(when.strftime("%H:%M:%S"), name="mono"))
            color = (
                t.warning
                if note.condition == "restart_loop"
                else (t.notice if note.condition == "test" else t.critical)
            )
            top.addWidget(Pill(CONDITION_WORDS.get(note.condition, note.condition), color))
            top.addStretch()
            column.addLayout(top)
            column.addWidget(label(note.summary, name="rowTitle"))
            body = label(note.body, role="hint")
            body.setWordWrap(True)
            column.addWidget(body)
            self.recent.addWidget(item)
        if not self.history:
            self.recent.addWidget(
                label(
                    "No notifications yet this session. Send a test alert to check "
                    "that they reach your desktop.",
                    role="hint",
                )
            )

    def _unmute(self, source_id: str) -> None:
        self.w.insights.set_muted(source_id, False)
        self.refresh()
