"""Access: who LogLens runs as, what it can read, and the exact fix for what it can't.

Fixes are shown with a Copy button, never run: LogLens does not ask for root.
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import TYPE_CHECKING

from PySide6.QtCore import Qt
from PySide6.QtGui import QGuiApplication
from PySide6.QtWidgets import QFrame, QGridLayout, QHBoxLayout, QPushButton, QVBoxLayout, QWidget

from loglens.core.models import Severity
from loglens.gui.dashboard.base import DashPage, clear_layout
from loglens.gui.dashboard.widgets import Card, Kpi, Pill, label
from loglens.gui.theme import SEVERITY_GLYPH
from loglens.security.privileges import current_groups, journal_access_issue

if TYPE_CHECKING:
    from loglens.gui.main_window import MainWindow

HELPER_SOCKET = Path("/run/loglens-helper.sock")  # helper.server.DEFAULT_SOCKET
DOCKER_SOCKET = Path("/var/run/docker.sock")
#: The first shell command in a hint ("... (sudo usermod -aG adm $USER), then ...").
_COMMAND = re.compile(r"(sudo [^(),;]+?|dockerd-rootless-setuptool\.sh install)(?=[),;]|, then|$)")


def command_in(hint: str) -> str | None:
    """The copy-pasteable command inside a fix hint, if there is one."""
    found = _COMMAND.search(hint)
    return found.group(1).strip().rstrip(".") if found else None


class AccessPage(DashPage):
    """Permissions and how to fix them."""

    def __init__(self, window: MainWindow) -> None:
        super().__init__(
            window,
            "Access",
            "What LogLens can read, and the exact fix when it can't",
            "",
            "Check again",
        )
        self.header.action.clicked.connect(window.backend.refresh_discovery)
        self.user = Kpi("Running as")
        self.readable = Kpi("Sources found")
        self.helper = Kpi("Read-only helper")
        kpis = QHBoxLayout()
        kpis.setSpacing(20)
        for kpi in (self.user, self.readable, self.helper):
            kpis.addWidget(kpi)
        perms = Card("Permissions", "What this user may read")
        self.perms = QVBoxLayout()
        self.perms.setSpacing(14)
        perms.body.addLayout(self.perms)
        perms.body.addStretch()
        fixes = Card("How to fix", "")
        self.fixes_card = fixes
        self.fixes = QVBoxLayout()
        self.fixes.setSpacing(18)
        fixes.body.addLayout(self.fixes)
        fixes.body.addStretch()
        fixes.body.addWidget(
            label("LogLens never asks for root. Fixes are shown, never run for you.", role="hint")
        )
        grid = QGridLayout()
        grid.setSpacing(20)
        grid.addWidget(perms, 0, 0)
        grid.addWidget(fixes, 0, 1)
        self.body.addLayout(kpis)
        self.body.addLayout(grid, 1)

    def refresh(self) -> None:
        """Re-check permissions and list the current discovery issues."""
        t, w = self.colors, self.w
        root = os.geteuid() == 0
        self.user.set_value(
            "root" if root else "Regular user",
            "not recommended" if root else "not root",
            t.error if root else t.ok,
        )
        issues = list(w._issues)
        errors = dict(w._collector_errors)
        problems = len(issues) + len(errors)
        self.readable.set_value(
            f"{len(w.tree_model.sources()):,}",
            f"{problems} problem{'s' * (problems != 1)}" if problems else "all readable",
            t.warning if problems else t.ok,
        )
        installed = HELPER_SOCKET.exists()
        self.helper.set_value(
            "Running" if installed else "Not installed",
            "" if installed else "optional",
            t.notice,
        )
        clear_layout(self.perms)
        groups = current_groups()
        journal = journal_access_issue(groups)
        self._perm(
            journal is None,
            "System journal",
            "Every service's journal is readable" if journal is None else journal.message,
        )
        if not DOCKER_SOCKET.exists():
            self._perm(None, "Docker", "Docker is not installed or not running")
        elif os.access(DOCKER_SOCKET, os.R_OK | os.W_OK):
            self._perm(
                True,
                "Docker",
                "Containers and Compose projects are visible",
                "root-equivalent" if "docker" in groups else None,
            )
        else:
            self._perm(False, "Docker", "No access to the Docker socket")
        files = [i for i in issues if i.discoverer == "files"]
        self._perm(
            not files,
            "Log files",
            f"{len(files)} folder(s) or file(s) are not readable"
            if files
            else "Every log file LogLens found is readable",
        )
        self._perm(
            w.settings.redact_secrets,
            "Secrets",
            "Passwords, tokens and keys are removed before storing"
            if w.settings.redact_secrets
            else "Secrets are stored as they appear (Settings > Privacy)",
        )
        self._perm(not root, "Least privilege", "The window never needs root to run")
        clear_layout(self.fixes)
        rows = [(i.severity, i.message, i.hint or "") for i in issues]
        rows += [
            (Severity.ERROR, f"Reading {sid} stopped: {err}", "LogLens keeps retrying.")
            for sid, err in errors.items()
        ]
        rows.sort(key=lambda r: -r[0])
        self.fixes_card.caption.setText(f"{len(rows)} issue{'s' * (len(rows) != 1)}")
        for severity, message, hint in rows:
            self.fixes.addWidget(self._fix(severity, message, hint))
        if not rows:
            self.fixes.addWidget(label("Nothing to fix: every source is readable.", role="hint"))

    def _perm(self, ok: bool | None, title: str, why: str, tag: str | None = None) -> None:
        t = self.colors
        color = t.dim if ok is None else (t.ok if ok else t.error)
        row = QWidget()
        line = QHBoxLayout(row)
        line.setContentsMargins(0, 0, 0, 0)
        line.setSpacing(12)
        mark = Pill("-" if ok is None else ("✓" if ok else "✕"), color)
        mark.setAccessibleName("allowed" if ok else "not allowed")
        text = QVBoxLayout()
        text.setSpacing(2)
        text.addWidget(label(title, name="rowTitle"))
        why_label = label(why, role="hint")
        why_label.setWordWrap(True)
        text.addWidget(why_label)
        line.addWidget(mark, 0, Qt.AlignmentFlag.AlignTop)
        line.addLayout(text, 1)
        if tag:
            line.addWidget(Pill(tag, t.warning), 0, Qt.AlignmentFlag.AlignTop)
        self.perms.addWidget(row)

    def _fix(self, severity: Severity, message: str, hint: str) -> QWidget:
        box = QWidget()
        column = QVBoxLayout(box)
        column.setContentsMargins(0, 0, 0, 0)
        column.setSpacing(6)
        head = label(f"{SEVERITY_GLYPH.get(severity) or '●'}  {message}", name="rowTitle")
        head.setWordWrap(True)
        head.setStyleSheet(f"color: {self.colors.severity(severity).name()};")
        column.addWidget(head)
        if hint:
            how = label(hint, role="hint")
            how.setWordWrap(True)
            column.addWidget(how)
        if command := command_in(hint):
            frame = QFrame()
            frame.setObjectName("command")
            line = QHBoxLayout(frame)
            line.setContentsMargins(12, 6, 6, 6)
            code = label(command, name="mono")
            code.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            copy = QPushButton("Copy")
            copy.setObjectName("link")
            copy.setAccessibleName(f"Copy: {command}")
            copy.clicked.connect(lambda _=False, c=command: self._copy(c))
            line.addWidget(code, 1)
            line.addWidget(copy)
            column.addWidget(frame)
        return box

    def _copy(self, command: str) -> None:
        QGuiApplication.clipboard().setText(command)
        self.w.statusBar().showMessage("Copied. Run it in a terminal yourself.", 5000)
