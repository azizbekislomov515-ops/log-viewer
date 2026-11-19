"""First-run onboarding: what LogLens can read, how to fix what it cannot, which sources to
show and follow, and the demos.

Shown once, after the main window appears (``Settings.onboarded``), and again from
⋯ > Getting started. It reuses the window's own discovery results (the wizard updates
when discovery does), so it never runs discovery a second time.
"""

from __future__ import annotations

import shutil
import sys
from collections.abc import Sequence
from dataclasses import dataclass, replace

from PySide6.QtCore import QProcess, Qt
from PySide6.QtGui import QGuiApplication
from PySide6.QtWidgets import (
    QCheckBox,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QVBoxLayout,
    QWidget,
    QWizard,
    QWizardPage,
)

from loglens.config import Settings
from loglens.core.models import DiscoveryIssue, GroupKind, ServiceGroup, Severity
from loglens.resources import data_path
from loglens.security.text import printable

#: Discoverer -> the category it fills.
_DISCOVERER_CATEGORY = {"systemd": "system", "docker": "docker", "files": "files"}
CATEGORY_TITLES = {
    "system": "System services (journald)",
    "docker": "Docker containers and Compose projects",
    "files": "Log files (/var/log)",
}
#: Exclude patterns that hide a whole category.
CATEGORY_EXCLUDES = {"system": ("systemd:*",), "docker": ("docker:*",), "files": ("file:*",)}
#: Groups with more sources than this are not offered for background following.
MAX_FOLLOW_GROUP = 25
DEMO_STACK_PROJECT = "loglens-demo"


@dataclass(frozen=True, slots=True)
class Access:
    """What LogLens found in one category and what limits it."""

    category: str
    sources: int
    issues: tuple[DiscoveryIssue, ...]

    @property
    def state(self) -> str:
        """``ok``, ``limited`` (some sources, some problems) or ``unavailable``."""
        problems = [i for i in self.issues if i.severity >= Severity.WARNING]
        if not problems:
            return "ok" if self.sources or not self.issues else "unavailable"
        return "limited" if self.sources else "unavailable"


def access_summary(
    groups: Sequence[ServiceGroup], issues: Sequence[DiscoveryIssue]
) -> list[Access]:
    """Per category: how many sources were found and the issues that limit it."""
    counts = {"system": 0, "docker": 0, "files": 0}
    for group in groups:
        key = {GroupKind.SYSTEM: "system", GroupKind.FILES: "files"}.get(group.kind, "docker")
        counts[key] += len(group.sources)
    return [
        Access(
            category,
            counts[category],
            tuple(i for i in issues if _DISCOVERER_CATEGORY.get(i.discoverer) == category),
        )
        for category in ("system", "docker", "files")
    ]


def followable(groups: Sequence[ServiceGroup]) -> list[ServiceGroup]:
    """Groups small enough to follow in the background (Compose projects, file groups)."""
    return [
        g
        for g in groups
        if g.kind in (GroupKind.DOCKER_COMPOSE, GroupKind.FILES)
        and 0 < len(g.sources) <= MAX_FOLLOW_GROUP
    ]


def apply_choices(
    settings: Settings,
    shown: dict[str, bool],
    follow: Sequence[ServiceGroup],
) -> Settings:
    """Settings after onboarding: hidden categories excluded, chosen groups pinned."""
    hidden = {p for patterns in CATEGORY_EXCLUDES.values() for p in patterns}
    exclude = [p for p in settings.discovery_exclude if p not in hidden]
    for category, visible in shown.items():
        if not visible:
            exclude += CATEGORY_EXCLUDES[category]
    pins = set(settings.pinned) | {s.id for g in follow for s in g.sources}
    return replace(
        settings,
        discovery_exclude=tuple(exclude),
        pinned=tuple(sorted(pins)),
        onboarded=True,
    )


def demo_stack_command() -> list[str] | None:
    """The command that starts the demo Compose stack, or None without Docker."""
    docker = shutil.which("docker")
    compose = data_path("demo_stack") / "docker-compose.yml"
    if docker is None or not compose.is_file():
        return None
    return [docker, "compose", "-f", str(compose), "-p", DEMO_STACK_PROJECT, "up", "-d", "--build"]


def demo_app_command() -> list[str]:
    """The command that opens LogLens on replayed sample logs."""
    exe = shutil.which("loglens")
    if exe is not None:
        return [exe, "--demo"]
    return [sys.executable, "-c", "import sys; from loglens.gui.app import main; "
            "sys.exit(main(['--demo']))"]  # fmt: skip


def _label(text: str, *, wrap: bool = True, role: str | None = None) -> QLabel:
    label = QLabel(text)
    label.setTextFormat(Qt.TextFormat.PlainText)
    label.setWordWrap(wrap)
    label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
    if role:
        label.setProperty("role", role)
    return label


class _AccessPage(QWizardPage):
    def __init__(self) -> None:
        super().__init__()
        self.setTitle("What LogLens can read")
        self.setSubTitle(
            "LogLens runs as you, never as root. Where your account cannot read a log, "
            "here is exactly what to change."
        )
        self.body = QVBoxLayout(self)
        self.rows: list[QWidget] = []

    def show_access(self, rows: Sequence[Access]) -> None:
        for widget in self.rows:
            widget.deleteLater()
        self.rows = []
        glyph = {"ok": "✔", "limited": "⚠", "unavailable": "✖"}
        for access in rows:
            box = QWidget()
            layout = QVBoxLayout(box)
            layout.setContentsMargins(0, 4, 0, 4)
            head = f"{glyph[access.state]}  {CATEGORY_TITLES[access.category]}: "
            head += f"{access.sources} found" if access.sources else "none found"
            title = _label(head)
            title.setStyleSheet("font-weight: 600")
            layout.addWidget(title)
            for issue in access.issues:
                layout.addWidget(_label(printable(issue.message), role="hint"))
                if issue.hint:
                    line = QHBoxLayout()
                    line.addWidget(_label("How to fix: " + printable(issue.hint)), 1)
                    copy = QPushButton("Copy")
                    copy.setToolTip("Copy the fix to the clipboard")
                    copy.clicked.connect(
                        lambda _=False, h=issue.hint: QGuiApplication.clipboard().setText(h)
                    )
                    line.addWidget(copy, 0, Qt.AlignmentFlag.AlignTop)
                    layout.addLayout(line)
            self.body.addWidget(box)
            self.rows.append(box)
        note = _label(
            "After changing a group, log out and back in, then use ⋯ > Look for new "
            "sources now. Details: Troubleshooting in the user guide.",
            role="hint",
        )
        self.body.addWidget(note)
        self.rows.append(note)
        self.body.addStretch()


class _ChoosePage(QWizardPage):
    def __init__(self, settings: Settings) -> None:
        super().__init__()
        self.setTitle("Choose what to monitor")
        self.setSubTitle(
            "Shown sources appear in the list on the left. Followed ones are read in the "
            "background, so you get unread counts and notifications without opening them."
        )
        grid = QGridLayout(self)
        grid.addWidget(_label("Show", role="hint"), 0, 0)
        self.shown: dict[str, QCheckBox] = {}
        for row, (category, title) in enumerate(CATEGORY_TITLES.items(), start=1):
            box = QCheckBox(title)
            box.setChecked(not set(CATEGORY_EXCLUDES[category]) <= set(settings.discovery_exclude))
            self.shown[category] = box
            grid.addWidget(box, row, 0, 1, 2)
        self.follow_title = _label("Follow in the background", role="hint")
        grid.addWidget(self.follow_title, 5, 0)
        self.follow_area = QVBoxLayout()
        grid.addLayout(self.follow_area, 6, 0, 1, 2)
        grid.setRowStretch(7, 1)
        self.follow: dict[str, tuple[QCheckBox, ServiceGroup]] = {}

    def show_groups(self, groups: Sequence[ServiceGroup]) -> None:
        offered = followable(groups)
        for group_id in list(self.follow):
            if group_id not in {g.id for g in offered}:
                self.follow.pop(group_id)[0].deleteLater()
        for group in offered:
            if group.id in self.follow:
                self.follow[group.id] = (self.follow[group.id][0], group)
                continue
            box = QCheckBox(f"{printable(group.name)} ({len(group.sources)})")
            box.setChecked(group.kind is GroupKind.DOCKER_COMPOSE)
            self.follow[group.id] = (box, group)
            self.follow_area.addWidget(box)
        self.follow_title.setVisible(bool(self.follow))

    def choices(self) -> tuple[dict[str, bool], list[ServiceGroup]]:
        shown = {category: box.isChecked() for category, box in self.shown.items()}
        follow = [group for box, group in self.follow.values() if box.isChecked()]
        return shown, follow


class _DemoPage(QWizardPage):
    def __init__(self) -> None:
        super().__init__()
        self.setTitle("Try it with sample logs")
        self.setSubTitle("Optional. Both demos run on this computer only.")
        layout = QVBoxLayout(self)
        layout.addWidget(_label(
            "Replay demo: a second LogLens window replays sample Squid, ClamAV, nginx, sshd "
            "and Docker logs. Nothing is installed or started."
        ))  # fmt: skip
        self.replay = QPushButton("Open the replay demo")
        self.replay.clicked.connect(self._open_replay)
        layout.addWidget(self.replay, 0, Qt.AlignmentFlag.AlignLeft)
        layout.addSpacing(12)
        layout.addWidget(_label(
            "Demo stack: real Squid, ClamAV and nginx containers (Docker Compose project "
            f"'{DEMO_STACK_PROJECT}') that produce blocked sites, a test-virus detection "
            "and a crash loop. Builds small Alpine images (needs network once). Stop it "
            f"with: docker compose -p {DEMO_STACK_PROJECT} down -v"
        ))  # fmt: skip
        self.stack = QPushButton("Start the demo stack")
        self.stack.clicked.connect(self._start_stack)
        layout.addWidget(self.stack, 0, Qt.AlignmentFlag.AlignLeft)
        self.status = _label("", role="hint")
        layout.addWidget(self.status)
        layout.addStretch()
        self.process: QProcess | None = None
        if demo_stack_command() is None:
            self.stack.setEnabled(False)
            self.status.setText("The demo stack needs Docker with Compose and Docker access.")

    def _open_replay(self) -> None:
        program, *args = demo_app_command()
        ok = QProcess.startDetached(program, args)[0]
        self.status.setText("The replay demo is opening." if ok else "Could not start it.")

    def _start_stack(self) -> None:
        command = demo_stack_command()
        if command is None or self.process is not None:
            return
        self.process = QProcess(self)
        self.process.setProcessChannelMode(QProcess.ProcessChannelMode.MergedChannels)
        self.process.finished.connect(self._stack_finished)
        self.process.start(command[0], command[1:])
        self.stack.setEnabled(False)
        self.status.setText("Building and starting the demo stack (a minute or two)…")

    def _stack_finished(self, code: int, _status: object) -> None:
        assert self.process is not None  # noqa: S101 - set by _start_stack
        output = bytes(self.process.readAll().data()).decode(errors="replace")
        self.process = None
        self.stack.setEnabled(True)
        if code == 0:
            self.status.setText(
                f"Started. It appears under Docker Compose > {DEMO_STACK_PROJECT} in a moment."
            )
        else:
            last = printable(output.strip().splitlines()[-1] if output.strip() else "")
            self.status.setText(f"Docker could not start it (exit {code}): {last}")


class OnboardingWizard(QWizard):
    """The first-run guide. ``result_settings`` is valid after it is accepted."""

    def __init__(
        self,
        settings: Settings,
        groups: Sequence[ServiceGroup],
        issues: Sequence[DiscoveryIssue],
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.setWindowTitle("Welcome to LogLens")
        self.setWizardStyle(QWizard.WizardStyle.ModernStyle)
        self.setOption(QWizard.WizardOption.NoBackButtonOnStartPage)
        self._settings = settings
        welcome = QWizardPage()
        welcome.setTitle("Welcome to LogLens")
        layout = QVBoxLayout(welcome)
        layout.addWidget(_label(
            "LogLens finds the logs on this computer (systemd services, Docker containers "
            "and Compose projects, files such as Squid, ClamAV and nginx) and explains in "
            "plain language what each service is doing.\n\n"
            "• Everything stays on this computer. Nothing is sent anywhere.\n"
            "• Passwords, tokens, keys and card numbers are removed before logs are "
            "stored.\n"
            "• It runs as you and only reads. It never needs root.\n\n"
            "This takes a minute: see what LogLens can read, choose what to monitor, and "
            "optionally try a demo."
        ))  # fmt: skip
        layout.addStretch()
        self.access = _AccessPage()
        self.choose = _ChoosePage(settings)
        self.demo = _DemoPage()
        for page in (welcome, self.access, self.choose, self.demo):
            self.addPage(page)
        self.update_sources(groups, issues)
        self.resize(720, 560)

    def update_sources(
        self, groups: Sequence[ServiceGroup], issues: Sequence[DiscoveryIssue]
    ) -> None:
        """Refresh from a new discovery result."""
        self.access.show_access(access_summary(groups, issues))
        self.choose.show_groups(groups)

    def result_settings(self) -> Settings:
        """The settings with the user's choices applied (and ``onboarded`` set)."""
        shown, follow = self.choose.choices()
        return apply_choices(self._settings, shown, follow)
