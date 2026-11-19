"""Smaller widgets: source tree delegate, issues panel, command palette, settings dialog,
time-range dialog and the debug overlay."""

from __future__ import annotations

import math
import time
from collections import deque
from collections.abc import Callable, Sequence
from dataclasses import replace
from datetime import datetime, timedelta

from PySide6.QtCore import (
    QDateTime,
    QEvent,
    QModelIndex,
    QObject,
    QPersistentModelIndex,
    QPointF,
    QRect,
    QRectF,
    QSize,
    Qt,
    QTimer,
    Signal,
)
from PySide6.QtGui import QColor, QFont, QKeyEvent, QPainter, QPainterPath, QPen
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QDateTimeEdit,
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QFormLayout,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QPlainTextEdit,
    QPushButton,
    QSpinBox,
    QStyle,
    QStyledItemDelegate,
    QStyleOptionViewItem,
    QVBoxLayout,
    QWidget,
)

from loglens.config import INLINE_MODES, THEMES, Settings
from loglens.core.models import DiscoveryIssue, LogSource, Severity, SourceKind, SourceStatus
from loglens.gui import theme as themes
from loglens.gui.notify import CONDITIONS
from loglens.gui.source_tree import NodeKind, TreeRole
from loglens.security.redact import Redactor

AnyIndex = QModelIndex | QPersistentModelIndex


# ---------------------------------------------------------------------- icons


def paint_kind_icon(painter: QPainter, rect: QRectF, kind: str, color: QColor) -> None:
    """Small line icons drawn with QPainter (crisp at any scale, theme-colored)."""
    painter.save()
    painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)
    pen = QPen(color, 1.3)
    painter.setPen(pen)
    painter.setBrush(Qt.BrushStyle.NoBrush)
    r = rect.adjusted(2, 2, -2, -2)
    cx, cy, w, h = r.center().x(), r.center().y(), r.width(), r.height()
    if kind == "systemd":  # a gear: circle with teeth
        painter.drawEllipse(QPointF(cx, cy), w * 0.22, h * 0.22)
        for i in range(8):
            a = i * math.pi / 4
            painter.drawLine(
                QPointF(cx + math.cos(a) * w * 0.32, cy + math.sin(a) * h * 0.32),
                QPointF(cx + math.cos(a) * w * 0.46, cy + math.sin(a) * h * 0.46),
            )
    elif kind in ("container", "compose"):  # an isometric box (stacked for compose)
        layers = (0, -3) if kind == "compose" else (0,)
        for dy in layers:
            path = QPainterPath()
            top = r.top() + h * 0.18 + dy + (3 if kind == "compose" else 0)
            path.moveTo(cx, top)
            path.lineTo(r.right(), top + h * 0.2)
            path.lineTo(r.right(), top + h * 0.6)
            path.lineTo(cx, top + h * 0.8)
            path.lineTo(r.left(), top + h * 0.6)
            path.lineTo(r.left(), top + h * 0.2)
            path.closeSubpath()
            painter.drawPath(path)
        painter.drawLine(
            QPointF(cx, r.top() + h * 0.58 + (3 if kind == "compose" else 0)),
            QPointF(cx, r.bottom()),
        )
    elif kind == "file":  # a page with a folded corner
        path = QPainterPath()
        left, top, right, bottom = r.left() + w * 0.15, r.top(), r.right() - w * 0.15, r.bottom()
        path.moveTo(left, top)
        path.lineTo(right - w * 0.25, top)
        path.lineTo(right, top + h * 0.25)
        path.lineTo(right, bottom)
        path.lineTo(left, bottom)
        path.closeSubpath()
        painter.drawPath(path)
        for frac in (0.5, 0.68, 0.86):
            painter.drawLine(
                QPointF(left + w * 0.15, top + h * frac), QPointF(right - w * 0.15, top + h * frac)
            )
    painter.restore()


def _icon_kind(index: AnyIndex) -> str | None:
    kind = index.data(TreeRole.KIND)
    if kind == NodeKind.SOURCE:
        source: LogSource = index.data(TreeRole.SOURCE)
        return {
            SourceKind.SYSTEMD: "systemd",
            SourceKind.DOCKER_CONTAINER: "container",
            SourceKind.FILE: "file",
        }[source.kind]
    if kind == NodeKind.GROUP:
        return "compose" if str(index.data(TreeRole.NODE_ID)).startswith("compose") else "file"
    return None


class SourceDelegate(QStyledItemDelegate):
    """Tree rows: kind icon, name, status shape (filled / ring / cross), unread badge."""

    def __init__(self, parent: QObject | None = None) -> None:
        super().__init__(parent)
        self.theme = themes.DARK

    def sizeHint(self, option: QStyleOptionViewItem, index: AnyIndex) -> QSize:
        size = super().sizeHint(option, index)
        return QSize(size.width() + 40, max(size.height(), 24))

    def paint(self, painter: QPainter, option: QStyleOptionViewItem, index: AnyIndex) -> None:
        t = self.theme
        rect: QRect = option.rect
        state = option.state
        painter.save()
        if state & QStyle.StateFlag.State_Selected:
            painter.fillRect(rect, QColor(t.raised))
            painter.fillRect(QRect(rect.left(), rect.top(), 2, rect.height()), QColor(t.accent))
        elif state & QStyle.StateFlag.State_MouseOver:
            hover = QColor(t.raised)
            hover.setAlpha(120)
            painter.fillRect(rect, hover)
        kind = index.data(TreeRole.KIND)
        x = rect.left() + 4
        font = QFont(option.font)
        if kind == NodeKind.CATEGORY:
            font.setWeight(QFont.Weight.DemiBold)
            painter.setFont(font)
            painter.setPen(QColor(t.text))
        else:
            painter.setFont(font)
            painter.setPen(QColor(t.text))
        icon = _icon_kind(index)
        if icon is not None:
            paint_kind_icon(
                painter,
                QRectF(x, rect.top() + (rect.height() - 16) / 2, 16, 16),
                icon,
                QColor(t.dim),
            )
            x += 22
        right = rect.right() - 8
        unread = int(index.data(TreeRole.UNREAD) or 0)
        if unread:
            label = "99+" if unread > 99 else str(unread)
            fm = painter.fontMetrics()
            bw = fm.horizontalAdvance(label) + 12
            badge = QRect(right - bw, rect.center().y() - 8, bw, 16)
            painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)
            painter.setPen(Qt.PenStyle.NoPen)
            painter.setBrush(QColor(t.error))
            painter.drawRoundedRect(badge, 8, 8)
            painter.setPen(QColor(t.on_accent if t.name == "light" else t.canvas))
            painter.drawText(badge, Qt.AlignmentFlag.AlignCenter, label)
            right = badge.left() - 6
        count = index.data(TreeRole.COUNT)
        if count and kind != NodeKind.SOURCE:
            painter.setPen(QColor(t.dim))
            label = str(count)
            fm = painter.fontMetrics()
            painter.drawText(
                QRect(
                    right - fm.horizontalAdvance(label),
                    rect.top(),
                    fm.horizontalAdvance(label),
                    rect.height(),
                ),
                Qt.AlignmentFlag.AlignVCenter,
                label,
            )
            right -= fm.horizontalAdvance(label) + 6
        if kind == NodeKind.SOURCE:
            source: LogSource = index.data(TreeRole.SOURCE)
            right = self._status(painter, right, rect, source.status)
            if index.data(TreeRole.PINNED):
                painter.setPen(QColor(t.dim))
                painter.drawText(
                    QRect(right - 14, rect.top(), 14, rect.height()),
                    Qt.AlignmentFlag.AlignCenter,
                    "⚲",
                )
                right -= 16
        painter.setPen(
            QColor(
                t.text
                if kind != NodeKind.SOURCE
                or index.data(TreeRole.SOURCE).status != SourceStatus.STOPPED
                else t.dim
            )
        )
        text = str(index.data(Qt.ItemDataRole.DisplayRole) or "")
        elided = painter.fontMetrics().elidedText(text, Qt.TextElideMode.ElideRight, right - x - 4)
        painter.drawText(
            QRect(x, rect.top(), right - x, rect.height()), Qt.AlignmentFlag.AlignVCenter, elided
        )
        painter.restore()

    def _status(self, painter: QPainter, right: int, rect: QRect, status: SourceStatus) -> int:
        t = self.theme
        cx, cy, r = right - 5, rect.center().y(), 4
        painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)
        if status == SourceStatus.RUNNING:
            painter.setPen(Qt.PenStyle.NoPen)
            painter.setBrush(QColor(t.ok))
            painter.drawEllipse(QPointF(cx, cy), r, r)
        elif status == SourceStatus.FAILED:
            painter.setPen(QPen(QColor(t.error), 2))
            painter.drawLine(QPointF(cx - r, cy - r), QPointF(cx + r, cy + r))
            painter.drawLine(QPointF(cx - r, cy + r), QPointF(cx + r, cy - r))
        else:
            painter.setPen(QPen(QColor(t.dim), 1.2))
            painter.setBrush(Qt.BrushStyle.NoBrush)
            painter.drawEllipse(QPointF(cx, cy), r - 0.5, r - 0.5)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing, False)
        return right - 2 * r - 8


# ---------------------------------------------------------------------- issues panel


class IssuesPanel(QWidget):
    """Discovery issues and collector errors, each with what to do about it."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.list = QListWidget(self)
        self.list.setWordWrap(True)
        self.list.setAccessibleName("Discovery issues")
        self.list.setSelectionMode(QListWidget.SelectionMode.NoSelection)
        self.empty = QLabel("No problems found. Every source LogLens knows about is readable.")
        self.empty.setProperty("role", "hint")
        self.empty.setWordWrap(True)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.addWidget(self.empty)
        layout.addWidget(self.list)
        self.theme = themes.DARK
        self.count = 0

    def set_issues(
        self, issues: Sequence[DiscoveryIssue], collector_errors: dict[str, str] | None = None
    ) -> None:
        """Show issues (most severe first) and per-source collector errors."""
        self.list.clear()
        rows: list[tuple[Severity, str, str]] = [
            (i.severity, f"{i.discoverer}: {i.message}", i.hint or "") for i in issues
        ]
        rows += [
            (
                Severity.ERROR,
                f"Reading {sid} stopped: {err}",
                "LogLens keeps retrying. Check that the source still exists and is readable.",
            )
            for sid, err in (collector_errors or {}).items()
        ]
        rows.sort(key=lambda r: -r[0])
        for severity, message, hint in rows:
            glyph = themes.SEVERITY_GLYPH.get(severity) or "●"
            text = f"{glyph}  {message}"
            if hint:
                text += f"\n     How to fix: {hint}"
            item = QListWidgetItem(text)
            item.setForeground(
                self.theme.severity(severity) if not hint else QColor(self.theme.text)
            )
            item.setData(
                Qt.ItemDataRole.AccessibleTextRole, f"{severity.name.lower()}: {message}. {hint}"
            )
            self.list.addItem(item)
        self.count = len(rows)
        self.empty.setVisible(not rows)
        self.list.setVisible(bool(rows))


# ---------------------------------------------------------------------- command palette


def fuzzy_score(query: str, text: str) -> int | None:
    """Subsequence match score (higher is better), None if ``query`` is not in ``text``.

    Rewards consecutive characters and matches at word starts: "cld" finds clamav-daemon.
    """
    q, s = query.lower(), text.lower()
    if not q:
        return 0
    score, pos, prev = 0, -1, -2
    for ch in q:
        pos = s.find(ch, pos + 1)
        if pos < 0:
            return None
        score += 3 if pos == prev + 1 else 1
        if pos == 0 or not s[pos - 1].isalnum():
            score += 2
        prev = pos
    return score * 100 - len(s)


class CommandPalette(QDialog):
    """Ctrl+K: type to jump to any source (fuzzy), Enter opens it."""

    chosen = Signal(str)  # source id

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent, Qt.WindowType.Popup | Qt.WindowType.FramelessWindowHint)
        self.setAccessibleName("Jump to source")
        frame = QFrame(self)
        frame.setObjectName("palette")
        self.input = QLineEdit(frame)
        self.input.setPlaceholderText("Jump to a source…  (type part of a name)")
        self.input.setAccessibleName("Source name")
        self.results = QListWidget(frame)
        self.results.setAccessibleName("Matching sources")
        inner = QVBoxLayout(frame)
        inner.addWidget(self.input)
        inner.addWidget(self.results)
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.addWidget(frame)
        self.resize(560, 380)
        self._sources: list[LogSource] = []
        self.input.textChanged.connect(self._filter)
        self.input.installEventFilter(self)
        self.results.itemActivated.connect(self._activate)

    def open_with(self, sources: Sequence[LogSource]) -> None:
        """Show over the parent window with every known source."""
        self._sources = list(sources)
        self.input.clear()
        self._filter("")
        parent = self.parentWidget()
        if parent is not None:
            geo = parent.geometry()
            self.move(geo.center().x() - self.width() // 2, geo.top() + 90)
        self.show()
        self.input.setFocus()

    def _filter(self, text: str) -> None:
        scored = [
            (score, s)
            for s in self._sources
            if (score := fuzzy_score(text, f"{s.display_name} {s.id}")) is not None
        ]
        scored.sort(key=lambda pair: (-pair[0], pair[1].display_name))
        self.results.clear()
        for _, source in scored[:200]:
            item = QListWidgetItem(f"{source.display_name}    {source.id}")
            item.setData(Qt.ItemDataRole.UserRole, source.id)
            self.results.addItem(item)
        if self.results.count():
            self.results.setCurrentRow(0)

    def eventFilter(self, watched: QObject, event: QEvent) -> bool:
        if (
            watched is self.input
            and isinstance(event, QKeyEvent)
            and event.type() == QEvent.Type.KeyPress
        ):
            if event.key() in (Qt.Key.Key_Down, Qt.Key.Key_Up):
                step = 1 if event.key() == Qt.Key.Key_Down else -1
                self.results.setCurrentRow(
                    max(0, min(self.results.currentRow() + step, self.results.count() - 1))
                )
                return True
            if event.key() in (Qt.Key.Key_Return, Qt.Key.Key_Enter):
                if (item := self.results.currentItem()) is not None:
                    self._activate(item)
                return True
        return super().eventFilter(watched, event)

    def _activate(self, item: QListWidgetItem) -> None:
        self.chosen.emit(item.data(Qt.ItemDataRole.UserRole))
        self.close()


# ---------------------------------------------------------------------- settings


class SettingsFields:
    """The editors for every ``Settings`` field, shared by the dialog and the Settings page.

    ``_build_fields`` creates them, ``_load_fields`` shows a ``Settings`` in them and
    ``result_settings`` reads them back (fields without an editor keep their value).
    """

    _settings: Settings

    def _build_fields(self, settings: Settings) -> None:
        self.theme = QComboBox()
        self.theme.addItems(["Follow system", "Light", "Dark"])
        self.retention_days = QSpinBox()
        self.retention_days.setRange(0, 3650)
        self.retention_days.setSuffix(" days")
        self.retention_days.setSpecialValueText("Keep forever")
        self.max_rows = QSpinBox()
        self.max_rows.setRange(0, 100_000_000)
        self.max_rows.setSingleStep(10_000)
        self.max_rows.setSpecialValueText("No limit")
        self.rule_dirs = QListWidget()
        self.add_dir_btn, self.remove_dir_btn = QPushButton("Add folder…"), QPushButton("Remove")
        self.add_dir_btn.clicked.connect(self._add_dir)
        self.remove_dir_btn.clicked.connect(
            lambda: self.rule_dirs.takeItem(self.rule_dirs.currentRow())
        )
        self.exclude = QPlainTextEdit()
        self.exclude.setAccessibleName("Hidden sources, one pattern per line")
        self.exclude.setFixedHeight(80)
        self.inline = QComboBox()
        self.inline.addItems(["Off", "Compact: title after the line", "Full: a second line"])
        self.notify: dict[str, QCheckBox] = {k: QCheckBox(text) for k, text in CONDITIONS.items()}
        self.muted = QPlainTextEdit()
        self.muted.setAccessibleName("Sources that never notify, one id per line")
        self.muted.setFixedHeight(60)
        self.interval = QSpinBox()
        self.interval.setRange(5, 3600)
        self.interval.setSuffix(" s")
        self.redact = QCheckBox("Remove passwords, tokens, keys and card numbers before storing")
        self.reversible = QCheckBox("Keep originals on this computer so I can reveal them")
        self.reversible.setToolTip(
            "Off (recommended): secrets are gone for good. On: they are kept in an owner-only "
            "file under ~/.local/share/loglens/vault. Exports never contain them."
        )
        self.redact_patterns = QPlainTextEdit()
        self.redact_patterns.setAccessibleName("Extra secret patterns, one regex per line")
        self.redact_patterns.setFixedHeight(50)
        self.pattern_error = QLabel("")
        self.pattern_error.setTextFormat(Qt.TextFormat.PlainText)
        self.pattern_error.setProperty("role", "hint")
        self.memory_mb = _budget_box(settings.memory_budget_mb, 128, 65_536, " MB")
        self.disk_mb = _budget_box(settings.disk_budget_mb, 64, 1_048_576, " MB")
        self.collectors = _budget_box(settings.max_collectors, 1, 10_000, "")
        self._load_fields(settings)

    def _load_fields(self, settings: Settings) -> None:
        """Show ``settings`` in the editors (they become the base of ``result_settings``)."""
        self._settings = settings
        self.theme.setCurrentIndex(THEMES.index(settings.theme))
        self.retention_days.setValue(settings.retention_days)
        self.max_rows.setValue(settings.max_rows_per_source)
        self.rule_dirs.clear()
        self.rule_dirs.addItems(list(settings.rule_dirs))
        self.exclude.setPlainText("\n".join(settings.discovery_exclude))
        self.inline.setCurrentIndex(INLINE_MODES.index(settings.inline_explanations))
        for key, box in self.notify.items():
            box.setChecked(key in settings.notify_on)
        self.muted.setPlainText("\n".join(settings.muted))
        self.interval.setValue(settings.discovery_interval_s)
        self.redact.setChecked(settings.redact_secrets)
        self.reversible.setChecked(settings.redact_reversible)
        self.redact_patterns.setPlainText("\n".join(settings.redact_patterns))
        self.pattern_error.setText("")
        budgets: list[tuple[QSpinBox, int]] = [
            (self.memory_mb, settings.memory_budget_mb),
            (self.disk_mb, settings.disk_budget_mb),
            (self.collectors, settings.max_collectors),
        ]
        for spin, value in budgets:
            spin.setValue(value if value else spin.minimum())

    def pattern_errors(self) -> list[str]:
        """Invalid custom secret patterns (a pattern that is silently dropped would leave
        the secrets it was meant to hide, so nothing is saved while there are any)."""
        errors = Redactor(self._patterns()).errors
        self.pattern_error.setText("Not saved, fix: " + "; ".join(errors) if errors else "")
        return errors

    def _patterns(self) -> tuple[str, ...]:
        lines = self.redact_patterns.toPlainText().splitlines()
        return tuple(p.strip() for p in lines if p.strip())

    def _add_dir(self) -> None:
        parent = self if isinstance(self, QWidget) else None
        path = QFileDialog.getExistingDirectory(parent, "Rule pack folder")
        if path:
            self.rule_dirs.addItem(path)

    def result_settings(self) -> Settings:
        """The edited settings."""
        patterns = tuple(p.strip() for p in self.exclude.toPlainText().splitlines() if p.strip())
        return replace(
            self._settings,
            theme=THEMES[self.theme.currentIndex()],
            retention_days=self.retention_days.value(),
            max_rows_per_source=self.max_rows.value(),
            rule_dirs=tuple(self.rule_dirs.item(i).text() for i in range(self.rule_dirs.count())),
            discovery_exclude=patterns,
            discovery_interval_s=self.interval.value(),
            inline_explanations=INLINE_MODES[self.inline.currentIndex()],
            notify_on=tuple(k for k, box in self.notify.items() if box.isChecked()),
            muted=tuple(m.strip() for m in self.muted.toPlainText().splitlines() if m.strip()),
            redact_secrets=self.redact.isChecked(),
            redact_reversible=self.reversible.isChecked(),
            redact_patterns=self._patterns(),
            memory_budget_mb=_budget(self.memory_mb),
            disk_budget_mb=_budget(self.disk_mb),
            max_collectors=_budget(self.collectors),
        )


class SettingsDialog(QDialog, SettingsFields):
    """Edits ``Settings`` in one form; the caller saves them to config.toml."""

    def __init__(self, settings: Settings, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Settings")
        self._build_fields(settings)
        dir_buttons = QHBoxLayout()
        dir_buttons.addWidget(self.add_dir_btn)
        dir_buttons.addWidget(self.remove_dir_btn)
        dir_buttons.addStretch()
        notify_box = QVBoxLayout()
        for box in self.notify.values():
            notify_box.addWidget(box)
        form = QFormLayout()
        form.addRow("Theme", self.theme)
        form.addRow("Keep logs for", self.retention_days)
        form.addRow("Keep at most (per source)", self.max_rows)
        form.addRow("Extra rule pack folders", self.rule_dirs)
        form.addRow("", dir_buttons)
        form.addRow("Hide sources matching", self.exclude)
        hint = QLabel("One pattern per line, e.g. systemd:*.scope or docker:test-*")
        hint.setProperty("role", "hint")
        form.addRow("", hint)
        form.addRow("Look for new sources every", self.interval)
        form.addRow("Explanations under rows", self.inline)
        form.addRow("Desktop notifications for", notify_box)
        form.addRow("Never notify for", self.muted)
        form.addRow("Secrets", self.redact)
        form.addRow("", self.reversible)
        form.addRow("Also remove matches of", self.redact_patterns)
        form.addRow("", self.pattern_error)
        form.addRow("Memory budget", self.memory_mb)
        form.addRow("Disk budget", self.disk_mb)
        form.addRow("Follow at most", self.collectors)
        note = QLabel("Retention, privacy and limit changes apply the next time LogLens starts.")
        note.setProperty("role", "hint")
        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Save | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout = QVBoxLayout(self)
        layout.addLayout(form)
        layout.addWidget(note)
        layout.addWidget(buttons)
        self.resize(600, 860)

    def accept(self) -> None:
        """Save, unless a custom secret pattern is not a valid regex."""
        if not self.pattern_errors():
            super().accept()


def _budget_box(value: int, low: int, high: int, suffix: str) -> QSpinBox:
    """A spin box whose lowest value (``low - 1``) reads "No limit" and means 0."""
    box = QSpinBox()
    box.setRange(low - 1, high)
    box.setSpecialValueText("No limit")
    box.setSuffix(suffix)
    box.setValue(value if value else low - 1)
    return box


def _budget(box: QSpinBox) -> int:
    return 0 if box.value() == box.minimum() else box.value()


class TimeRangeDialog(QDialog):
    """Custom time range: from / to."""

    def __init__(
        self, since: datetime | None, until: datetime | None, parent: QWidget | None = None
    ) -> None:
        super().__init__(parent)
        self.setWindowTitle("Custom time range")
        now = datetime.now().astimezone()
        self.since = QDateTimeEdit(QDateTime(since or now - timedelta(hours=1)))
        self.until = QDateTimeEdit(QDateTime(until or now))
        for edit in (self.since, self.until):
            edit.setCalendarPopup(True)
            edit.setDisplayFormat("yyyy-MM-dd HH:mm:ss")
        form = QFormLayout(self)
        form.addRow("From", self.since)
        form.addRow("To", self.until)
        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        form.addRow(buttons)

    def range(self) -> tuple[datetime, datetime]:
        """The chosen (since, until), timezone-aware."""
        return (
            _aware(self.since.dateTime().toPython()),
            _aware(self.until.dateTime().toPython()),
        )


def _aware(value: object) -> datetime:
    assert isinstance(value, datetime)  # noqa: S101 (QDateTime.toPython of a datetime edit)
    return value.astimezone()


# ---------------------------------------------------------------------- debug overlay


class FrameMeter(QObject):
    """Measures GUI responsiveness: how late a 16 ms timer fires = event-loop stall."""

    def __init__(self, parent: QObject | None = None) -> None:
        super().__init__(parent)
        self.samples: deque[float] = deque(maxlen=600)
        self._timer = QTimer(self)
        self._timer.setInterval(16)
        self._timer.setTimerType(Qt.TimerType.PreciseTimer)
        self._timer.timeout.connect(self._tick)
        self._last = 0.0

    def start(self) -> None:
        """Begin sampling."""
        self._last = time.perf_counter()
        self._timer.start()

    def stop(self) -> None:
        """Stop sampling."""
        self._timer.stop()

    def _tick(self) -> None:
        now = time.perf_counter()
        self.samples.append((now - self._last) * 1000)
        self._last = now

    def summary(self) -> tuple[float, float, float]:
        """(average, p99, max) frame interval in ms over the recent window."""
        data = sorted(self.samples)
        if not data:
            return 0.0, 0.0, 0.0
        return sum(data) / len(data), data[min(len(data) - 1, int(len(data) * 0.99))], data[-1]


class DebugOverlay(QLabel):
    """Ctrl+Alt+D: frame time and model update rates, drawn over the log area."""

    def __init__(self, stats: Callable[[], str], parent: QWidget) -> None:
        super().__init__(parent)
        self.setObjectName("debugOverlay")
        self.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents)
        self._stats = stats
        self._timer = QTimer(self)
        self._timer.setInterval(500)
        self._timer.timeout.connect(self.refresh)
        self.hide()

    def toggle(self) -> None:
        """Show/hide."""
        if self.isVisible():
            self._timer.stop()
            self.hide()
        else:
            self.refresh()
            self.show()
            self.raise_()
            self._timer.start()

    def refresh(self) -> None:
        """Re-read the stats and stick to the top-right corner."""
        self.setText(self._stats())
        self.adjustSize()
        parent = self.parentWidget()
        if parent is not None:
            self.move(parent.width() - self.width() - 24, 8)
