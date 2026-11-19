"""Dialogs: the rule editor (live preview, saves to the user pack) and export."""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta
from pathlib import Path

from PySide6.QtCore import QDateTime, QTimer, Signal
from PySide6.QtWidgets import (
    QButtonGroup,
    QCheckBox,
    QComboBox,
    QDateTimeEdit,
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPlainTextEdit,
    QPushButton,
    QRadioButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from loglens.core.models import LogEntry, LogSource, RawRecord
from loglens.explain.editor import (
    CATEGORIES,
    SEVERITIES,
    EditorError,
    Preview,
    RuleDraft,
    preview,
    save,
    suggest,
)
from loglens.export import FORMATS
from loglens.gui import theme as themes
from loglens.gui.insight_widgets import plain_label
from loglens.parsers import Normalizer


class RuleEditorDialog(QDialog):
    """Create (or replace) a rule from a log line, with a live preview."""

    saved = Signal(object)  # Path of the user pack

    def __init__(
        self,
        entry: LogEntry,
        source: LogSource,
        counter_line: str = "",
        *,
        directory: Path | None = None,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.setWindowTitle("New rule from this line")
        self.resize(820, 760)
        self._entry, self._source, self._directory = entry, source, directory
        self._normalize = Normalizer()
        self.draft = suggest(entry, source, counter_line)
        self.outcome: Preview | None = None
        mono = themes.mono_font()

        def line(text: str, name: str) -> QLineEdit:
            edit = QLineEdit(text)
            edit.setAccessibleName(name)
            edit.textChanged.connect(self._changed)
            return edit

        self.example = QPlainTextEdit(entry.raw)
        self.example.setReadOnly(True)
        self.example.setMaximumHeight(60)
        self.example.setFont(mono)
        self.example.setAccessibleName("Example line")
        self.rule_id = line(self.draft.rule_id, "Rule id")
        self.title_edit = line(self.draft.title, "Title")
        self.regex = line(self.draft.regex, "Regular expression")
        self.regex.setFont(mono)
        self.field = QComboBox()
        self.field.addItems(["message", "raw"])
        self.field.currentIndexChanged.connect(self._changed)
        self.template = QPlainTextEdit(self.draft.template)
        self.template.setMaximumHeight(70)
        self.template.setAccessibleName("Explanation template")
        self.template.textChanged.connect(self._changed)
        self.cause = line("", "Probable cause")
        self.action = line("", "Suggested action")
        self.category = QComboBox()
        self.category.addItems(list(CATEGORIES))
        self.category.setCurrentText(self.draft.category)
        self.category.currentIndexChanged.connect(self._changed)
        self.severity = QComboBox()
        self.severity.addItems(["(keep the line's)", *SEVERITIES[1:]])
        if self.draft.severity:
            self.severity.setCurrentText(self.draft.severity)
        self.severity.currentIndexChanged.connect(self._changed)
        scope = self.draft.applies_to
        self.scoped = QCheckBox(
            "Only for " + ", ".join(v for values in scope.values() for v in values)
            if scope
            else "Applies to every source"
        )
        self.scoped.setChecked(bool(scope))
        self.scoped.setEnabled(bool(scope))
        self.scoped.toggled.connect(self._changed)
        self.counter = line(counter_line, "Counter-example")
        self.counter.setPlaceholderText("A similar line this rule must NOT explain")
        form = QFormLayout()
        form.addRow("Example line", self.example)
        form.addRow("Rule id", self.rule_id)
        form.addRow("Title", self.title_edit)
        form.addRow("Regex", self.regex)
        form.addRow("Match on", self.field)
        form.addRow("Explanation", self.template)
        hint = plain_label(
            "Use {{ name }} for a named regex group, e.g. (?P<ip>...) → {{ ip }}. "
            "In 'Suggested action' write {{ ip | shquote }}.",
            role="hint",
            wrap=True,
        )
        form.addRow("", hint)
        form.addRow("Probable cause", self.cause)
        form.addRow("Suggested action", self.action)
        form.addRow("Category", self.category)
        form.addRow("Severity", self.severity)
        form.addRow("Scope", self.scoped)
        form.addRow("Counter-example", self.counter)
        self.problems = plain_label(wrap=True)
        self.groups = QTableWidget(0, 2)
        self.groups.setHorizontalHeaderLabels(["Group", "Value"])
        self.groups.verticalHeader().hide()
        self.groups.horizontalHeader().setStretchLastSection(True)
        self.groups.setMaximumHeight(120)
        self.groups.setAccessibleName("Extracted values")
        self.rendered = plain_label(wrap=True)
        self.rendered.setObjectName("explainText")
        self.buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Save | QDialogButtonBox.StandardButton.Cancel
        )
        self.buttons.accepted.connect(self._save)
        self.buttons.rejected.connect(self.reject)
        layout = QVBoxLayout(self)
        layout.addLayout(form)
        layout.addWidget(plain_label("Preview", role="section"))
        layout.addWidget(self.problems)
        layout.addWidget(self.groups)
        layout.addWidget(self.rendered)
        layout.addWidget(self.buttons)
        self._timer = QTimer(self)
        self._timer.setSingleShot(True)
        self._timer.setInterval(200)
        self._timer.timeout.connect(self.refresh)
        self.theme = themes.DARK
        self.refresh()

    def _changed(self, *_: object) -> None:
        self._timer.start()

    def current_draft(self) -> RuleDraft:
        """The draft as the form shows it."""
        severity = self.severity.currentText()
        return replace(
            self.draft,
            rule_id=self.rule_id.text().strip(),
            title=self.title_edit.text(),
            regex=self.regex.text(),
            match_field=self.field.currentText(),
            template=self.template.toPlainText(),
            cause=self.cause.text(),
            action=self.action.text(),
            category=self.category.currentText(),
            severity="" if severity.startswith("(") else severity,
            applies_to=self.draft.applies_to if self.scoped.isChecked() else {},
            counter_example=self.counter.text(),
        )

    def refresh(self) -> None:
        """Re-run the preview (debounced while typing)."""
        draft = self.current_draft()
        counter = None
        if draft.counter_example.strip():
            record = RawRecord(self._source.id, draft.counter_example, self._entry.timestamp)
            counter = self._normalize(self._source, record)
        self.outcome = preview(draft, self._entry, self._source, counter)
        problems = list(self.outcome.problems)
        self.problems.setText(
            "\n".join(f"• {p}" for p in problems) if problems else "✓ Ready to save."
        )
        self.problems.setStyleSheet(f"color: {self.theme.error if problems else self.theme.ok};")
        self.groups.setRowCount(len(self.outcome.groups))
        for i, (name, value) in enumerate(self.outcome.groups.items()):
            self.groups.setItem(i, 0, QTableWidgetItem(name))
            self.groups.setItem(i, 1, QTableWidgetItem(value))
        exp = self.outcome.explanation
        if exp is None:
            self.rendered.setText("(no explanation yet)")
        else:
            parts = [exp.title, exp.plain_text]
            if exp.probable_cause:
                parts.append(f"Probable cause: {exp.probable_cause}")
            if exp.suggested_action:
                parts.append(f"What to do: {exp.suggested_action}")
            self.rendered.setText("\n".join(parts))
        save_btn = self.buttons.button(QDialogButtonBox.StandardButton.Save)
        if save_btn is not None:
            save_btn.setEnabled(self.outcome.ok)

    def _save(self) -> None:
        self.refresh()
        if self.outcome is None or not self.outcome.ok or self.outcome.explanation is None:
            return
        try:
            path = save(self.current_draft(), self.outcome.explanation, self._directory)
        except EditorError as exc:
            self.problems.setText("\n".join(f"• {p}" for p in exc.problems))
            self.problems.setStyleSheet(f"color: {self.theme.error};")
            return
        except OSError as exc:
            self.problems.setText(f"• Could not write the rule file: {exc}")
            return
        self.saved.emit(path)
        self.accept()


class ExportDialog(QDialog):
    """Choose what to export (view, selection or time range) and the format."""

    def __init__(self, rows: int, selected: int, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Export entries")
        self.format = QComboBox()
        for key, label in FORMATS.items():
            self.format.addItem(f"{label} (.{key})", key)
        self.scope_view = QRadioButton(f"Everything in this view ({rows:,} entries)")
        self.scope_selected = QRadioButton(f"Selected entries ({selected:,})")
        self.scope_range = QRadioButton("A time range of this view:")
        self.scope_selected.setEnabled(selected > 0)
        (self.scope_selected if selected else self.scope_view).setChecked(True)
        group = QButtonGroup(self)
        for button in (self.scope_view, self.scope_selected, self.scope_range):
            group.addButton(button)
        now = datetime.now().astimezone()
        self.since = QDateTimeEdit(QDateTime(now - timedelta(hours=1)))
        self.until = QDateTimeEdit(QDateTime(now))
        for edit in (self.since, self.until):
            edit.setCalendarPopup(True)
            edit.setDisplayFormat("yyyy-MM-dd HH:mm:ss")
        span = QHBoxLayout()
        span.addWidget(QLabel("from"))
        span.addWidget(self.since)
        span.addWidget(QLabel("to"))
        span.addWidget(self.until)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Cancel)
        export = QPushButton("Export…")
        export.setDefault(True)
        buttons.addButton(export, QDialogButtonBox.ButtonRole.AcceptRole)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        form = QFormLayout(self)
        form.addRow("Format", self.format)
        form.addRow(self.scope_view)
        form.addRow(self.scope_selected)
        form.addRow(self.scope_range)
        form.addRow(span)
        form.addRow(buttons)

    def choice(self) -> tuple[str, str, datetime | None, datetime | None]:
        """``(format, scope, since, until)``; scope is view, selected or range."""
        scope = (
            "selected"
            if self.scope_selected.isChecked()
            else "range"
            if self.scope_range.isChecked()
            else "view"
        )
        since = self.since.dateTime().toPython()
        until = self.until.dateTime().toPython()
        assert isinstance(since, datetime) and isinstance(until, datetime)  # noqa: S101
        return self.format.currentData(), scope, since.astimezone(), until.astimezone()
