"""Widgets that show understanding: the Explain panel, the Service Overview page (health,
summary, timeline, cards) and the Compose project dashboard.

All text that can come from logs or discovery is shown as plain text (never rich text).
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime

from PySide6.QtCharts import (
    QBarCategoryAxis,
    QBarSet,
    QChart,
    QChartView,
    QDateTimeAxis,
    QLineSeries,
    QScatterSeries,
    QStackedBarSeries,
    QValueAxis,
)
from PySide6.QtCore import QDateTime, QMargins, QPointF, QRectF, Qt, Signal
from PySide6.QtGui import QColor, QGuiApplication, QPainter, QPaintEvent
from PySide6.QtWidgets import (
    QComboBox,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QPlainTextEdit,
    QPushButton,
    QScrollArea,
    QSizePolicy,
    QTableWidget,
    QTableWidgetItem,
    QToolTip,
    QVBoxLayout,
    QWidget,
)

from loglens.core.models import Explanation, LogEntry, SourceStatus
from loglens.explain.overview import Bucket, CardResult, OverviewReport
from loglens.gui import theme as themes
from loglens.gui.analyst import WINDOWS, ComposeModel, OverviewModel, ServiceSummary
from loglens.security.text import printable

STATE_WORDS = {"healthy": "Healthy", "degraded": "Degraded", "failing": "Failing", "quiet": "Quiet"}
_HIDDEN_FIELD_PREFIXES = ("_", "__")


class SafeLabel(QLabel):
    """A plain-text QLabel whose ``setText`` neutralizes control and bidi characters."""

    def setText(self, text: str) -> None:
        """Set the text, made safe to display."""
        super().setText(printable(text))


def plain_label(text: str = "", *, role: str | None = None, wrap: bool = False) -> QLabel:
    """A QLabel that never interprets its text as HTML."""
    label = SafeLabel(printable(text))
    label.setTextFormat(Qt.TextFormat.PlainText)
    label.setWordWrap(wrap)
    if role:
        label.setProperty("role", role)
    return label


def _ago(when: datetime | None, now: datetime | None = None) -> str:
    if when is None:
        return ""
    now = now or datetime.now(when.tzinfo)
    seconds = int((now - when).total_seconds())
    if seconds < 60:
        return "just now"
    if seconds < 3600:
        return f"{seconds // 60} min ago"
    if seconds < 86400:
        return f"{seconds // 3600} h ago"
    return f"{seconds // 86400} days ago"


def state_color(theme: themes.Theme, state: str) -> QColor:
    """Color of a health state word."""
    return QColor(
        {"healthy": theme.ok, "degraded": theme.warning, "failing": theme.error}.get(
            state, theme.dim
        )
    )


# ---------------------------------------------------------------------- Explain panel


class ExplainPanel(QWidget):
    """Right dock: what the selected entry means, its fields and the raw line."""

    createRule = Signal(object)  # LogEntry

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.theme = themes.DARK
        self._entry: LogEntry | None = None
        self.empty = plain_label("Select a log entry to see what it means.", role="hint", wrap=True)
        self.title = plain_label(wrap=True)
        self.title.setObjectName("explainTitle")
        self.severity_chip = plain_label()
        self.severity_chip.setObjectName("chip")
        self.category_chip = plain_label()
        self.category_chip.setObjectName("chip")
        self.confidence = plain_label(role="hint")
        chips = QHBoxLayout()
        chips.addWidget(self.severity_chip)
        chips.addWidget(self.category_chip)
        chips.addWidget(self.confidence)
        chips.addStretch()
        self.text = plain_label(wrap=True)
        self.text.setObjectName("explainText")
        self.cause_head = plain_label("Probable cause", role="section")
        self.cause = plain_label(wrap=True)
        self.action_head = plain_label("What to do", role="section")
        self.action = plain_label(wrap=True)
        self.action.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        self.refs = plain_label(role="hint", wrap=True)
        self.no_rule = plain_label(
            "No rule explains this line yet. LogLens only explains what a rule recognises; "
            "it does not guess.",
            wrap=True,
        )
        self.create_btn = QPushButton("Create rule from this line…")
        self.create_btn.clicked.connect(self._create_rule)
        self.fields_head = plain_label("Fields", role="section")
        self.fields = QTableWidget(0, 2)
        self.fields.setHorizontalHeaderLabels(["Field", "Value"])
        self.fields.verticalHeader().hide()
        self.fields.horizontalHeader().setStretchLastSection(True)
        self.fields.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.fields.setAccessibleName("Fields of the selected entry")
        self.fields.setWordWrap(True)
        self.raw_head = plain_label("Raw line", role="section")
        self.raw = QPlainTextEdit()
        self.raw.setReadOnly(True)
        self.raw.setAccessibleName("Raw log line")
        self.raw.setMaximumHeight(110)
        self.copy_btn = QPushButton("Copy raw line")
        self.copy_btn.clicked.connect(
            lambda: QGuiApplication.clipboard().setText(self.raw.toPlainText())
        )
        body = QWidget()
        layout = QVBoxLayout(body)
        layout.setContentsMargins(12, 10, 12, 10)
        layout.setSpacing(6)
        layout.addWidget(self.empty)
        layout.addWidget(self.title)
        layout.addLayout(chips)
        part: QWidget
        for part in (
            self.text,
            self.no_rule,
            self.create_btn,
            self.cause_head,
            self.cause,
            self.action_head,
            self.action,
            self.refs,
            self.fields_head,
            self.fields,
            self.raw_head,
            self.raw,
            self.copy_btn,
        ):
            layout.addWidget(part)
        layout.addStretch()
        scroll = QScrollArea(self)
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setWidget(body)
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.addWidget(scroll)
        self.show_entry(None, None)

    def _create_rule(self) -> None:
        if self._entry is not None:
            self.createRule.emit(self._entry)

    def show_entry(self, entry: LogEntry | None, explanation: Explanation | None) -> None:
        """Show ``entry`` (None: the empty state)."""
        self._entry = entry
        has_entry = entry is not None
        explained = explanation is not None
        self.empty.setVisible(not has_entry)
        for widget in (self.fields_head, self.fields, self.raw_head, self.raw, self.copy_btn):
            widget.setVisible(has_entry)
        for widget in (
            self.title,
            self.severity_chip,
            self.category_chip,
            self.confidence,
            self.text,
        ):
            widget.setVisible(explained)
        self.no_rule.setVisible(has_entry and not explained)
        self.create_btn.setVisible(has_entry and not explained)
        self.cause_head.setVisible(bool(explanation and explanation.probable_cause))
        self.cause.setVisible(bool(explanation and explanation.probable_cause))
        self.action_head.setVisible(bool(explanation and explanation.suggested_action))
        self.action.setVisible(bool(explanation and explanation.suggested_action))
        self.refs.setVisible(bool(explanation and explanation.references))
        if entry is None:
            return
        if explanation is not None:
            self.title.setText(explanation.title)
            severity = explanation.severity_assessment
            glyph = themes.SEVERITY_GLYPH.get(severity) or "●"
            self.severity_chip.setText(f"{glyph} {severity.name.title()}")
            self.severity_chip.setStyleSheet(f"color: {self.theme.severity(severity).name()};")
            self.category_chip.setText(explanation.category.value.title())
            self.confidence.setText(f"confidence {explanation.confidence:.0%}")
            self.text.setText(explanation.plain_text)
            self.cause.setText(explanation.probable_cause or "")
            self.action.setText(explanation.suggested_action or "")
            self.refs.setText("See: " + ", ".join(explanation.references))
        rows = [(k, v) for k, v in (explanation.extracted.items() if explanation else ())]
        shown = {k for k, _ in rows}
        rows += [
            (k, v)
            for k, v in sorted(entry.fields.items())
            if k not in shown and not k.startswith(_HIDDEN_FIELD_PREFIXES) and not k.isupper()
        ]
        rows.insert(0, ("time", entry.timestamp.astimezone().isoformat(timespec="milliseconds")))
        rows.insert(1, ("severity", entry.severity.name.lower()))
        self.fields.setRowCount(len(rows))
        for i, (key, value) in enumerate(rows):
            self.fields.setItem(i, 0, QTableWidgetItem(printable(str(key))))
            self.fields.setItem(i, 1, QTableWidgetItem(printable(str(value))))
        self.fields.resizeRowsToContents()
        self.fields.setFixedHeight(min(26 * len(rows) + 30, 320))
        self.raw.setPlainText(printable(entry.raw))  # copying cannot carry terminal escapes


# ---------------------------------------------------------------------- timeline


class TimelineChart(QChartView):
    """Events per bucket stacked by severity, spike markers above bars; click to filter."""

    intervalClicked = Signal(object, object)  # start, end

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setRenderHint(QPainter.RenderHint.Antialiasing)
        self.setMinimumHeight(200)
        self.setMaximumHeight(260)
        self.setAccessibleName("Events per minute by severity. Click a bar to see those logs.")
        self._buckets: tuple[Bucket, ...] = ()
        self.theme = themes.DARK
        self.setChart(QChart())

    def set_buckets(self, buckets: Sequence[Bucket], theme: themes.Theme) -> None:
        """Rebuild the chart (a few dozen bars: cheap)."""
        self.theme = theme
        self._buckets = tuple(buckets)
        chart = QChart()
        chart.setAnimationOptions(QChart.AnimationOption.NoAnimation)
        chart.setBackgroundBrush(QColor(theme.canvas))
        chart.setMargins(QMargins(4, 4, 4, 4))
        chart.legend().setLabelColor(QColor(theme.dim))
        chart.legend().setAlignment(Qt.AlignmentFlag.AlignTop)
        series = QStackedBarSeries()
        series.setBarWidth(0.85)
        other = QColor(theme.dim)
        other.setAlpha(110)
        colors = (QColor(theme.critical), QColor(theme.error), QColor(theme.warning), other)
        for index, label in enumerate(("Critical", "Error", "Warning", "Other")):
            bar_set = QBarSet(label)
            bar_set.setColor(colors[index])
            bar_set.setBorderColor(colors[index])
            bar_set.append([float(b.counts[index]) for b in buckets])
            bar_set.clicked.connect(self._clicked)
            bar_set.hovered.connect(self._hovered)
            series.append(bar_set)
        chart.addSeries(series)
        # Bars sit on a hidden category axis (one slot per bucket); a date-time axis over the
        # same span carries readable time labels (category labels would be elided to "…").
        axis_x = QBarCategoryAxis()
        axis_x.append([str(i) for i in range(len(buckets))])
        axis_x.setVisible(False)
        axis_time = QDateTimeAxis()
        axis_time.setTickCount(7)
        span = (buckets[-1].end - buckets[0].start).total_seconds() if buckets else 3600
        axis_time.setFormat("HH:mm:ss" if span <= 1800 else "HH:mm")
        axis_time.setLabelsColor(QColor(theme.dim))
        axis_time.setGridLineVisible(False)
        if buckets:
            axis_time.setRange(
                QDateTime(buckets[0].start.astimezone()), QDateTime(buckets[-1].end.astimezone())
            )
        axis_y = QValueAxis()
        top = max((b.total for b in buckets), default=0)
        axis_y.setRange(0, max(4, top * 1.15))
        axis_y.setLabelFormat("%d")
        axis_y.setLabelsColor(QColor(theme.dim))
        axis_y.setGridLineColor(QColor(theme.border))
        chart.addAxis(axis_x, Qt.AlignmentFlag.AlignBottom)
        chart.addAxis(axis_time, Qt.AlignmentFlag.AlignBottom)
        chart.addAxis(axis_y, Qt.AlignmentFlag.AlignLeft)
        series.attachAxis(axis_x)
        series.attachAxis(axis_y)
        anchor = QLineSeries()  # invisible: gives the time axis a series to scale
        if buckets:
            anchor.append(QDateTime(buckets[0].start.astimezone()).toMSecsSinceEpoch(), 0)
            anchor.append(QDateTime(buckets[-1].end.astimezone()).toMSecsSinceEpoch(), 0)
        anchor.setColor(QColor(0, 0, 0, 0))
        chart.addSeries(anchor)
        anchor.attachAxis(axis_time)
        anchor.attachAxis(axis_y)
        for marker in chart.legend().markers(anchor):
            marker.setVisible(False)
        spikes = [(i, b) for i, b in enumerate(buckets) if b.spike]
        if spikes:
            marks = QScatterSeries()
            marks.setName("Spike")
            marks.setMarkerShape(QScatterSeries.MarkerShape.MarkerShapeTriangle)
            marks.setMarkerSize(11)
            marks.setColor(QColor(theme.error))
            marks.setBorderColor(QColor(theme.canvas))
            for i, b in spikes:
                marks.append(QPointF(i, b.total + max(1.0, top * 0.06)))
            chart.addSeries(marks)
            hidden_x = QValueAxis()
            hidden_x.setRange(-0.5, len(buckets) - 0.5)
            hidden_x.setVisible(False)
            chart.addAxis(hidden_x, Qt.AlignmentFlag.AlignTop)
            marks.attachAxis(hidden_x)
            marks.attachAxis(axis_y)
        self.setChart(chart)

    def _clicked(self, index: int) -> None:
        if 0 <= index < len(self._buckets):
            bucket = self._buckets[index]
            self.intervalClicked.emit(bucket.start, bucket.end)

    def _hovered(self, status: bool, index: int) -> None:
        if not status or not 0 <= index < len(self._buckets):
            QToolTip.hideText()
            return
        b = self._buckets[index]
        text = (
            f"{b.start.astimezone():%H:%M:%S} to {b.end.astimezone():%H:%M:%S}\n"
            f"{b.total} entries: {b.counts[0]} critical, {b.counts[1]} errors, "
            f"{b.counts[2]} warnings{' · spike' if b.spike else ''}\nClick to see these logs"
        )
        QToolTip.showText(self.cursor().pos(), text, self)


# ---------------------------------------------------------------------- cards


class _TopRows(QWidget):
    """Value / count rows with a proportional bar behind each (painted)."""

    def __init__(self, rows: Sequence[tuple[str, ...]], theme: themes.Theme) -> None:
        super().__init__()
        self._rows = list(rows)
        self._theme = theme
        self.setMinimumHeight(22 * max(len(rows), 1))
        self.setAccessibleName(", ".join(f"{r[0]}: {r[1]}" for r in rows))

    def paintEvent(self, event: QPaintEvent) -> None:
        painter = QPainter(self)
        t = self._theme
        counts = [int(r[1].replace(",", "")) for r in self._rows] or [1]
        biggest = max(counts) or 1
        fm = painter.fontMetrics()
        for i, (row, count) in enumerate(zip(self._rows, counts, strict=True)):
            y = i * 22
            bar = QColor(t.accent)
            bar.setAlpha(45)
            painter.fillRect(QRectF(0, y + 2, (self.width() - 2) * count / biggest, 18), bar)
            painter.setPen(QColor(t.text))
            value = fm.elidedText(
                printable(row[0]), Qt.TextElideMode.ElideMiddle, self.width() - 70
            )
            painter.drawText(
                QRectF(6, y, self.width() - 70, 22), Qt.AlignmentFlag.AlignVCenter, value
            )
            painter.setPen(QColor(t.dim))
            painter.drawText(
                QRectF(0, y, self.width() - 6, 22),
                Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignRight,
                row[1],
            )


class CardWidget(QFrame):
    """One overview card (declared in a rule pack)."""

    def __init__(
        self, card: CardResult, theme: themes.Theme, parent: QWidget | None = None
    ) -> None:
        super().__init__(parent)
        self.setObjectName("card")
        self.card = card
        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 10, 12, 10)
        head = QHBoxLayout()
        title = plain_label(card.title)
        title.setObjectName("cardTitle")
        head.addWidget(title)
        head.addStretch()
        if card.warn:
            flag = plain_label("▲ attention")
            flag.setStyleSheet(f"color: {theme.error};")
            head.addWidget(flag)
        layout.addLayout(head)
        self.setAccessibleName(f"{card.title} card")
        if card.kind == "count":
            number = plain_label(f"{card.total:,}")
            number.setObjectName("cardNumber")
            if card.warn:
                number.setStyleSheet(f"color: {theme.error};")
            layout.addWidget(number)
            layout.addWidget(plain_label("entries in this period", role="hint"))
        elif not card.rows:
            layout.addWidget(plain_label(card.empty, role="hint", wrap=True))
        elif card.kind == "top":
            layout.addWidget(_TopRows(card.rows, theme))
        else:
            for row in card.rows:
                time_label = plain_label(row[0], role="hint")
                what = plain_label(row[1], wrap=True)
                extra = [c for c in row[2:] if c]
                line = QHBoxLayout()
                line.addWidget(time_label, 0, Qt.AlignmentFlag.AlignTop)
                column = QVBoxLayout()
                column.addWidget(what)
                if extra:
                    column.addWidget(plain_label(" · ".join(extra), role="hint", wrap=True))
                line.addLayout(column, 1)
                layout.addLayout(line)
        layout.addStretch()
        self.setSizePolicy(QSizePolicy.Policy.Preferred, QSizePolicy.Policy.Maximum)


# ---------------------------------------------------------------------- overview page


class OverviewPage(QWidget):
    """Health header, what's happening, timeline and cards for a source or group."""

    openLogs = Signal(object)  # tuple of source ids
    intervalClicked = Signal(object, object, object)  # source ids, start, end

    def __init__(self, model: OverviewModel, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.model = model
        self.theme = themes.DARK
        self.state = plain_label("…")
        self.state.setObjectName("stateWord")
        self.heading = plain_label(model.title)
        self.heading.setObjectName("pageTitle")
        self.facts = plain_label(role="hint", wrap=True)
        self.reasons = plain_label(wrap=True)
        self.period = QComboBox()
        self.period.setAccessibleName("Period")
        for key in WINDOWS:
            self.period.addItem(
                {
                    "15m": "Last 15 minutes",
                    "1h": "Last hour",
                    "6h": "Last 6 hours",
                    "24h": "Last 24 hours",
                }[key],
                key,
            )
        self.period.setCurrentIndex(list(WINDOWS).index(model.window))
        self.period.activated.connect(lambda _: model.set_window(self.period.currentData()))
        logs = QPushButton("Open logs")
        logs.clicked.connect(lambda: self.openLogs.emit(model.source_ids))
        header = QGridLayout()
        header.addWidget(self.state, 0, 0)
        header.addWidget(self.heading, 0, 1)
        header.addWidget(self.period, 0, 2, Qt.AlignmentFlag.AlignRight)
        header.addWidget(logs, 0, 3)
        header.addWidget(self.facts, 1, 0, 1, 4)
        header.addWidget(self.reasons, 2, 0, 1, 4)
        header.setColumnStretch(1, 1)
        self.summary_head = plain_label("What's happening", role="section")
        self.summary = plain_label("Collecting entries…", wrap=True)
        self.summary.setObjectName("summary")
        self.chart = TimelineChart()
        self.chart.intervalClicked.connect(
            lambda a, b: self.intervalClicked.emit(model.source_ids, a, b)
        )
        self.cards = QGridLayout()
        self.cards.setSpacing(10)
        self.footer = plain_label(role="hint", wrap=True)
        body = QWidget()
        layout = QVBoxLayout(body)
        layout.setContentsMargins(18, 14, 18, 14)
        layout.setSpacing(10)
        layout.addLayout(header)
        layout.addWidget(self.summary_head)
        layout.addWidget(self.summary)
        layout.addWidget(self.chart)
        layout.addLayout(self.cards)
        layout.addWidget(self.footer)
        layout.addStretch()
        scroll = QScrollArea(self)
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setWidget(body)
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.addWidget(scroll)
        model.reportChanged.connect(self.show_report)
        if model.report is not None:
            self.show_report(model.report)

    def set_theme(self, theme: themes.Theme) -> None:
        """Restyle (re-renders the last report)."""
        self.theme = theme
        if self.model.report is not None:
            self.show_report(self.model.report)

    def show_report(self, report: OverviewReport) -> None:
        """Show a report (called at most once per second by the model)."""
        t = self.theme
        h = report.health
        self.state.setText(f"● {STATE_WORDS[h.state]}")
        self.state.setStyleSheet(f"color: {state_color(t, h.state).name()};")
        status = {
            SourceStatus.RUNNING: "running",
            SourceStatus.STOPPED: "stopped",
            SourceStatus.FAILED: "failed",
            SourceStatus.UNKNOWN: "status unknown",
        }[h.status]
        facts = [status]
        if h.last_restart is not None:
            facts.append(
                f"restarted {h.restarts} times · last "
                f"{h.last_restart.astimezone():%H:%M:%S} ({_ago(h.last_restart)})"
            )
        else:
            facts.append("no restart in this period")
        usual = (
            f" (usually {h.baseline_error_rate:.1%})" if h.baseline_error_rate is not None else ""
        )
        facts.append(f"errors {h.error_rate:.1%} of the last 5 min{usual}")
        if h.last_error is not None:
            facts.append(f"last error {h.last_error.astimezone():%H:%M:%S}: {h.last_error_text}")
        else:
            facts.append("no errors in this period")
        self.facts.setText("   ·   ".join(facts))
        self.reasons.setText(("Why: " + "; ".join(h.reasons) + ".") if h.reasons else "")
        self.reasons.setStyleSheet(f"color: {state_color(t, h.state).name()};")
        self.reasons.setVisible(bool(h.reasons))
        self.summary.setText(report.summary)
        self.chart.set_buckets(report.timeline, t)
        while self.cards.count():
            item = self.cards.takeAt(0)
            if item is not None and (widget := item.widget()) is not None:
                widget.deleteLater()
        for i, card in enumerate(report.cards):
            self.cards.addWidget(CardWidget(card, t), i // 3, i % 3, Qt.AlignmentFlag.AlignTop)
        packs = ", ".join(report.packs) or "none (no rule pack describes this service yet)"
        sampled = f" Cards use the newest {report.analyzed:,} entries." if report.capped else ""
        self.footer.setText(f"Cards from rule packs: {packs}.{sampled}")


# ---------------------------------------------------------------------- compose dashboard


class ServiceTile(QFrame):
    """One service of a Compose project."""

    openLogs = Signal(str)
    openOverview = Signal(str)

    def __init__(self, summary: ServiceSummary, theme: themes.Theme) -> None:
        super().__init__()
        self.setObjectName("tile")
        source = summary.source
        name = str(source.metadata.get("compose_service") or source.display_name)
        self.setAccessibleName(f"{name}, {source.status.value}")
        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 10, 12, 10)
        title = plain_label(name)
        title.setObjectName("cardTitle")
        title.setStyleSheet(f"color: {theme.series_color(name).name()};")
        shape = {
            SourceStatus.RUNNING: ("●", theme.ok),
            SourceStatus.FAILED: ("✕", theme.error),
        }.get(source.status, ("○", theme.dim))
        status = plain_label(f"{shape[0]} {source.status.value}")
        status.setStyleSheet(f"color: {shape[1]};")
        head = QHBoxLayout()
        head.addWidget(title)
        head.addStretch()
        head.addWidget(status)
        layout.addLayout(head)
        layout.addWidget(plain_label(f"{source.metadata.get('image', '')}", role="hint"))
        stats = plain_label(
            f"{summary.restarts} restart{'s' if summary.restarts != 1 else ''} · "
            f"{summary.errors} error{'s' if summary.errors != 1 else ''} in the last hour"
        )
        if summary.restarts >= 3:
            stats.setStyleSheet(f"color: {theme.warning};")
        layout.addWidget(stats)
        if summary.last_error is not None:
            last = plain_label(
                f"Last error {summary.last_error.astimezone():%H:%M:%S}: {summary.last_error_text}",
                wrap=True,
            )
            last.setStyleSheet(f"color: {theme.error};")
            layout.addWidget(last)
        for hint in summary.hints:
            layout.addWidget(plain_label(f"↳ {hint}", role="hint", wrap=True))
        buttons = QHBoxLayout()
        logs = QPushButton("Logs")
        logs.setAccessibleName(f"Logs of {name}")
        logs.clicked.connect(lambda: self.openLogs.emit(source.id))
        overview = QPushButton("Overview")
        overview.setAccessibleName(f"Overview of {name}")
        overview.clicked.connect(lambda: self.openOverview.emit(source.id))
        buttons.addWidget(logs)
        buttons.addWidget(overview)
        buttons.addStretch()
        layout.addLayout(buttons)


class ComposeDashboard(QWidget):
    """Every service of a Compose project at a glance."""

    openLogs = Signal(str)
    openOverview = Signal(str)
    openAll = Signal()

    def __init__(self, model: ComposeModel, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.model = model
        self.theme = themes.DARK
        self.heading = plain_label(f"Compose project: {model.title}")
        self.heading.setObjectName("pageTitle")
        self.counts = plain_label(role="hint")
        all_logs = QPushButton("All logs merged")
        all_logs.clicked.connect(self.openAll.emit)
        head = QHBoxLayout()
        head.addWidget(self.heading)
        head.addStretch()
        head.addWidget(self.counts)
        head.addWidget(all_logs)
        self.grid = QGridLayout()
        self.grid.setSpacing(10)
        body = QWidget()
        layout = QVBoxLayout(body)
        layout.setContentsMargins(18, 14, 18, 14)
        layout.addLayout(head)
        layout.addLayout(self.grid)
        layout.addStretch()
        scroll = QScrollArea(self)
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setWidget(body)
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.addWidget(scroll)
        model.servicesChanged.connect(self.show_services)

    def set_theme(self, theme: themes.Theme) -> None:
        """Restyle."""
        self.theme = theme
        self.show_services(self.model.services)

    def show_services(self, services: Sequence[ServiceSummary]) -> None:
        """Show the service tiles."""
        while self.grid.count():
            item = self.grid.takeAt(0)
            if item is not None and (widget := item.widget()) is not None:
                widget.deleteLater()
        for i, summary in enumerate(services):
            tile = ServiceTile(summary, self.theme)
            tile.openLogs.connect(self.openLogs.emit)
            tile.openOverview.connect(self.openOverview.emit)
            self.grid.addWidget(tile, i // 3, i % 3, Qt.AlignmentFlag.AlignTop)
        running = sum(1 for s in services if s.source.status == SourceStatus.RUNNING)
        failed = sum(1 for s in services if s.source.status == SourceStatus.FAILED)
        self.counts.setText(f"{len(services)} services · {running} running · {failed} failed")
