"""Timeline: entries over time for everything followed (the Overview page's stacked
severity chart, with spike markers), the notable moments and the busiest sources."""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING

from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QButtonGroup,
    QGridLayout,
    QHBoxLayout,
    QPushButton,
    QTableWidgetItem,
)

from loglens.core.models import Severity
from loglens.gui.analyst import WINDOWS
from loglens.gui.dashboard.base import DashPage, table
from loglens.gui.dashboard.model import Dashboard
from loglens.gui.dashboard.widgets import Card, ShareRows
from loglens.gui.insight_widgets import TimelineChart
from loglens.gui.theme import SEVERITY_GLYPH

if TYPE_CHECKING:
    from loglens.gui.main_window import MainWindow

PERIODS = {"15m": "15 min", "1h": "1 h", "6h": "6 h", "24h": "24 h"}
#: Rule tags that make an entry notable whatever its severity.
NOTABLE_TAGS = frozenset({"restart", "restart_loop", "detection"})
MOMENTS = 8


def notable(d: Dashboard) -> list[tuple[datetime, Severity, str, str]]:
    """(when, severity, what happened, source id or ''), newest first: warnings and worse,
    restarts and detections, plus every error spike on the timeline."""
    rows = [
        (m.when, m.severity, m.title + (f"  (\u00d7{m.count})" if m.count > 1 else ""), m.source_id)
        for m in d.latest
        if m.severity >= Severity.WARNING or NOTABLE_TAGS.intersection(m.tags)
    ]
    rows += [
        (b.start, Severity.ERROR, f"Error spike: {b.errors:,} errors in one interval", "")
        for b in d.timeline
        if b.spike
    ]
    return sorted(rows, key=lambda r: r[0], reverse=True)[:MOMENTS]


class TimelinePage(DashPage):
    """What happened, when."""

    def __init__(self, window: MainWindow) -> None:
        super().__init__(
            window,
            "Timeline",
            "What happened, when, across every followed source",
            "Search all logs",
            "Open these logs",
        )
        self.header.action.clicked.connect(self.open_period)
        self.chart = TimelineChart()
        self.chart.setMinimumHeight(260)
        self.chart.intervalClicked.connect(self._open_interval)
        self.periods = QButtonGroup(self)
        segments = QHBoxLayout()
        segments.setSpacing(6)
        for key, text in PERIODS.items():
            button = QPushButton(text)
            button.setObjectName("segment")
            button.setCheckable(True)
            button.setChecked(key == window.dashboard.window)
            button.setAccessibleName(f"Show the last {text}")
            button.clicked.connect(lambda _=False, k=key: window.dashboard.set_window(k))
            self.periods.addButton(button)
            segments.addWidget(button)
        chart_card = Card("Events over time", "")
        chart_card.head.addLayout(segments)
        chart_card.body.addWidget(self.chart)
        self.moments = table(["What happened", "Service", "Time"])
        self.moments.cellClicked.connect(self._open_moment)
        self.moments.cellActivated.connect(self._open_moment)
        moments_card = Card("Notable moments", "Newest first")
        moments_card.body.addWidget(self.moments)
        self.busiest = ShareRows()
        self.busiest.clicked.connect(window.open_source)
        busiest_card = Card("Busiest sources", "Last 24 h")
        busiest_card.body.addWidget(self.busiest)
        busiest_card.body.addStretch()
        grid = QGridLayout()
        grid.setSpacing(20)
        grid.addWidget(chart_card, 0, 0, 1, 3)
        grid.addWidget(moments_card, 1, 0, 1, 2)
        grid.addWidget(busiest_card, 1, 2)
        for column in range(3):
            grid.setColumnStretch(column, 1)
        self.body.addLayout(grid, 1)
        self._sources: list[str] = []
        window.dashboard.changed.connect(lambda _: self.refresh())

    def refresh(self) -> None:
        """Render the last dashboard."""
        d = self.w.dashboard.dashboard
        if d is None:
            return
        self.chart.set_buckets(d.timeline, self.colors)
        names = self.w.tree_model.display_names()
        self.busiest.set_rows([(sid, names.get(sid, sid), n) for sid, n in d.busiest])
        rows = notable(d)
        self.moments.setRowCount(max(1, len(rows)))
        self._sources = [r[3] for r in rows]
        if not rows:
            self.moments.setItem(0, 0, QTableWidgetItem("Nothing notable in the last 24 hours."))
            for column in (1, 2):
                self.moments.setItem(0, column, QTableWidgetItem(""))
            return
        for row, (when, severity, text, source_id) in enumerate(rows):
            glyph = SEVERITY_GLYPH.get(severity) or "·"
            what = QTableWidgetItem(f"{glyph}  {text}")
            what.setForeground(self.colors.severity(severity))
            what.setToolTip(text)
            service = QTableWidgetItem(names.get(source_id, source_id) if source_id else "all")
            stamp = QTableWidgetItem(when.astimezone().strftime("%H:%M"))
            stamp.setForeground(QColor(self.colors.dim))
            for column, item in enumerate((what, service, stamp)):
                self.moments.setItem(row, column, item)

    def _followed(self) -> tuple[str, ...]:
        return tuple(sorted(self.w._follow_refs))

    def _open_interval(self, start: datetime, end: datetime) -> None:
        if ids := self._followed():
            self.w.insights._open_interval(ids, start, end)

    def _open_moment(self, row: int, _column: int = 0) -> None:
        if 0 <= row < len(self._sources) and self._sources[row]:
            self.w.open_source(self._sources[row])

    def open_period(self) -> None:
        """Every followed source, merged, over the period on screen."""
        d = self.w.dashboard.dashboard
        span, _ = WINDOWS[self.w.dashboard.window]
        if d is not None:
            self._open_interval(d.now - span, d.now)
