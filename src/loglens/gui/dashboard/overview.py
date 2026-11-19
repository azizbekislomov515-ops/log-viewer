"""Overview: four figures, the event rate, entries by source kind, errors per day and the
latest explanations, for everything LogLens follows."""

from __future__ import annotations

from typing import TYPE_CHECKING

from PySide6.QtGui import QColor, QGuiApplication
from PySide6.QtWidgets import QGridLayout, QHBoxLayout, QTableWidgetItem

from loglens.core.models import SourceStatus
from loglens.gui.dashboard.base import SEVERITY_WORDS, DashPage, table
from loglens.gui.dashboard.model import Dashboard
from loglens.gui.dashboard.widgets import Card, DayBars, Donut, Kpi, RateChart
from loglens.gui.log_model import plain_tooltip
from loglens.security.redact import Redactor
from loglens.security.text import printable

if TYPE_CHECKING:
    from loglens.gui.main_window import MainWindow

KIND_NAMES = {"systemd": "journald", "docker": "Docker", "file": "Log files"}


def kind_name(kind: str) -> str:
    """Display name of a stored source kind (``docker_container`` counts as Docker)."""
    return KIND_NAMES.get(kind.split("_", 1)[0], kind)


def delta(now: float, before: float) -> str:
    """'+12%' style change, or '' when there is nothing to compare with."""
    if not before:
        return ""
    change = (now - before) / before
    return f"{change:+.0%}"


class OverviewPage(DashPage):
    """The landing page."""

    def __init__(self, window: MainWindow) -> None:
        super().__init__(
            window,
            "Overview",
            "Everything LogLens follows on this machine, last 24 hours",
            "Search all logs",
            "Copy summary",
        )
        self.header.action.clicked.connect(self.copy_summary)
        self.rate = Kpi("Events per minute")
        self.errors = Kpi("Errors, 24 h")
        self.followed = Kpi("Sources followed")
        self.healthy = Kpi("Healthy services")
        kpis = QHBoxLayout()
        kpis.setSpacing(20)
        for kpi in (self.rate, self.errors, self.followed, self.healthy):
            kpis.addWidget(kpi)
        self.chart = RateChart()
        rate_card = Card("Event rate", "All entries, and errors (dashed), per hour")
        rate_card.body.addWidget(self.chart)
        self.donut = Donut()
        kind_card = Card("Events by source")
        kind_card.body.addWidget(self.donut)
        self.days = DayBars()
        days_card = Card("Errors per day", "Last 7 days")
        days_card.body.addWidget(self.days)
        self.latest = table(["What happened", "Service", "Time", "Severity", "Count"])
        self.latest.setMinimumHeight(40 * 7)
        self.latest.cellActivated.connect(self._open_row)
        self.latest.cellClicked.connect(self._open_row)
        latest_card = Card("Latest explanations", "Click a row to see its logs")
        latest_card.body.addWidget(self.latest)
        grid = QGridLayout()
        grid.setSpacing(20)
        grid.addWidget(rate_card, 0, 0, 1, 3)
        grid.addWidget(kind_card, 0, 3)
        grid.addWidget(days_card, 1, 0)
        grid.addWidget(latest_card, 1, 1, 1, 3)
        for column in range(4):
            grid.setColumnStretch(column, 1)
        self.body.addLayout(kpis)
        self.body.addLayout(grid, 1)
        self._rows: list[str] = []
        window.dashboard.changed.connect(lambda _: self.refresh())

    def refresh(self) -> None:
        """Figures from discovery and the backend now; the rest from the last dashboard."""
        t, w = self.colors, self.w
        sources = w.tree_model.sources()
        self.followed.set_value(f"{len(w._follow_refs):,}", f"of {len(sources):,} found", t.accent)
        services = [s for s in sources if s.status != SourceStatus.UNKNOWN]
        running = sum(s.status == SourceStatus.RUNNING for s in services)
        failed = sum(s.status == SourceStatus.FAILED for s in services)
        self.healthy.set_value(
            f"{running} / {len(services)}" if services else "-",
            f"{failed} failed" if failed else ("all running" if services else ""),
            t.error if failed else t.ok,
        )
        d = w.dashboard.dashboard
        if d is None:
            return
        self.rate.set_value(
            f"{d.per_minute:,.0f}" if d.per_minute >= 10 else f"{d.per_minute:.1f}",
            delta(d.per_minute, d.per_minute_before),
            t.accent,
        )
        self.errors.set_value(
            f"{d.errors_24h:,}",
            f"{d.errors_24h - d.errors_before:+,}" if d.errors_before else "",
            t.error if d.errors_24h > d.errors_before else t.ok,
        )
        self.chart.set_points(d.hourly)
        kinds: dict[str, int] = {}
        for kind, n in d.by_kind.items():
            kinds[kind_name(kind)] = kinds.get(kind_name(kind), 0) + n
        palette = (t.accent, t.series[1], t.series[2], t.series[3])
        ordered = sorted(kinds.items())
        self.donut.set_parts([(name, n, palette[i % 4]) for i, (name, n) in enumerate(ordered)])
        self.days.set_days(d.daily_errors)
        self._fill_latest(d)

    def _fill_latest(self, d: Dashboard) -> None:
        names = self.w.tree_model.display_names()
        moments = d.latest[:6]
        self.latest.setRowCount(len(moments))
        self._rows = [m.source_id for m in moments]
        for row, m in enumerate(moments):
            word = SEVERITY_WORDS.get(m.severity.name, m.severity.name.title())
            cells = (
                m.title,
                names.get(m.source_id, m.source_id),
                m.when.astimezone().strftime("%H:%M"),
                word,
                f"\u00d7{m.count:,}",
            )
            for column, text in enumerate(cells):
                item = QTableWidgetItem(text)
                item.setToolTip(plain_tooltip(text) if column == 0 else "")
                if column == 3:
                    item.setForeground(self.colors.severity(m.severity))
                if column == 2:
                    item.setForeground(QColor(self.colors.dim))
                self.latest.setItem(row, column, item)
        if not moments:
            self.latest.setRowCount(1)
            self.latest.setItem(
                0, 0, QTableWidgetItem("Nothing a rule recognized in the last 24 hours yet.")
            )
            self._rows = []

    def _open_row(self, row: int, _column: int = 0) -> None:
        if 0 <= row < len(self._rows):
            self.w.open_source(self._rows[row])

    def summary_text(self) -> str:
        """The page as Markdown (redacted again and stripped of control characters)."""
        d = self.w.dashboard.dashboard
        if d is None:
            return "# LogLens overview\n\nNo data yet.\n"
        names = self.w.tree_model.display_names()
        lines = [
            f"# LogLens overview, {d.now.astimezone():%Y-%m-%d %H:%M}",
            "",
            f"* Events per minute: {d.per_minute:,.1f}",
            f"* Errors in the last 24 h: {d.errors_24h:,} (24 h before: {d.errors_before:,})",
            f"* Entries in the last 24 h: {d.total_24h:,}",
            "",
            "## Latest explanations",
            "",
        ]
        lines += [
            f"* {m.when.astimezone():%H:%M} [{m.severity.name}] "
            f"{names.get(m.source_id, m.source_id)}: {m.title} (\u00d7{m.count})"
            for m in d.latest
        ] or ["* none"]
        text, _ = Redactor(self.w.settings.redact_patterns).redact("\n".join(lines) + "\n")
        return printable(text)

    def copy_summary(self) -> None:
        """Copy ``summary_text`` to the clipboard."""
        QGuiApplication.clipboard().setText(self.summary_text())
        self.w.statusBar().showMessage("Copied the overview as Markdown", 5000)
