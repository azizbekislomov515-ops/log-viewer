"""The window's "explain what is happening" features (Phase 6), in a controller the
window owns (``window.insights``): the Explain dock, inline explanations,
Overview and Compose dashboard pages, notifications, the rule editor, export and incident
reports.
"""

from __future__ import annotations

import logging
from collections.abc import Sequence
from dataclasses import replace
from datetime import datetime
from itertools import batched
from pathlib import Path
from typing import TYPE_CHECKING, Any

from PySide6.QtCore import QModelIndex, Qt
from PySide6.QtGui import QAction, QGuiApplication
from PySide6.QtWidgets import QDockWidget, QFileDialog, QWidget

from loglens.core.models import Explanation, LogEntry, LogSource
from loglens.explain.editor import user_rules_dir
from loglens.export import incident_report, write_entries
from loglens.gui.analyst import (
    Analyst,
    ComposeModel,
    LiveExplainer,
    OverviewModel,
    make_engine,
)
from loglens.gui.dialogs import ExportDialog, RuleEditorDialog
from loglens.gui.insight_widgets import ComposeDashboard, ExplainPanel, OverviewPage
from loglens.gui.notify import DesktopNotifier, NotificationCenter
from loglens.storage import Storage

if TYPE_CHECKING:
    from loglens.gui.log_view import LogView
    from loglens.gui.main_window import MainWindow

log = logging.getLogger(__name__)
#: Incident reports explain at most this many selected entries.
REPORT_LIMIT = 500


class Insights:
    """Owns the Explain dock, pages and notifications; ``w`` is the window."""

    def __init__(self, window: MainWindow) -> None:
        self.w = window
        self.engine = make_engine(self.w.settings)
        self.analyst = Analyst(lambda: make_engine(self.w.settings))
        self.explain_panel = ExplainPanel(self.w)
        self.explain_panel.createRule.connect(self.create_rule)
        dock = QDockWidget("Explain", self.w)
        dock.setObjectName("explainDock")
        dock.setWidget(self.explain_panel)
        dock.setMinimumWidth(320)
        self.w.addDockWidget(Qt.DockWidgetArea.RightDockWidgetArea, dock)
        self.explain_dock = dock
        self.center = NotificationCenter(self.w.settings.notify_on, self.w.settings.muted)
        self.notifier = DesktopNotifier()
        self.live_explainer = LiveExplainer(
            self.w.analytics,
            self.analyst,
            self.center,
            self.notifier,
            sources=lambda: {s.id: s for s in self.w.tree_model.sources()},
            parent=self.w,
        )
        self.live_explainer.notified.connect(
            lambda note: self.w.statusBar().showMessage(f"Notified: {note.summary}", 6000)
        )
        self.live_explainer.unavailable.connect(
            lambda msg: self.w.statusBar().showMessage(msg, 10000)
        )
        self._pages: list[OverviewPage | ComposeDashboard] = []

    # ------------------------------------------------------------------ explain panel

    def _explain_row(self, view: LogView, current: QModelIndex) -> None:
        entry = view.model.entry_at(current.row()) if current.isValid() else None
        if entry is None:
            self.explain_panel.show_entry(None, None)
            return
        self.explain_panel.show_entry(entry, self.explain(entry))

    def explain(self, entry: LogEntry) -> Explanation | None:
        """The GUI thread's explanation of one entry (single entries and visible rows)."""
        return self.engine.explain(entry, self.w.tree_model.source(entry.source_id))

    def set_inline_mode(self, mode: str) -> None:
        """off / compact / full explanations under rows, for every tab."""
        self.w.settings = replace(self.w.settings, inline_explanations=mode)
        for tab in self.w._all_tabs():
            for view in tab.views:
                self._apply_inline(view)
        with_signals = self.w.inline_btn.blockSignals(True)
        self.w.inline_btn.setChecked(mode != "off")
        self.w.inline_btn.blockSignals(with_signals)
        self.w._save_settings()

    def _apply_inline(self, view: LogView) -> None:
        mode = self.w.settings.inline_explanations
        view.model.set_explainer(self.explain if mode != "off" else None, mode)
        view.set_inline(mode)

    def _toggle_inline(self, on: bool) -> None:
        current = self.w.settings.inline_explanations
        self.set_inline_mode(("full" if current == "off" else current) if on else "off")

    # ------------------------------------------------------------------ rule editor

    def create_rule(self, entry: LogEntry) -> None:
        """Open the rule editor for an unexplained line."""
        source = self.w.tree_model.source(entry.source_id)
        if source is None:
            from loglens.collectors import source_from_id  # noqa: PLC0415

            source = source_from_id(entry.source_id)
        dialog = RuleEditorDialog(entry, source, self._counter_line(entry), parent=self.w)
        dialog.theme = self.w._theme
        dialog.refresh()
        dialog.saved.connect(self._rules_changed)
        dialog.exec()

    def _counter_line(self, entry: LogEntry) -> str:
        """A nearby line of the same source with a different message (a counter-example)."""
        tab = self.w._tab()
        if tab is None:
            return ""
        model = tab.view.model
        row = model.row_of(entry.id)
        if row is None:
            return ""
        for step in (-1, 1, -2, 2, -3, 3, -5, 5):
            other = model.entry_at(row + step)
            if other and other.source_id == entry.source_id and other.message != entry.message:
                return other.raw
        return ""

    def _rules_changed(self, path: Path) -> None:
        self.engine = make_engine(self.w.settings)
        self.analyst.reload()
        for tab in self.w._all_tabs():
            for view in tab.views:
                self._apply_inline(view)
        current = self.w._tab()
        if current is not None:
            self._explain_row(current.view, current.view.tree.currentIndex())
        self.w.statusBar().showMessage(f"Rule saved to {path}", 8000)

    # ------------------------------------------------------------------ overview pages

    def open_overview(
        self, source_ids: Sequence[str], title: str | None = None
    ) -> OverviewPage | None:
        """Show the Service Overview for one source or a group."""
        sources = [s for sid in source_ids if (s := self.w.tree_model.source(sid)) is not None]
        if not sources:
            return None
        for page in self._pages:
            if isinstance(page, OverviewPage) and page.model.source_ids == tuple(
                s.id for s in sources
            ):
                self.w.tabs.setCurrentWidget(page)
                return page
        name = title or (sources[0].display_name if len(sources) == 1 else "group")
        model = OverviewModel(self.w.analytics, self.analyst, name, sources, parent=self.w)
        page = OverviewPage(model)
        page.set_theme(self.w._theme)
        page.openLogs.connect(self._open_ids)
        page.intervalClicked.connect(self._open_interval)
        self._add_page(page, f"Overview: {name}", sources)
        model.refresh()
        return page

    def open_dashboard(self, group_id: str) -> ComposeDashboard | None:
        """Show the Compose project dashboard."""
        group = self.w.tree_model.group(group_id)
        if group is None:
            return None
        for page in self._pages:
            if isinstance(page, ComposeDashboard) and page.model.title == group.name:
                self.w.tabs.setCurrentWidget(page)
                return page
        model = ComposeModel(
            self.w.analytics, self.analyst, group.name, list(group.sources), parent=self.w
        )
        page = ComposeDashboard(model)
        page.set_theme(self.w._theme)
        page.openLogs.connect(self.w.open_source)
        page.openOverview.connect(lambda sid: self.open_overview([sid]))
        page.openAll.connect(lambda: self.w.open_group(group_id))
        self._add_page(page, f"Dashboard: {group.name}", list(group.sources))
        model.refresh()
        return page

    def _add_page(
        self, page: OverviewPage | ComposeDashboard, title: str, sources: Sequence[LogSource]
    ) -> None:
        for source in sources:
            self.w._follow(source)
        self._pages.append(page)
        index = self.w.tabs.addTab(page, title)
        self.w._add_close_button(index, page, title)
        self.w.tabs.setCurrentIndex(index)
        self.w.stack.setCurrentWidget(self.w.tabs)

    def _close_page(self, page: QWidget) -> bool:
        if page not in self._pages:
            return False
        assert isinstance(page, OverviewPage | ComposeDashboard)  # noqa: S101
        self._pages.remove(page)
        page.model.stop()
        for source_id in page.model.source_ids:
            if source_id in self.w._follow_refs:
                self.w._unfollow(source_id)
        return True

    def _open_ids(self, source_ids: Sequence[str]) -> None:
        if len(source_ids) == 1:
            self.w.open_source(source_ids[0])
            return
        group = next(
            (g for g in self.w._groups if tuple(s.id for s in g.sources) == tuple(source_ids)), None
        )
        if group is not None:
            self.w.open_group(group.id)

    def _open_interval(self, source_ids: Sequence[str], start: datetime, end: datetime) -> None:
        """A timeline bar was clicked: a log tab limited to that interval."""
        from loglens.gui.main_window import TabState  # noqa: PLC0415

        names = [src.display_name for s in source_ids if (src := self.w.tree_model.source(s))]
        title = f"{names[0] if len(names) == 1 else 'group'} {start.astimezone():%H:%M}"
        state = TabState(title, tuple(source_ids), range_key="custom", since=start, until=end)
        self.w._open(state, new_tab=True)

    def _pages_mark_dirty(self, entries: Sequence[LogEntry]) -> None:
        if not self._pages:
            return
        changed = {e.source_id for e in entries}
        for page in self._pages:
            if changed.intersection(page.model.source_ids):
                page.model.mark_dirty()

    def _pages_update_sources(self) -> None:
        for page in self._pages:
            sources = [s for sid in page.model.source_ids if (s := self.w.tree_model.source(sid))]
            if sources:
                page.model.set_sources(sources)

    # ------------------------------------------------------------------ export and reports

    def _selected_entries(self, view: LogView, done: Any) -> None:
        rows = view.selected_rows()[:REPORT_LIMIT]
        view.model.entries_for_rows(rows, done)

    def copy_incident_report(self) -> None:
        """Selected entries with their explanations, as Markdown, to the clipboard."""
        tab = self.w._tab()
        if tab is None:
            return
        view = tab.view

        def done(entries: list[LogEntry]) -> None:
            pairs = [(e, self.explain(e)) for e in entries]
            text = incident_report(
                pairs, self.w.tree_model.display_names(), f"Incident: {tab.state.title}"
            )
            QGuiApplication.clipboard().setText(text)
            self.w.statusBar().showMessage(
                f"Copied an incident report of {len(pairs)} entries", 6000
            )

        if not view.selected_rows():
            self.w.statusBar().showMessage("Select the entries for the report first", 5000)
            return
        self._selected_entries(view, done)

    def export_view(self) -> None:
        """Export the current view, the selection or a time range to a file."""
        tab = self.w._tab()
        if tab is None:
            return
        view = tab.view
        dialog = ExportDialog(view.model.rowCount(), len(view.selected_rows()), self.w)
        if not dialog.exec():
            return
        fmt, scope, since, until = dialog.choice()
        path_text, _ = QFileDialog.getSaveFileName(
            self.w,
            "Export to",
            str(Path.home() / f"loglens-{tab.state.title}.{fmt}"),
            f"{fmt.upper()} (*.{fmt})",
        )
        if not path_text:
            return
        self.export_to(view, Path(path_text), fmt=fmt, scope=scope, since=since, until=until)

    def export_to(
        self,
        view: LogView,
        path: Path,
        *,
        fmt: str,
        scope: str,
        since: datetime | None = None,
        until: datetime | None = None,
    ) -> None:
        """Write the export on the reader thread (never blocks the GUI)."""
        model = view.model
        if scope == "selected":
            ids = [model.id_at(r) for r in view.selected_rows()]
        elif scope == "view":
            ids = [model.id_at(r) for r in range(model.rowCount())]
        else:
            ids = []
        query = replace(model.query, since=since, until=until)

        def job(storage: Storage) -> int:
            chosen = list(storage.entry_ids(query)[0]) if scope == "range" else ids

            def entries() -> Any:
                for chunk in batched(chosen, 900):
                    yield from storage.entries_by_id(chunk)

            with path.open("w", encoding="utf-8", newline="" if fmt == "csv" else None) as handle:
                return write_entries(entries(), fmt, handle)

        self.w.statusBar().showMessage(f"Exporting to {path}…")
        self.w.worker.submit(
            job,
            lambda n: self.w.statusBar().showMessage(f"Exported {n:,} entries to {path}", 10000),
            lambda exc: self.w.statusBar().showMessage(f"Export failed: {exc}", 10000),
        )

    def _log_view_actions(self, view: LogView) -> list[QAction]:
        explain = QAction("Explain in panel", view)
        explain.triggered.connect(self.explain_dock.show)
        report = QAction("Copy incident report (Markdown)", view)
        report.triggered.connect(self.copy_incident_report)
        export = QAction("Export…", view)
        export.triggered.connect(self.export_view)
        actions = [explain, report, export]
        current = view.tree.currentIndex()
        entry = view.model.entry_at(current.row()) if current.isValid() else None
        if entry is not None and self.explain(entry) is None:
            create = QAction("Create rule from this line…", view)
            create.triggered.connect(lambda: self.create_rule(entry))
            actions.append(create)
        return actions

    # ------------------------------------------------------------------ notifications

    def set_muted(self, source_id: str, muted: bool) -> None:
        """Mute or unmute desktop notifications for a source."""
        current = set(self.w.settings.muted)
        current = current | {source_id} if muted else current - {source_id}
        self.w.settings = replace(self.w.settings, muted=tuple(sorted(current)))
        self.center.muted = current
        self.w._save_settings()

    def _settings_changed_insights(self, old: Any) -> None:
        self.center.conditions = set(self.w.settings.notify_on)
        self.center.muted = set(self.w.settings.muted)
        if self.w.settings.rule_dirs != old.rule_dirs:
            self._rules_changed(user_rules_dir())
        if self.w.settings.inline_explanations != old.inline_explanations:
            self.set_inline_mode(self.w.settings.inline_explanations)
