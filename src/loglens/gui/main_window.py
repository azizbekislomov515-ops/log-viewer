"""MainWindow: source tree, tabbed log views, toolbar, status bar, issues, shortcuts.

Data flow: the backend delivers entries into a deque; ``_drain`` (a 100 ms timer on the GUI
thread) hands each batch to every open tab's model and turns errors from sources the user
is not looking at into unread badges. Database reads go through the ``Worker``.
"""

from __future__ import annotations

import json
import logging
import os
import time
from collections import Counter
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Protocol

from PySide6.QtCore import (
    QModelIndex,
    QPoint,
    QSignalBlocker,
    QSortFilterProxyModel,
    Qt,
    QTimer,
    SignalInstance,
)
from PySide6.QtGui import (
    QCloseEvent,
    QGuiApplication,
    QKeySequence,
    QResizeEvent,
    QShortcut,
)
from PySide6.QtWidgets import (
    QAbstractItemView,
    QComboBox,
    QDockWidget,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMenu,
    QSplitter,
    QStackedWidget,
    QTabBar,
    QTabWidget,
    QToolBar,
    QToolButton,
    QTreeView,
    QVBoxLayout,
    QWidget,
)

from loglens.config import Settings, save_settings
from loglens.core.models import DiscoveryIssue, LogEntry, LogSource, ServiceGroup, Severity
from loglens.gui import theme as themes
from loglens.gui.log_model import Column, LogTableModel, SearchSpec, plain_tooltip
from loglens.gui.log_view import LogView
from loglens.gui.source_tree import NodeKind, SourceTreeModel, TreeRole
from loglens.gui.widgets import (
    CommandPalette,
    DebugOverlay,
    FrameMeter,
    IssuesPanel,
    SettingsDialog,
    SourceDelegate,
    TimeRangeDialog,
)
from loglens.gui.workers import Worker
from loglens.storage import EntryQuery

log = logging.getLogger(__name__)

DRAIN_MS = 100
#: Severity chips: label -> severities it covers.
CHIPS: tuple[tuple[str, frozenset[Severity]], ...] = (
    ("Critical", frozenset({Severity.CRITICAL})),
    ("Error", frozenset({Severity.ERROR})),
    ("Warning", frozenset({Severity.WARNING})),
    ("Notice", frozenset({Severity.NOTICE})),
    ("Info", frozenset({Severity.INFO})),
    ("Debug", frozenset({Severity.DEBUG, Severity.TRACE})),
)
RANGES: tuple[tuple[str, str, timedelta | None], ...] = (
    ("live", "Live (everything)", None),
    ("5m", "Last 5 minutes", timedelta(minutes=5)),
    ("1h", "Last hour", timedelta(hours=1)),
    ("24h", "Last 24 hours", timedelta(hours=24)),
    ("custom", "Custom range…", None),
)


class BackendLike(Protocol):
    """What the window needs from the backend (the real one or a test stub)."""

    sourcesChanged: SignalInstance
    statsChanged: SignalInstance
    failed: SignalInstance

    def follow(self, source: LogSource) -> None: ...
    def unfollow(self, source_id: str) -> None: ...
    def refresh_discovery(self) -> None: ...
    def take_entries(self, limit: int = ...) -> list[LogEntry]: ...

    @property
    def backlog(self) -> int: ...


def session_path() -> Path:
    """``$XDG_STATE_HOME/loglens/session.json``: open tabs and their filters."""
    base = os.environ.get("XDG_STATE_HOME") or str(Path.home() / ".local" / "state")
    return Path(base) / "loglens" / "session.json"


@dataclass
class TabState:
    """Per-tab filters (they persist with the session)."""

    title: str
    source_ids: tuple[str, ...]
    group_id: str | None = None
    severities: frozenset[Severity] = field(default_factory=lambda: frozenset(Severity))
    range_key: str = "live"
    since: datetime | None = None
    until: datetime | None = None
    search: SearchSpec = field(default_factory=SearchSpec)
    split: bool = False

    def query(self, source_ids: Sequence[str] | None = None) -> EntryQuery:
        """The storage query for this tab (or a subset of its sources)."""
        since, until = self.since, self.until
        delta = {k: d for k, _, d in RANGES}.get(self.range_key)
        if delta is not None:
            since, until = datetime.now().astimezone() - delta, None
        elif self.range_key == "live":
            since = until = None
        everything = self.severities >= frozenset(Severity)
        return EntryQuery(
            tuple(source_ids or self.source_ids),
            None if everything else self.severities,
            since,
            until,
        )

    def to_json(self) -> dict[str, Any]:
        """Session file form."""
        return {
            "title": self.title,
            "sources": list(self.source_ids),
            "group": self.group_id,
            "severities": sorted(s.name for s in self.severities),
            "range": self.range_key if self.range_key != "custom" else "live",
            "search": self.search.text,
            "regex": self.search.is_regex,
            "split": self.split,
        }

    @classmethod
    def from_json(cls, data: dict[str, Any]) -> TabState:
        """Inverse of ``to_json`` (unknown values fall back to defaults)."""
        names = {s.name for s in Severity}
        return cls(
            title=str(data.get("title", "?")),
            source_ids=tuple(str(s) for s in data.get("sources", [])),
            group_id=data.get("group"),
            severities=frozenset(Severity[n] for n in data.get("severities", []) if n in names)
            or frozenset(Severity),
            range_key=data.get("range", "live")
            if data.get("range") in {k for k, *_ in RANGES}
            else "live",
            search=SearchSpec(str(data.get("search", "")), bool(data.get("regex", False))),
            split=bool(data.get("split", False)),
        )


class LogTab(QWidget):
    """One tab: a merged view of its sources, or (for groups) one view per source."""

    def __init__(
        self, state: TabState, worker: Worker, names: dict[str, str], parent: QWidget | None = None
    ) -> None:
        super().__init__(parent)
        self.state = state
        self._worker = worker
        self._names = names
        self.views: list[LogView] = []
        self.paused = False
        self.wrap = False
        self.banner = QFrame(self)
        self.banner.setObjectName("banner")
        self.banner_text = QLabel(self.banner)
        self.banner_text.setTextFormat(Qt.TextFormat.PlainText)
        self.banner_text.setObjectName("bannerText")
        banner_layout = QHBoxLayout(self.banner)
        banner_layout.setContentsMargins(10, 4, 10, 4)
        banner_layout.addWidget(self.banner_text)
        self.banner.hide()
        self.body = QSplitter(Qt.Orientation.Vertical, self)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        layout.addWidget(self.banner)
        layout.addWidget(self.body)
        self._theme = themes.DARK
        self._font = themes.mono_font()
        self.rebuild()

    @property
    def is_group(self) -> bool:
        """True for multi-source tabs (Compose projects, file groups)."""
        return len(self.state.source_ids) > 1

    def rebuild(self) -> None:
        """(Re)create the views: one merged view, or one per source when split."""
        for view in self.views:
            view.setParent(None)
            view.deleteLater()
        self.views = []
        parts = (
            [(sid,) for sid in self.state.source_ids]
            if self.state.split and self.is_group
            else [self.state.source_ids]
        )
        for source_ids in parts:
            model = LogTableModel(self._worker, self.state.query(source_ids), self._names, self)
            view = LogView(model, self.body)
            if len(parts) > 1:  # split: say which service each pane shows
                name = self._names.get(source_ids[0]) or source_ids[0]
                view.set_caption(name, self._theme.series_color(name).name())
            view.tree.setColumnHidden(Column.SOURCE, len(source_ids) == 1)
            view.set_theme(self._theme)
            view.set_font(self._font)
            view.set_wrap(self.wrap)
            model.loadingChanged.connect(lambda _on: self._update_banner())
            self.body.addWidget(view)
            self.views.append(view)
            model.set_search(self.state.search)
            model.set_paused(self.paused)
            model.reload()

    @property
    def view(self) -> LogView:
        """The view with focus (or the first)."""
        for view in self.views:
            if view.tree.hasFocus():
                return view
        return self.views[0]

    def apply_filters(self) -> None:
        """Re-query every view after the tab's filters changed."""
        for view in self.views:
            view.model.set_query(self.state.query(view.model.query.source_ids))

    def set_search(self, spec: SearchSpec) -> None:
        """Highlight ``spec`` in every view."""
        self.state.search = spec
        for view in self.views:
            view.model.set_search(spec)

    def set_paused(self, paused: bool) -> None:
        """Hold/release live entries."""
        self.paused = paused
        for view in self.views:
            view.model.set_paused(paused)
        self._update_banner()

    def set_wrap(self, wrap: bool) -> None:
        """Wrap long lines."""
        self.wrap = wrap
        for view in self.views:
            view.set_wrap(wrap)

    def set_follow(self, follow: bool) -> None:
        """Keep the newest entry in view."""
        for view in self.views:
            view.set_follow(follow)

    def set_theme(self, theme: themes.Theme, font: Any) -> None:
        """Restyle views."""
        self._theme, self._font = theme, font
        for view in self.views:
            view.set_theme(theme)
            view.set_font(font)
            if view.caption.isVisible() or view.caption.text():
                name = view.caption.text()
                view.set_caption(name, theme.series_color(name).name())

    def set_names(self, names: dict[str, str]) -> None:
        """Source display names changed."""
        self._names = names
        for view in self.views:
            view.model.set_display_names(names)

    def append_live(self, entries: Sequence[LogEntry]) -> None:
        """Give live entries to every view (each filters for itself)."""
        for view in self.views:
            view.model.append_live(entries)
        if self.paused:
            self._update_banner()

    def _update_banner(self) -> None:
        loading = any(v.model.loading for v in self.views)
        if self.paused:
            held = sum(v.model.held_count for v in self.views)
            self.banner_text.setText(
                f"Paused. {held:,} new entries are waiting. Press Ctrl+P to resume."
            )
        elif loading:
            self.banner_text.setText("Loading stored entries…")
        self.banner.setVisible(self.paused or loading)


class MainWindow(QMainWindow):
    """The LogLens window."""

    def __init__(
        self,
        backend: BackendLike,
        worker: Worker,
        settings: Settings,
        *,
        settings_path: Path | None = None,
        state_path: Path | None = None,
    ) -> None:
        super().__init__()
        self.setWindowTitle("LogLens")
        self.resize(1440, 900)
        self.backend = backend
        self.worker = worker
        self.settings = settings
        self._settings_path = settings_path
        self._state_path = state_path
        self._issues: tuple[DiscoveryIssue, ...] = ()
        self._collector_errors: dict[str, str] = {}
        self._follow_refs: Counter[str] = Counter()
        self._theme = themes.resolve(settings.theme)
        self._font = themes.mono_font()
        self._last_drain_ms = 0.0
        self._rates = {"rows": 0.0, "pages": 0.0, "t": time.perf_counter(), "rows0": 0, "pages0": 0}
        self._restored = False

        self.tree_model = SourceTreeModel(self)
        self.tree_model.set_pinned(settings.pinned)
        self._build_tree_dock()
        self._build_central()
        self._build_toolbar()
        self._build_status_bar()
        self._build_issues_dock()
        self.palette_popup = CommandPalette(self)
        self.palette_popup.chosen.connect(self.open_source)
        self.frame_meter = FrameMeter(self)
        self.frame_meter.start()
        self.overlay = DebugOverlay(self._debug_text, self.stack)
        self._build_shortcuts()

        backend.sourcesChanged.connect(self._on_sources)
        backend.statsChanged.connect(self._on_stats)
        backend.failed.connect(lambda msg: self.statusBar().showMessage(msg, 15000))
        self._drain_timer = QTimer(self)
        self._drain_timer.setInterval(DRAIN_MS)
        self._drain_timer.timeout.connect(self.drain)
        self._drain_timer.start()
        self.apply_theme(self._theme)

    # ------------------------------------------------------------------ construction

    def _build_tree_dock(self) -> None:
        dock = QDockWidget("Sources", self)
        dock.setObjectName("sourcesDock")
        dock.setFeatures(QDockWidget.DockWidgetFeature.DockWidgetMovable)
        panel = QWidget(dock)
        self.tree_filter = QLineEdit(panel)
        self.tree_filter.setPlaceholderText("Filter sources")
        self.tree_filter.setAccessibleName("Filter sources")
        self.tree_filter.setClearButtonEnabled(True)
        self.tree_proxy = QSortFilterProxyModel(self)
        self.tree_proxy.setSourceModel(self.tree_model)
        self.tree_proxy.setRecursiveFilteringEnabled(True)
        self.tree_proxy.setFilterCaseSensitivity(Qt.CaseSensitivity.CaseInsensitive)
        self.tree_filter.textChanged.connect(self._filter_tree)
        self.tree = QTreeView(panel)
        self.tree.setModel(self.tree_proxy)
        self.tree.setHeaderHidden(True)
        self.tree.setMouseTracking(True)
        self.tree.setAccessibleName("Log sources")
        self.tree.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.tree.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.tree_delegate = SourceDelegate(self.tree)
        self.tree.setItemDelegate(self.tree_delegate)
        self.tree.activated.connect(self._tree_activated)
        self.tree.clicked.connect(self._tree_activated)
        self.tree.customContextMenuRequested.connect(self._tree_menu)
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(6, 6, 0, 0)
        layout.addWidget(self.tree_filter)
        layout.addWidget(self.tree)
        dock.setWidget(panel)
        dock.setMinimumWidth(260)
        self.addDockWidget(Qt.DockWidgetArea.LeftDockWidgetArea, dock)
        self.sources_dock = dock

    def _build_central(self) -> None:
        self.tabs = QTabWidget(self)
        self.tabs.setMovable(True)
        self.tabs.setDocumentMode(True)
        self.tabs.setAccessibleName("Open logs")
        self.tabs.currentChanged.connect(self._on_tab_changed)
        self.empty = QLabel(
            "<p style='font-size:15px'>Pick a service on the left to see its logs live.</p>"
            "<p>Or press <b>Ctrl+K</b> and type part of its name.</p>"
        )
        self.empty.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.empty.setProperty("role", "hint")
        self.stack = QStackedWidget(self)
        self.stack.addWidget(self.empty)
        self.stack.addWidget(self.tabs)
        self.setCentralWidget(self.stack)

    def _build_toolbar(self) -> None:
        bar = QToolBar("Main", self)
        bar.setObjectName("mainToolbar")
        bar.setMovable(False)
        self.addToolBar(bar)
        self.search = QLineEdit(bar)
        self.search.setPlaceholderText("Search this tab  (Ctrl+F)")
        self.search.setAccessibleName("Search")
        self.search.setClearButtonEnabled(True)
        self.search.setFixedWidth(240)
        self.search.returnPressed.connect(lambda: self.next_match(forward=True))
        self._search_timer = QTimer(self)
        self._search_timer.setSingleShot(True)
        self._search_timer.setInterval(250)
        self._search_timer.timeout.connect(self._apply_search)
        self.search.textChanged.connect(lambda _: self._search_timer.start())
        bar.addWidget(self.search)
        self.regex_btn = self._tool(
            bar, ".*", "Regular expression (stops if too slow)", checkable=True
        )
        self.regex_btn.toggled.connect(lambda _: self._apply_search())
        self.prev_btn = self._tool(bar, "↑", "Previous match (Shift+F3)")
        self.prev_btn.clicked.connect(lambda: self.next_match(forward=False))
        self.next_btn = self._tool(bar, "↓", "Next match (F3)")
        self.next_btn.clicked.connect(lambda: self.next_match(forward=True))
        self.match_label = QLabel("", bar)
        self.match_label.setMinimumWidth(80)
        bar.addWidget(self.match_label)
        bar.addSeparator()
        self.chips: list[tuple[QToolButton, frozenset[Severity]]] = []
        for label, severities in CHIPS:
            glyph = themes.SEVERITY_GLYPH[max(severities)]
            chip = self._tool(
                bar, f"{glyph} {label}".strip(), f"Show {label.lower()} entries", checkable=True
            )
            chip.setAccessibleName(f"Show {label.lower()} entries")
            chip.setProperty("chip", True)
            chip.setChecked(True)
            chip.toggled.connect(self._apply_severities)
            self.chips.append((chip, severities))
        bar.addSeparator()
        self.range_box = QComboBox(bar)
        self.range_box.setAccessibleName("Time range")
        for key, label, _ in RANGES:
            self.range_box.addItem(label, key)
        self.range_box.activated.connect(self._apply_range)
        bar.addWidget(self.range_box)
        spacer = QWidget(bar)
        spacer.setSizePolicy(
            spacer.sizePolicy().horizontalPolicy().Expanding, spacer.sizePolicy().verticalPolicy()
        )
        bar.addWidget(spacer)
        self.pause_btn = self._tool(bar, "Pause", "Pause live updates (Ctrl+P)", checkable=True)
        self.pause_btn.toggled.connect(self._set_paused)
        self.follow_btn = self._tool(bar, "Follow", "Keep the newest entry in view", checkable=True)
        self.follow_btn.setChecked(True)
        self.follow_btn.toggled.connect(lambda on: self._tab() and self._tab().set_follow(on))  # type: ignore[union-attr]
        self.wrap_btn = self._tool(bar, "Wrap", "Wrap long lines", checkable=True)
        self.wrap_btn.toggled.connect(lambda on: self._tab() and self._tab().set_wrap(on))  # type: ignore[union-attr]
        self.split_btn = self._tool(
            bar, "Split", "Show each service of this group separately", checkable=True
        )
        self.split_btn.toggled.connect(self._set_split)
        menu_btn = self._tool(bar, "⋯", "More")
        menu = QMenu(menu_btn)
        menu.addAction("Jump to source…", QKeySequence("Ctrl+K"), self.show_palette)
        menu.addAction("Look for new sources now", self.backend.refresh_discovery)
        menu.addAction("Settings…", QKeySequence("Ctrl+,"), self.show_settings)
        menu.addAction("Discovery issues", lambda: self.issues_dock.setVisible(True))
        menu_btn.setMenu(menu)
        menu_btn.setPopupMode(QToolButton.ToolButtonPopupMode.InstantPopup)
        self.toolbar = bar
        self._sync_toolbar()

    def _tool(self, bar: QToolBar, text: str, tip: str, *, checkable: bool = False) -> QToolButton:
        button = QToolButton(bar)
        button.setText(text)
        button.setToolTip(tip)
        button.setAccessibleName(tip.split(" (", maxsplit=1)[0])
        button.setCheckable(checkable)
        button.setFocusPolicy(Qt.FocusPolicy.StrongFocus)
        bar.addWidget(button)
        return button

    def _build_status_bar(self) -> None:
        status = self.statusBar()
        self.rate_label = QLabel("0 lines/s")
        self.collectors_label = QLabel("0 sources followed")
        self.stored_label = QLabel("")
        self.issues_btn = QToolButton(status)
        self.issues_btn.setAccessibleName("Discovery issues")
        self.issues_btn.setText("No issues")
        self.issues_btn.clicked.connect(
            lambda: self.issues_dock.setVisible(not self.issues_dock.isVisible())
        )
        for widget in (self.rate_label, self.collectors_label, self.stored_label):
            status.addPermanentWidget(widget)
        status.addPermanentWidget(self.issues_btn)

    def _build_issues_dock(self) -> None:
        self.issues_panel = IssuesPanel(self)
        dock = QDockWidget("Discovery issues", self)
        dock.setObjectName("issuesDock")
        dock.setWidget(self.issues_panel)
        self.addDockWidget(Qt.DockWidgetArea.BottomDockWidgetArea, dock)
        dock.hide()
        self.issues_dock = dock

    def _build_shortcuts(self) -> None:
        def bind(keys: str, fn: Any) -> None:
            shortcut = QShortcut(QKeySequence(keys), self)
            shortcut.setContext(Qt.ShortcutContext.WindowShortcut)
            shortcut.activated.connect(fn)

        bind("Ctrl+F", self.focus_search)
        bind("Ctrl+K", self.show_palette)
        bind("Ctrl+P", self.pause_btn.toggle)
        bind("Ctrl+W", lambda: self.close_tab(self.tabs.currentIndex()))
        bind("Ctrl+,", self.show_settings)
        bind("F3", lambda: self.next_match(forward=True))
        bind("Shift+F3", lambda: self.next_match(forward=False))
        bind("Ctrl+Alt+D", self.overlay.toggle)
        bind("Escape", self._escape)
        for n in range(1, 10):
            bind(
                f"Ctrl+{n}",
                lambda n=n: self.tabs.setCurrentIndex(n - 1) if n <= self.tabs.count() else None,
            )

    # ------------------------------------------------------------------ sources

    def _on_sources(
        self, groups: tuple[ServiceGroup, ...], issues: tuple[DiscoveryIssue, ...]
    ) -> None:
        expanded = self._expanded_nodes()
        rebuilt = self.tree_model.update(groups, self.settings.excluded)
        if rebuilt:
            self._restore_expanded(expanded or {"cat:compose", "cat:files", "cat:containers"})
        names = self.tree_model.display_names()
        for tab in self._all_tabs():
            tab.set_names(names)
        self._issues = issues
        self._update_issues()
        for source_id in self.settings.pinned:
            if (source := self.tree_model.source(source_id)) is not None and not self._follow_refs[
                source_id
            ]:
                self._follow(source)
        if not self._restored:
            self._restored = True
            self.restore_session()

    def _expanded_nodes(self) -> set[str]:
        out = set()
        for node_id, item in self.tree_model._items.items():
            index = self.tree_proxy.mapFromSource(item.index())
            if index.isValid() and self.tree.isExpanded(index):
                out.add(node_id)
        return out

    def _restore_expanded(self, node_ids: set[str]) -> None:
        for node_id in node_ids:
            if (item := self.tree_model.item_for(node_id)) is not None:
                self.tree.setExpanded(self.tree_proxy.mapFromSource(item.index()), True)

    def _filter_tree(self, text: str) -> None:
        self.tree_proxy.setFilterFixedString(text)
        if text:
            self.tree.expandAll()

    def _tree_activated(self, proxy_index: QModelIndex) -> None:
        index = self.tree_proxy.mapToSource(proxy_index)
        kind = index.data(TreeRole.KIND)
        if kind == NodeKind.SOURCE:
            self.open_source(index.data(TreeRole.NODE_ID))
        elif kind == NodeKind.GROUP:
            self.open_group(index.data(TreeRole.NODE_ID))

    def _tree_menu(self, pos: QPoint) -> None:
        index = self.tree_proxy.mapToSource(self.tree.indexAt(pos))
        kind = index.data(TreeRole.KIND)
        node_id = index.data(TreeRole.NODE_ID)
        menu = QMenu(self)
        if kind == NodeKind.SOURCE:
            menu.addAction("Open", lambda: self.open_source(node_id))
            menu.addAction("Open in new tab", lambda: self.open_source(node_id, new_tab=True))
            pinned = node_id in self.tree_model.pinned
            menu.addAction(
                "Unpin" if pinned else "Pin (follow in background)",
                lambda: self.set_pinned(node_id, not pinned),
            )
            menu.addAction("Copy ID", lambda: QGuiApplication.clipboard().setText(node_id))
        elif kind == NodeKind.GROUP:
            menu.addAction("Open all services", lambda: self.open_group(node_id))
            menu.addAction("Open in new tab", lambda: self.open_group(node_id, new_tab=True))
            menu.addAction("Copy ID", lambda: QGuiApplication.clipboard().setText(node_id))
        menu.addSeparator()
        menu.addAction("Look for new sources now", self.backend.refresh_discovery)
        menu.exec(self.tree.viewport().mapToGlobal(pos))

    def set_pinned(self, source_id: str, pinned: bool) -> None:
        """Pin = follow in the background (unread badges) and remember it."""
        pins = set(self.settings.pinned)
        if pinned:
            pins.add(source_id)
            if (source := self.tree_model.source(source_id)) is not None:
                self._follow(source)
        elif source_id in pins:
            pins.discard(source_id)
            self._unfollow(source_id)
        from dataclasses import replace  # noqa: PLC0415

        self.settings = replace(self.settings, pinned=tuple(sorted(pins)))
        self.tree_model.set_pinned(pins)
        self._save_settings()

    def _follow(self, source: LogSource) -> None:
        self._follow_refs[source.id] += 1
        if self._follow_refs[source.id] == 1:
            self.backend.follow(source)

    def _unfollow(self, source_id: str) -> None:
        self._follow_refs[source_id] -= 1
        if self._follow_refs[source_id] <= 0:
            del self._follow_refs[source_id]
            self.backend.unfollow(source_id)

    # ------------------------------------------------------------------ tabs

    def _all_tabs(self) -> list[LogTab]:
        return [w for i in range(self.tabs.count()) if isinstance(w := self.tabs.widget(i), LogTab)]

    def _tab(self) -> LogTab | None:
        widget = self.tabs.currentWidget()
        return widget if isinstance(widget, LogTab) else None

    def open_source(self, source_id: str, *, new_tab: bool = False) -> LogTab | None:
        """Show a source's logs (focus its tab if one is open)."""
        source = self.tree_model.source(source_id)
        if source is None:
            return None
        return self._open(TabState(source.display_name, (source_id,)), new_tab=new_tab)

    def open_group(self, group_id: str, *, new_tab: bool = False) -> LogTab | None:
        """Show every service of a group merged in one tab."""
        group = self.tree_model.group(group_id)
        if group is None:
            return None
        state = TabState(group.name, tuple(s.id for s in group.sources), group_id=group_id)
        return self._open(state, new_tab=new_tab)

    def _open(self, state: TabState, *, new_tab: bool) -> LogTab:
        if not new_tab:
            for i, tab in enumerate(self._all_tabs()):
                if tab.state.source_ids == state.source_ids:
                    self.tabs.setCurrentIndex(i)
                    return tab
        tab = LogTab(state, self.worker, self.tree_model.display_names(), self.tabs)
        tab.set_theme(self._theme, self._font)
        self._wire_views(tab)
        for source_id in state.source_ids:
            if (source := self.tree_model.source(source_id)) is not None:
                self._follow(source)
        index = self.tabs.addTab(tab, state.title)
        self.tabs.setTabToolTip(index, plain_tooltip(", ".join(state.source_ids)))
        close = QToolButton(self.tabs)
        close.setText("×")  # noqa: RUF001 (a real multiplication sign: the close glyph)
        close.setObjectName("tabClose")
        close.setToolTip("Close tab (Ctrl+W)")
        close.setAccessibleName(f"Close {state.title}")
        close.setAutoRaise(True)
        close.clicked.connect(lambda _=False, t=tab: self.close_tab(self.tabs.indexOf(t)))
        self.tabs.tabBar().setTabButton(index, QTabBar.ButtonPosition.RightSide, close)
        self.tabs.setCurrentIndex(index)
        self.stack.setCurrentWidget(self.tabs)
        self._save_session()
        return tab

    def _wire_views(self, tab: LogTab) -> None:
        for view in tab.views:
            view.copied.connect(
                lambda n, fmt: self.statusBar().showMessage(f"Copied {n} entries as {fmt}", 4000)
            )
            view.model.searchFinished.connect(self._on_search_finished)
            view.followChanged.connect(lambda on, t=tab: self._on_follow_changed(t, on))

    def _on_follow_changed(self, tab: LogTab, follow: bool) -> None:
        if tab is self._tab():
            with QSignalBlocker(self.follow_btn):
                self.follow_btn.setChecked(follow)

    def close_tab(self, index: int) -> None:
        """Close a tab and stop following sources nothing else needs."""
        widget = self.tabs.widget(index)
        if not isinstance(widget, LogTab):
            return
        self.tabs.removeTab(index)
        for source_id in widget.state.source_ids:
            if source_id in self._follow_refs:
                self._unfollow(source_id)
        widget.deleteLater()
        if not self.tabs.count():
            self.stack.setCurrentWidget(self.empty)
        self._save_session()

    def _on_tab_changed(self, _index: int) -> None:
        tab = self._tab()
        if tab is not None:
            self.tree_model.clear_unread(tab.state.source_ids)
        self._sync_toolbar()

    def _sync_toolbar(self) -> None:
        """Show the active tab's filters in the toolbar (filters are per tab)."""
        tab = self._tab()
        enabled = tab is not None
        for widget in (
            self.search,
            self.regex_btn,
            self.prev_btn,
            self.next_btn,
            self.range_box,
            self.pause_btn,
            self.follow_btn,
            self.wrap_btn,
        ):
            widget.setEnabled(enabled)
        self.split_btn.setVisible(bool(tab and tab.is_group))
        if tab is None:
            return
        blockers = [
            QSignalBlocker(w)
            for w in (
                self.search,
                self.regex_btn,
                self.range_box,
                self.pause_btn,
                self.follow_btn,
                self.wrap_btn,
                self.split_btn,
                *(c for c, _ in self.chips),
            )
        ]
        self.search.setText(tab.state.search.text)
        self.regex_btn.setChecked(tab.state.search.is_regex)
        for chip, severities in self.chips:
            chip.setChecked(severities <= tab.state.severities)
        self.range_box.setCurrentIndex(self.range_box.findData(tab.state.range_key))
        self.pause_btn.setChecked(tab.paused)
        self.follow_btn.setChecked(tab.view.follow)
        self.wrap_btn.setChecked(tab.wrap)
        self.split_btn.setChecked(tab.state.split)
        del blockers
        self._update_match_label()

    # ------------------------------------------------------------------ filters and search

    def _apply_severities(self) -> None:
        tab = self._tab()
        if tab is None:
            return
        chosen = frozenset().union(*(sev for chip, sev in self.chips if chip.isChecked()))
        tab.state.severities = chosen
        tab.apply_filters()
        self._save_session()

    def _apply_range(self, _index: int) -> None:
        tab = self._tab()
        if tab is None:
            return
        key = self.range_box.currentData()
        if key == "custom":
            dialog = TimeRangeDialog(tab.state.since, tab.state.until, self)
            if not dialog.exec():
                self.range_box.setCurrentIndex(self.range_box.findData(tab.state.range_key))
                return
            tab.state.since, tab.state.until = dialog.range()
        tab.state.range_key = key
        tab.apply_filters()
        self._save_session()

    def _apply_search(self) -> None:
        tab = self._tab()
        if tab is None:
            return
        spec = SearchSpec(self.search.text(), self.regex_btn.isChecked())
        if spec != tab.state.search:
            tab.set_search(spec)  # the label updates when the search reports back
            self._save_session()

    def _on_search_finished(self, count: int, error: str) -> None:
        self.search.setProperty("invalid", bool(error))
        self.search.style().unpolish(self.search)
        self.search.style().polish(self.search)
        if error:
            self.match_label.setText("Search stopped")
            self.match_label.setToolTip(plain_tooltip(error))
            self.statusBar().showMessage(error, 8000)
        else:
            self._update_match_label()

    def _update_match_label(self) -> None:
        tab = self._tab()
        if tab is None or not tab.state.search.active:
            self.match_label.setText("")
            return
        total = sum(len(v.model.match_rows) for v in tab.views)
        self.match_label.setText(f"{total:,} matches" if total != 1 else "1 match")
        self.match_label.setToolTip("")

    def next_match(self, *, forward: bool) -> None:
        """Go to the next/previous search hit in the focused view."""
        tab = self._tab()
        if tab is None:
            return
        view = tab.view
        row = view.model.next_match(view.current_row(), forward=forward)
        if row is not None:
            view.go_to_row(row)

    def focus_search(self) -> None:
        """Ctrl+F."""
        self.search.setFocus()
        self.search.selectAll()

    def _escape(self) -> None:
        if self.search.hasFocus() and self._tab() is not None:
            self._tab().view.tree.setFocus()  # type: ignore[union-attr]

    def _set_paused(self, paused: bool) -> None:
        tab = self._tab()
        if tab is not None:
            tab.set_paused(paused)
        self.pause_btn.setText("Resume" if paused else "Pause")

    def _set_split(self, split: bool) -> None:
        tab = self._tab()
        if tab is None or not tab.is_group:
            return
        tab.state.split = split
        tab.rebuild()
        tab.set_theme(self._theme, self._font)
        self._wire_views(tab)
        self._save_session()

    # ------------------------------------------------------------------ live data

    def drain(self) -> None:
        """Move delivered entries into the open tabs (GUI timer)."""
        start = time.perf_counter()
        entries = self.backend.take_entries()
        if entries:
            for tab in self._all_tabs():
                tab.append_live(entries)
            current = self._tab()
            visible = set(current.state.source_ids) if current and self.isActiveWindow() else set()
            unread = Counter(
                e.source_id
                for e in entries
                if e.severity >= Severity.ERROR and e.source_id not in visible
            )
            if unread:
                self.tree_model.add_unread(dict(unread))
            if current is not None and current.state.search.active:
                self._update_match_label()
        self._last_drain_ms = (time.perf_counter() - start) * 1000

    def _on_stats(self, stats: Any) -> None:
        self.rate_label.setText(f"{stats.lines_per_s:,.0f} lines/s")
        self.collectors_label.setText(
            f"{stats.collectors} source{'s' if stats.collectors != 1 else ''} followed"
        )
        self.stored_label.setText(f"{stats.stored:,} stored")
        self._collector_errors = dict(stats.collector_errors)
        self._update_issues()

    def _update_issues(self) -> None:
        self.issues_panel.set_issues(self._issues, self._collector_errors)
        n = self.issues_panel.count
        self.issues_btn.setText(f"⚠ {n} issue{'s' if n != 1 else ''}" if n else "No issues")
        self.issues_btn.setToolTip("Show what limits discovery and how to fix it")

    def _debug_text(self) -> str:
        avg, p99, worst = self.frame_meter.summary()
        now = time.perf_counter()
        rows = sum(v.model.stats["appended"] for t in self._all_tabs() for v in t.views)
        pages = sum(v.model.stats["pages"] for t in self._all_tabs() for v in t.views)
        dt = max(now - self._rates["t"], 1e-6)
        rows_rate = (rows - self._rates["rows0"]) / dt
        pages_rate = (pages - self._rates["pages0"]) / dt
        self._rates.update(t=now, rows0=rows, pages0=pages)
        return (
            f"frame  avg {avg:5.1f} ms  p99 {p99:5.1f} ms  max {worst:5.1f} ms\n"
            f"rows appended  {rows_rate:8,.0f}/s\n"
            f"pages loaded   {pages_rate:8,.1f}/s\n"
            f"last drain     {self._last_drain_ms:6.1f} ms\n"
            f"backlog        {self.backend.backlog:8,d}"
        )

    # ------------------------------------------------------------------ theme, settings, palette

    def apply_theme(self, theme: themes.Theme) -> None:
        """Restyle every custom-painted part (the app stylesheet is set by the caller)."""
        self._theme = theme
        self.tree_delegate.theme = theme
        self.issues_panel.theme = theme
        self.issues_panel.set_issues(self._issues, self._collector_errors)
        for tab in self._all_tabs():
            tab.set_theme(theme, self._font)
        self.tree.viewport().update()

    def show_palette(self) -> None:
        """Ctrl+K."""
        self.palette_popup.open_with(self.tree_model.sources())

    def show_settings(self) -> None:
        """Ctrl+,."""
        dialog = SettingsDialog(self.settings, self)
        if not dialog.exec():
            return
        old = self.settings
        self.settings = dialog.result_settings()
        self._save_settings()
        if self.settings.theme != old.theme:
            app = QGuiApplication.instance()
            theme = themes.resolve(self.settings.theme)
            themes.apply(app, theme)  # type: ignore[arg-type]
            self.apply_theme(theme)
        if self.settings.discovery_exclude != old.discovery_exclude:
            self.backend.refresh_discovery()

    def _save_settings(self) -> None:
        try:
            save_settings(self.settings, self._settings_path)
        except OSError as exc:
            self.statusBar().showMessage(f"Could not save settings: {exc}", 10000)

    # ------------------------------------------------------------------ session

    def _save_session(self) -> None:
        if self._state_path is None:
            return
        data = {
            "tabs": [t.state.to_json() for t in self._all_tabs()],
            "current": self.tabs.currentIndex(),
        }
        try:
            self._state_path.parent.mkdir(parents=True, exist_ok=True)
            self._state_path.write_text(json.dumps(data, indent=1), encoding="utf-8")
        except OSError:
            log.warning("could not save session", exc_info=True)

    def restore_session(self) -> None:
        """Reopen last session's tabs (sources that no longer exist are skipped)."""
        if self._state_path is None or not self._state_path.exists():
            return
        try:
            data = json.loads(self._state_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return
        for raw in data.get("tabs", []):
            state = TabState.from_json(raw)
            known = tuple(s for s in state.source_ids if self.tree_model.source(s) is not None)
            if known:
                state.source_ids = known
                self._open(state, new_tab=True)
        current = data.get("current", 0)
        if isinstance(current, int) and 0 <= current < self.tabs.count():
            self.tabs.setCurrentIndex(current)

    # ------------------------------------------------------------------ Qt events

    def resizeEvent(self, event: QResizeEvent) -> None:
        super().resizeEvent(event)
        if self.overlay.isVisible():
            self.overlay.refresh()

    def closeEvent(self, event: QCloseEvent) -> None:
        self._save_session()
        self._drain_timer.stop()
        self.frame_meter.stop()
        super().closeEvent(event)
