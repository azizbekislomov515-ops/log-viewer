"""LogTableModel: a virtualized table over millions of entries, plus live appends.

The model holds only two compact arrays for its rows, the entry ids (ascending) and
their severities (9 bytes per row), loaded by one background query. Entries themselves
are fetched in pages, on demand, by the ``Worker`` (never on the GUI thread) and kept in a
bounded LRU cache. Until a page arrives the row shows a placeholder; severity (row color,
severity map) is always known.

Live entries are filtered with the tab's query and appended at the end. Ids only grow, so
appends never shift existing rows (the scroll position is kept), and an entry the initial
query already returned is recognized by its id and not shown twice.

Search highlights instead of filtering: matching ids come from FTS5 (or a timed regex) in
the background; ``match_rows`` drives next/previous and the severity-map ticks.
"""

from __future__ import annotations

import bisect
import html
import json
import logging
from array import array
from collections import OrderedDict
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, replace
from enum import IntEnum
from typing import Any

import regex
from PySide6.QtCore import (
    QAbstractTableModel,
    QModelIndex,
    QObject,
    QPersistentModelIndex,
    Qt,
    Signal,
)

from loglens.core.models import Explanation, LogEntry, Severity
from loglens.gui.workers import Worker
from loglens.security.text import printable
from loglens.storage import EntryQuery, Storage

log = logging.getLogger(__name__)

PAGE_ROWS = 256
CACHE_ENTRIES = 20_000
#: Live entries kept while paused; beyond this the tab reloads from the database on resume.
PAUSE_BUFFER = 200_000
#: Rows a tab keeps; older rows are dropped from the top (they stay in the database).
MAX_ROWS = 5_000_000
#: Rows per severity-map block (each block remembers its worst severity).
BLOCK_ROWS = 64
#: Regex highlighting gives up on a line after this long (the delegate paints on time).
HIGHLIGHT_TIMEOUT_S = 0.005
#: Shown for a row whose entry retention deleted after the tab loaded.
GONE = "(no longer stored: removed by the retention policy)"

AnyIndex = QModelIndex | QPersistentModelIndex


class Column(IntEnum):
    """Table columns (the header can hide any of them)."""

    TIME = 0
    SOURCE = 1
    SEVERITY = 2
    MESSAGE = 3


class Role(IntEnum):
    """Custom data roles."""

    ENTRY = Qt.ItemDataRole.UserRole + 1
    SEVERITY = Qt.ItemDataRole.UserRole + 2
    MATCH = Qt.ItemDataRole.UserRole + 3
    EXPANDED = Qt.ItemDataRole.UserRole + 4
    EXTRA_LINES = Qt.ItemDataRole.UserRole + 5
    SOURCE_ID = Qt.ItemDataRole.UserRole + 6
    EXPLANATION = Qt.ItemDataRole.UserRole + 7


HEADERS = {
    Column.TIME: "Time",
    Column.SOURCE: "Source",
    Column.SEVERITY: "Level",
    Column.MESSAGE: "Message",
}


@dataclass(frozen=True, slots=True)
class SearchSpec:
    """What the search box asks for. Empty text means no search."""

    text: str = ""
    is_regex: bool = False
    ignore_case: bool = True

    @property
    def active(self) -> bool:
        """True when there is something to search for."""
        return bool(self.text.strip())


class Highlighter:
    """Finds match spans in a message (for painting) and tests live entries."""

    def __init__(self, spec: SearchSpec) -> None:
        self.spec = spec
        self.error = ""
        self._pattern: Any = None
        self._words: list[str] = []
        if not spec.active:
            return
        if spec.is_regex:
            try:
                flags = regex.IGNORECASE if spec.ignore_case else 0
                self._pattern = regex.compile(spec.text, flags)
            except regex.error as exc:
                self.error = f"invalid regex: {exc}"
        else:
            self._words = [w.lower() for w in spec.text.split()]

    def spans(self, text: str) -> list[tuple[int, int]]:
        """``(start, end)`` of every match in ``text``, sorted; [] on timeout."""
        if self._pattern is not None:
            try:
                return [
                    m.span()
                    for m in self._pattern.finditer(text, timeout=HIGHLIGHT_TIMEOUT_S)
                    if m.end() > m.start()
                ]
            except TimeoutError:
                return []
        lower = text.lower()
        found: list[tuple[int, int]] = []
        for word in self._words:
            start = lower.find(word)
            while start >= 0:
                found.append((start, start + len(word)))
                start = lower.find(word, start + len(word))
        return sorted(found)

    def matches(self, entry: LogEntry) -> bool:
        """Whether a live entry matches (approximates FTS: every word must occur)."""
        if self._pattern is not None:
            return bool(self.spans(entry.message))
        lower = entry.message.lower()
        return bool(self._words) and all(word in lower for word in self._words)


class LogTableModel(QAbstractTableModel):
    """Rows of one tab. Feed it with ``append_live``; filter with ``set_query``."""

    loadingChanged = Signal(bool)
    rowsAppended = Signal(int)
    searchFinished = Signal(int, str)  # match count, error ("" if none)
    blocksChanged = Signal()

    def __init__(
        self,
        worker: Worker,
        query: EntryQuery,
        display_names: Mapping[str, str] | None = None,
        parent: QObject | None = None,
    ) -> None:
        super().__init__(parent)
        self._worker = worker
        self._query = query
        self._names = dict(display_names or {})
        self._ids: array[int] = array("q")
        self._sev: array[int] = array("b")
        self._blocks: array[int] = array("b")
        self._cache: OrderedDict[int, LogEntry | None] = OrderedDict()
        self._requested: set[int] = set()  # page numbers in flight
        self._token = 0
        self._loading = False
        self._pending_live: list[LogEntry] = []
        self._paused = False
        self._paused_buffer: list[LogEntry] = []
        self._stale = False
        self._expanded: set[int] = set()
        self._search = SearchSpec()
        self._highlighter = Highlighter(self._search)
        self._match_ids: set[int] = set()
        self._match_rows: list[int] = []
        self._search_token = 0
        self._explainer: Callable[[LogEntry], Explanation | None] | None = None
        self._explanations: OrderedDict[int, Explanation | None] = OrderedDict()
        self.inline_mode = "off"
        self.stats = {"pages": 0, "appended": 0}

    # ------------------------------------------------------------------ Qt model API

    def rowCount(self, parent: AnyIndex = QModelIndex()) -> int:  # noqa: B008
        """Number of rows (0 under any parent: the table is flat)."""
        return 0 if parent.isValid() else len(self._ids)

    def columnCount(self, parent: AnyIndex = QModelIndex()) -> int:  # noqa: B008
        """Four columns."""
        return 0 if parent.isValid() else len(Column)

    def headerData(
        self, section: int, orientation: Qt.Orientation, role: int = Qt.ItemDataRole.DisplayRole
    ) -> Any:
        """Column titles."""
        if orientation == Qt.Orientation.Horizontal and role == Qt.ItemDataRole.DisplayRole:
            return HEADERS.get(Column(section)) if 0 <= section < len(Column) else None
        return None

    def data(self, index: AnyIndex, role: int = Qt.ItemDataRole.DisplayRole) -> Any:  # noqa: PLR0911, PLR0912
        """Cell data. Unloaded rows return a placeholder and trigger a page fetch."""
        row = index.row()
        if not index.isValid() or not 0 <= row < len(self._ids):
            return None
        if role == Role.SEVERITY:
            return Severity(self._sev[row])
        entry_id = self._ids[row]
        if role == Role.MATCH:
            return entry_id in self._match_ids
        if role == Role.EXPANDED:
            return entry_id in self._expanded
        entry = self._entry(row)
        if role == Role.ENTRY:
            return entry
        if entry is None:
            if role != Qt.ItemDataRole.DisplayRole or index.column() != Column.MESSAGE:
                return None
            return GONE if entry_id in self._cache else "…"
        match role:
            case Qt.ItemDataRole.DisplayRole:
                return self._display(entry, Column(index.column()))
            case Role.EXPLANATION:
                return self.explanation_for(entry)
            case Role.EXTRA_LINES:
                return entry.message.count("\n")
            case Role.SOURCE_ID:
                return entry.source_id
            case Qt.ItemDataRole.ToolTipRole if index.column() == Column.MESSAGE:
                text = entry.message if len(entry.message) < 2000 else entry.message[:2000] + "…"
                return plain_tooltip(printable(text))
            case Qt.ItemDataRole.AccessibleTextRole:
                return (
                    f"{entry.severity.name.lower()}, {self._display(entry, Column.TIME)}, "
                    + (entry.message.split("\n", 1)[0])
                )
        return None

    def flags(self, index: AnyIndex) -> Qt.ItemFlag:
        """Selectable, enabled, read-only."""
        if not index.isValid():
            return Qt.ItemFlag.NoItemFlags
        return Qt.ItemFlag.ItemIsSelectable | Qt.ItemFlag.ItemIsEnabled

    # ------------------------------------------------------------------ query and loading

    @property
    def query(self) -> EntryQuery:
        """The tab's filter."""
        return self._query

    @property
    def loading(self) -> bool:
        """True while the initial id list is being loaded."""
        return self._loading

    def set_display_names(self, names: Mapping[str, str]) -> None:
        """Source id -> label used in the Source column."""
        self._names = dict(names)

    def set_query(self, query: EntryQuery) -> None:
        """Change the filter and reload from the database."""
        self._query = query
        self.reload()

    def reload(self) -> None:
        """Re-run the query (keeps nothing but the search)."""
        self._token += 1
        token = self._token
        self.beginResetModel()
        self._ids, self._sev, self._blocks = array("q"), array("b"), array("b")
        self._cache.clear()
        self._requested.clear()
        self._match_rows = []
        self._pending_live = []
        self._paused_buffer = []
        self._stale = False
        self.endResetModel()
        self._set_loading(True)
        query = self._query
        self._worker.submit(
            lambda s: s.entry_ids(query),
            lambda result: self._ids_loaded(token, result),
            lambda exc: self._ids_failed(token, exc),
        )

    def _ids_loaded(self, token: int, result: tuple[array[int], array[int]]) -> None:
        if token != self._token:
            return
        ids, sev = result
        last = ids[-1] if ids else 0
        late = [e for e in self._pending_live if e.id > last]
        self._pending_live = []
        self.beginResetModel()
        self._ids, self._sev = ids, sev
        self._blocks = _blocks(sev, 0, array("b"))
        self.endResetModel()
        self._set_loading(False)
        self.blocksChanged.emit()
        if late:
            self._append(late)
        if self._search.active:
            self._run_search()

    def _ids_failed(self, token: int, exc: Exception) -> None:
        if token != self._token:
            return
        log.warning("loading tab failed: %s", exc)
        self._set_loading(False)

    def _set_loading(self, loading: bool) -> None:
        if loading != self._loading:
            self._loading = loading
            self.loadingChanged.emit(loading)

    # ------------------------------------------------------------------ live appends

    def append_live(self, entries: Sequence[LogEntry]) -> int:
        """Add live entries that pass the tab's filter; returns how many were accepted."""
        accepted = [e for e in entries if e.id > 0 and self._query.accepts(e)]
        if not accepted:
            return 0
        if self._loading:
            self._pending_live += accepted
        elif self._paused:
            if len(self._paused_buffer) + len(accepted) > PAUSE_BUFFER:
                self._stale = True
                self._paused_buffer = []
            elif not self._stale:
                self._paused_buffer += accepted
        else:
            self._append(accepted)
        return len(accepted)

    def _append(self, entries: Sequence[LogEntry]) -> None:
        last = self._ids[-1] if self._ids else 0
        fresh = [e for e in entries if e.id > last]
        if not fresh:
            return
        if len(self._ids) + len(fresh) > MAX_ROWS:
            self._drop_head(len(self._ids) + len(fresh) - MAX_ROWS + MAX_ROWS // 10)
        first = len(self._ids)
        self.beginInsertRows(QModelIndex(), first, first + len(fresh) - 1)
        for entry in fresh:
            self._ids.append(entry.id)
            self._sev.append(int(entry.severity))
            self._remember(entry.id, entry)
        self.endInsertRows()
        self._blocks = _blocks(self._sev, first, self._blocks)
        if self._search.active:
            hits = [first + i for i, e in enumerate(fresh) if self._highlighter.matches(e)]
            self._match_ids.update(self._ids[r] for r in hits)
            self._match_rows += hits
        self.stats["appended"] += len(fresh)
        self.rowsAppended.emit(len(fresh))
        self.blocksChanged.emit()

    def shed_memory(self, keep_rows: int) -> int:
        """Under memory pressure: drop cached entries/explanations and all but the newest
        ``keep_rows`` rows (they stay in the database). Returns rows dropped."""
        self._cache.clear()
        self._explanations.clear()
        self._requested.clear()
        drop = max(0, len(self._ids) - keep_rows)
        if drop:
            self._drop_head(drop)
        return drop

    def _drop_head(self, count: int) -> None:
        count = min(count, len(self._ids))
        self.beginRemoveRows(QModelIndex(), 0, count - 1)
        del self._ids[:count]
        del self._sev[:count]
        self.endRemoveRows()
        self._blocks = _blocks(self._sev, 0, array("b"))
        self._match_rows = [r - count for r in self._match_rows if r >= count]
        self._requested.clear()

    @property
    def paused(self) -> bool:
        """True while live entries are held back."""
        return self._paused

    def set_paused(self, paused: bool) -> None:
        """Hold live entries (the view stays still); on resume show what arrived."""
        if paused == self._paused:
            return
        self._paused = paused
        if paused:
            return
        if self._stale:
            self.reload()
        else:
            held, self._paused_buffer = self._paused_buffer, []
            if held:
                self._append(held)

    @property
    def held_count(self) -> int:
        """Live entries waiting while paused."""
        return len(self._paused_buffer)

    # ------------------------------------------------------------------ entries and pages

    def entry_at(self, row: int) -> LogEntry | None:
        """The entry if loaded (requests its page otherwise)."""
        return self._entry(row) if 0 <= row < len(self._ids) else None

    def id_at(self, row: int) -> int:
        """Entry id of a row."""
        return self._ids[row]

    def row_of(self, entry_id: int) -> int | None:
        """Row of an entry id, if it is in this tab."""
        row = bisect.bisect_left(self._ids, entry_id)
        return row if row < len(self._ids) and self._ids[row] == entry_id else None

    def _entry(self, row: int) -> LogEntry | None:
        entry_id = self._ids[row]
        if entry_id in self._cache:
            self._cache.move_to_end(entry_id)
            return self._cache[entry_id]
        self._request_page(row // PAGE_ROWS)
        return self._cache.get(entry_id)  # set already if the worker answered synchronously

    def _request_page(self, page: int) -> None:
        if page in self._requested:
            return
        self._requested.add(page)
        token = self._token
        ids = list(self._ids[page * PAGE_ROWS : (page + 1) * PAGE_ROWS])
        self._worker.submit(
            lambda s: s.entries_by_id(ids),
            lambda entries: self._page_loaded(token, page, ids, entries),
            lambda exc: self._page_failed(token, page, exc),
        )

    def _page_loaded(self, token: int, page: int, ids: list[int], entries: list[LogEntry]) -> None:
        if token != self._token:
            return
        self._requested.discard(page)
        found = {e.id: e for e in entries}
        for entry_id in ids:
            self._remember(entry_id, found.get(entry_id))  # None: deleted by retention
        self.stats["pages"] += 1
        first = bisect.bisect_left(self._ids, ids[0]) if ids else 0
        last = min(first + len(ids), len(self._ids)) - 1
        if last >= first:
            self.dataChanged.emit(self.index(first, 0), self.index(last, len(Column) - 1))

    def _page_failed(self, token: int, page: int, exc: Exception) -> None:
        if token == self._token:
            self._requested.discard(page)
            log.warning("loading page %d failed: %s", page, exc)

    def _remember(self, entry_id: int, entry: LogEntry | None) -> None:
        self._cache[entry_id] = entry
        self._cache.move_to_end(entry_id)
        while len(self._cache) > CACHE_ENTRIES:
            self._cache.popitem(last=False)

    def entries_for_rows(self, rows: Sequence[int], done: Callable[[list[LogEntry]], None]) -> None:
        """Entries for ``rows`` (fetching what is not cached), in row order, to ``done``."""
        ids = [self._ids[r] for r in sorted(set(rows)) if 0 <= r < len(self._ids)]
        missing = [i for i in ids if i not in self._cache]

        def finish(fetched: list[LogEntry]) -> None:
            by_id = {e.id: e for e in fetched}
            for entry in fetched:
                self._remember(entry.id, entry)
            out = [by_id.get(i) or self._cache.get(i) for i in ids]
            done([e for e in out if e is not None])

        if missing:
            self._worker.submit(lambda s: s.entries_by_id(missing), finish)
        else:
            finish([])

    # ------------------------------------------------------------------ explanations

    def set_explainer(
        self, explainer: Callable[[LogEntry], Explanation | None] | None, inline_mode: str
    ) -> None:
        """How rows get explanations (for inline display) and how much to show."""
        self._explainer = explainer
        self.inline_mode = inline_mode
        self._explanations.clear()
        self._refresh_all()

    def explanation_for(self, entry: LogEntry) -> Explanation | None:
        """The (cached) explanation of a loaded entry, if an explainer is set."""
        if self._explainer is None:
            return None
        if entry.id in self._explanations:
            return self._explanations[entry.id]
        explanation = self._explainer(entry)
        self._explanations[entry.id] = explanation
        while len(self._explanations) > CACHE_ENTRIES:
            self._explanations.popitem(last=False)
        return explanation

    # ------------------------------------------------------------------ display

    def _display(self, entry: LogEntry, column: Column) -> str:
        """Display text: log content is hostile, so escapes/controls are neutralized."""
        return printable(self._display_raw(entry, column))

    def _display_raw(self, entry: LogEntry, column: Column) -> str:
        if column == Column.TIME:
            local = entry.timestamp.astimezone()
            return local.strftime("%m-%d %H:%M:%S.") + f"{local.microsecond // 1000:03d}"
        if column == Column.SOURCE:
            return self._names.get(entry.source_id) or entry.source_id.partition(":")[2]
        if column == Column.SEVERITY:
            return entry.severity.name
        if entry.id in self._expanded or "\n" not in entry.message:
            return entry.message
        return entry.message.split("\n", 1)[0]

    def toggle_expanded(self, row: int) -> bool:
        """Expand/collapse a multi-line entry; returns whether it is expanded now."""
        entry = self.entry_at(row)
        if entry is None or "\n" not in entry.message:
            return False
        if entry.id in self._expanded:
            self._expanded.discard(entry.id)
        else:
            self._expanded.add(entry.id)
        self.dataChanged.emit(self.index(row, 0), self.index(row, len(Column) - 1))
        return entry.id in self._expanded

    # ------------------------------------------------------------------ search

    @property
    def search(self) -> SearchSpec:
        """The current search."""
        return self._search

    @property
    def highlighter(self) -> Highlighter:
        """Span finder for the delegate."""
        return self._highlighter

    @property
    def match_rows(self) -> list[int]:
        """Rows that match the search, ascending."""
        return self._match_rows

    def set_search(self, spec: SearchSpec) -> None:
        """Highlight entries matching ``spec`` (runs in the background)."""
        self._search = spec
        self._highlighter = Highlighter(spec)
        self._match_ids = set()
        self._match_rows = []
        self._search_token += 1
        if self._highlighter.error:
            self.searchFinished.emit(0, self._highlighter.error)
        elif spec.active:
            self._run_search()
        else:
            self.searchFinished.emit(0, "")
        self._refresh_all()

    def _run_search(self) -> None:
        spec, token = self._search, self._search_token
        query = replace(
            self._query,
            text="" if spec.is_regex else spec.text,
            regex=spec.text if spec.is_regex else None,
            ignore_case=spec.ignore_case,
        )
        self._worker.submit(
            lambda s: _search_ids(s, query),
            lambda ids: self._search_done(token, ids),
            lambda exc: self._search_failed(token, exc),
        )

    def _search_done(self, token: int, ids: array[int]) -> None:
        if token != self._search_token:
            return
        rows = []
        for entry_id in ids:
            row = self.row_of(entry_id)
            if row is not None:
                rows.append(row)
        self._match_ids.update(ids)
        self._match_rows = sorted(set(rows) | set(self._match_rows))
        self.searchFinished.emit(len(self._match_rows), "")
        self.blocksChanged.emit()
        self._refresh_all()

    def _search_failed(self, token: int, exc: Exception) -> None:
        if token == self._search_token:
            self.searchFinished.emit(0, str(exc))

    def next_match(self, from_row: int, *, forward: bool = True) -> int | None:
        """The next (or previous) matching row after/before ``from_row``, wrapping."""
        rows = self._match_rows
        if not rows:
            return None
        if forward:
            i = bisect.bisect_right(rows, from_row)
            return rows[i % len(rows)]
        i = bisect.bisect_left(rows, from_row) - 1
        return rows[i % len(rows)]

    def _refresh_all(self) -> None:
        if self._ids:
            self.dataChanged.emit(self.index(0, 0), self.index(len(self._ids) - 1, len(Column) - 1))

    # ------------------------------------------------------------------ severity map

    def severity_blocks(self) -> tuple[int, array[int]]:
        """``(rows per block, worst severity of each block)`` for the severity map."""
        return BLOCK_ROWS, self._blocks

    # ------------------------------------------------------------------ export

    @staticmethod
    def as_text(entries: Sequence[LogEntry]) -> str:
        """Plain-text export: ISO time, level, source, message (raw line kept)."""
        return "\n".join(
            f"{e.timestamp.astimezone().isoformat(timespec='milliseconds')} "
            f"{e.severity.name:<8} {e.source_id} {e.message}"
            for e in entries
        )

    @staticmethod
    def as_json(entries: Sequence[LogEntry]) -> str:
        """JSON export: one object per entry."""
        return json.dumps(
            [
                {
                    "id": e.id,
                    "source": e.source_id,
                    "time": e.timestamp.isoformat(),
                    "severity": e.severity.name.lower(),
                    "message": e.message,
                    "raw": e.raw,
                    "fields": dict(e.fields),
                }
                for e in entries
            ],
            indent=2,
            ensure_ascii=False,
            default=str,
        )


def plain_tooltip(text: str) -> str:
    """Tooltip markup that shows ``text`` literally.

    Qt renders a tooltip as HTML when it looks like HTML, so log text such as
    ``<a href=...>`` or ``<img src=...>`` would be displayed as rich content. Escaping it
    and setting it in an explicit rich-text block keeps it inert (newlines preserved).
    """
    return f'<p style="white-space:pre-wrap">{html.escape(text)}</p>'


def _search_ids(storage: Storage, query: EntryQuery) -> array[int]:
    return storage.entry_ids(query)[0]


def _blocks(sev: array[int], first_row: int, blocks: array[int]) -> array[int]:
    """Recompute block maxima from ``first_row``'s block on (cheap for appends)."""
    start_block = first_row // BLOCK_ROWS
    del blocks[start_block:]
    for start in range(start_block * BLOCK_ROWS, len(sev), BLOCK_ROWS):
        blocks.append(max(sev[start : start + BLOCK_ROWS]))
    return blocks
