# LogLens GUI (Phase 5)

`loglens` starts the desktop app; `loglens --demo` replays sample logs through the real
pipeline (no Docker or root needed). Screenshots in [`screenshots/`](screenshots/) are
rendered offscreen from demo data with
`QT_QPA_PLATFORM=offscreen python -m loglens.gui.screenshots docs/screenshots`.

| | |
|---|---|
| ![main](screenshots/main-search-dark.png) | ![light](screenshots/compose-merged-light.png) |
| Search highlights, severity rail, unread badges | Compose project merged, one color per service |

## Layout

* **Sources** (left dock): System services / Docker Compose (project → services) /
  Standalone containers / Log files (group → files). Each row: kind icon, status shape
  (filled dot running, ring stopped, cross failed), unread-error badge, pin mark. Filter
  box on top. Context menu: Open, Open in new tab, Pin (follow in background), Copy ID,
  Look for new sources now. Click opens (or focuses) the source's tab; a Compose project or
  file group opens one merged tab.
* **Tabs** (center): one per source or group. Group tabs show every service merged, the
  service name in a stable per-service color; **Split** shows one pane per service.
* **Toolbar**: search (FTS5 prefix words, or `.*` regex), previous/next match and count,
  severity chips, time range (Live, 5 min, 1 h, 24 h, custom), Pause, Follow, Wrap, Split.
  Filters belong to the tab: switching tabs shows that tab's filters; they persist in
  `~/.local/state/loglens/session.json` with the open tabs.
* **Status bar**: pipeline lines/s, followed sources, stored entries, issues button.
* **Discovery issues** (bottom dock): each `DiscoveryIssue` and collector error with its
  "How to fix" text.
* **Settings** (Ctrl+,): theme, retention, extra rule-pack folders, hidden-source patterns,
  discovery interval; saved to `~/.config/loglens/config.toml` (0600, atomic write).

## Design system

One token table per theme (`gui/theme.py`) drives the QPalette, the single stylesheet and
everything custom-painted. Dark: graphite `#111418` / `#171B21` / `#222832`, steel-blue
accent `#7AB8F5`. Light: white canvas, `#F4F5F7` panels, `#1E66B0` accent. Follows the
desktop color scheme by default (and live, when it changes).

Severity is the product's signal, so it carries the identity: Okabe-Ito colorblind-safe
hues (vermilion error, orange warning, reddish-purple critical, sky-blue notice), each
paired with a **shape** in the row's rail (◆ critical, ▲ error, ● warning, ○ notice) and
the same shapes on the filter chips, so color is never the only cue. Every text color
meets WCAG 4.5:1 on both backgrounds in both themes (tested).

The signature element is the **severity map**: the strip beside the scrollbar compresses
the whole tab (a million rows) into its height. Errors and criticals are full-width
marks, warnings a thin edge, search hits ticks on the left, and the visible window a
frame. Click or drag to jump.

## Threads and data flow

```
asyncio thread (Backend)                         GUI thread
  discovery every N s ── sourcesChanged ───────▶  SourceTreeModel.update
  IngestPipeline ── stored batch ─▶ deque ──(100 ms drain timer)──▶ every tab's model
  stats every 1 s ──── statsChanged ───────────▶  status bar
reader thread (DbWorker, own SQLite connection)
  entry_ids(query) / entries_by_id(page) / timed regex ◀── submit ── LogTableModel
                                                ── done (queued signal) ──▶
```

The GUI thread never touches SQLite or a subprocess. GUI → backend calls
(`follow`, `unfollow`, `refresh_discovery`) are `call_soon_threadsafe` and return at once.
Entries arrive at tens of thousands per second, so they go through a deque drained once per
100 ms tick (one model update per tick, not one signal per batch). The window is built and
connected before the backend starts, so the first discovery result is never lost.

## The log view

`LogTableModel` (a `QAbstractTableModel`) holds two arrays per tab: entry ids (ascending)
and severities (9 bytes per row). They come from one background query on the covering index
`entries(source, id, severity, ts)`. Entries are fetched 256 rows at a time, on demand, into
a 20k-entry LRU cache. Until a page arrives the row shows a placeholder, but its severity
(row tint, rail, map) is already known. Live entries are filtered with the tab's query
(`EntryQuery.accepts`) and appended at the end. Ids only grow, so appends never move
existing rows, and anything the initial query already returned is ignored by id.

The view is a `QTableView`, not a `QTreeView`. At 1M rows QTreeView relays out every row
on each insert (775 ms per 400-row append, measured), while QTableView takes about 6 ms.
Row heights live in the vertical header: expanded multi-line entries (double-click, Enter
or the menu) and wrapped rows resize only themselves. Wrap measures just the rows on
screen, again whenever you scroll or resize.

Other details:

* Follow-bottom turns off when you scroll up or jump to a match, and back on at the
  bottom or with End.
* Pause holds live entries (up to 200k, then the tab reloads on resume).
* Copy (Ctrl+C or menu) exports the selection as text or JSON, fetching unloaded rows in
  the background.
* A row that retention deleted shows "no longer stored" instead of loading forever.

## Search

Plain search is FTS5: every word must match as a prefix (`fail` finds "Failed"), and
quotes and FTS syntax are neutralized. Regex search uses the `regex` module as an SQLite
function with three safeguards:

* a 50 ms timeout per line (catastrophic backtracking stops instead of hanging);
* a 10 s total budget, enforced by a progress handler;
* `concurrent=True`, so matching releases the GIL and the GUI keeps painting.

Search highlights matches rather than filtering. Live entries are matched as they arrive,
and highlighting uses a 5 ms per-line timeout.

## Keyboard

| Keys | Action |
|---|---|
| Ctrl+K | Jump to any source (fuzzy: `cld` finds clamav-daemon) |
| Ctrl+F, Enter / F3, Shift+F3 | Search, next match, previous match |
| Ctrl+P | Pause / resume live updates |
| Ctrl+1 … Ctrl+9, Ctrl+W | Switch to tab N, close tab |
| Enter / double-click | Expand or collapse a multi-line entry |
| Ctrl+C | Copy selected entries |
| Ctrl+, | Settings |
| Ctrl+Alt+D | Debug overlay: frame time, rows/s, pages/s, drain time, backlog |

Every interactive widget has an accessible name; tab order follows the visual order.

## Measurements

Laptop (Kali, Python 3.13, PySide6 6.12), offscreen. Reproduce with
`uv run pytest tests/test_gui_stress.py -s`. "Frame interval" is how often a 16 ms timer
actually fires, so 16 ms is perfect and anything higher is an event-loop stall.

**20,000 lines/s into one tab**, real pipeline (assembler, parsers, SQLite with FTS),
while the user scrolls:

| | |
|---|---|
| Pipeline ingest | 19,973 lines/s |
| Rows shown in the tab | 20,004 rows/s (122,000 rows in 6.1 s) |
| GUI frame interval | avg 19.3 ms, p99 39.9 ms, max 44.0 ms |
| Drain per 100 ms tick | avg 3.2 ms, max 8.4 ms |

**One tab over 1,000,000 stored entries**:

| | |
|---|---|
| Id list load (background) | 0.33 s |
| Jump anywhere → rows painted | avg 40 ms, max 45 ms |
| GUI frame interval while scrolling | avg 16.0 ms, p99 25.3 ms, max 26.5 ms |

**Storage at 1M rows**: one source's id list 0.10 s; three sources merged 0.40 s; one page
of 256 entries 1.2 ms.

**Real machine** (systemd + Docker): all 153 discovered sources (after the default
`*.scope` / `user@*` filters) appear in the tree, in all four categories, with both Compose
projects grouped (5 and 3 services). Opening NetworkManager, journald and a stopped
Compose container loaded 499, 6 and 112 entries and kept following them.
