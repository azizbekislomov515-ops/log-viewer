"""SQLite persistence: entries, per-source resume cursors, FTS5 search, retention.

* WAL mode: the GUI/CLI can read while the pipeline writes.
* Entries and the cursors of the records they came from are written in **one
  transaction**, so after a crash the stored cursor never points past (dupes on resume)
  or before (lost lines) what is in the database.
* Entry ids are explicit and monotonically increasing (``AUTOINCREMENT`` sequence), so
  ids are never reused even after retention deletes the newest rows.
* All methods are thread-safe (one connection guarded by a lock); the pipeline calls
  them from a worker thread.
"""

from __future__ import annotations

import json
import logging
import os
import sqlite3
import threading
import time
from array import array
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import regex

from loglens.core.models import LogEntry, LogSource, Severity, utc_now

log = logging.getLogger(__name__)

_EPOCH = datetime(1970, 1, 1, tzinfo=UTC)
_US = timedelta(microseconds=1)

#: Migration N (index N-1) upgrades the schema from version N-1 to N. Append only.
MIGRATIONS: tuple[str, ...] = (
    """
    CREATE TABLE sources (
        key          INTEGER PRIMARY KEY,
        id           TEXT NOT NULL UNIQUE,
        kind         TEXT NOT NULL,
        display_name TEXT NOT NULL,
        cursor       TEXT,
        updated_at   INTEGER
    );
    CREATE TABLE entries (
        id       INTEGER PRIMARY KEY AUTOINCREMENT,
        source   INTEGER NOT NULL,      -- sources.key
        ts       INTEGER NOT NULL,      -- microseconds since epoch, UTC
        severity INTEGER NOT NULL,
        message  TEXT NOT NULL,
        raw      TEXT,                  -- NULL when identical to message
        fields   TEXT,                  -- JSON object, NULL when empty
        parsed   INTEGER NOT NULL DEFAULT 0
    );
    CREATE INDEX entries_source_ts ON entries(source, ts);
    CREATE VIRTUAL TABLE entries_fts USING fts5(
        message, content='entries', content_rowid='id'
    );
    -- No insert trigger: write_batch() indexes each batch with one INSERT ... SELECT,
    -- ~4x faster than a per-row trigger. Deletions are kept in sync by this trigger.
    CREATE TRIGGER entries_ad AFTER DELETE ON entries BEGIN
        INSERT INTO entries_fts(entries_fts, rowid, message)
        VALUES ('delete', old.id, old.message);
    END;
    """,
    # 2: the GUI pages a filtered view by id. This covering index serves
    # "WHERE source IN (...) [AND severity/ts filters] ORDER BY id" without a sort.
    """
    CREATE INDEX entries_source_id ON entries(source, id, severity, ts);
    """,
)

#: A regex search gives up after this long in total ...
REGEX_BUDGET_S = 10.0
#: ... or when one message takes longer than this (catastrophic backtracking).
REGEX_LINE_TIMEOUT_S = 0.05

_SELECT = """
    SELECT e.id, s.id, e.ts, e.severity, e.message, e.raw, e.fields, e.parsed
    FROM entries e JOIN sources s ON s.key = e.source
"""


class StorageError(RuntimeError):
    """The database cannot be used (e.g. created by a newer LogLens)."""


class SearchError(ValueError):
    """A search could not run: invalid regex, or it was too slow and was stopped."""


@dataclass(frozen=True, slots=True)
class EntryQuery:
    """A filtered view of entries, ordered by id (= arrival order).

    ``severities`` None means all. ``text`` is a full-text query (every word must match,
    see ``search``); ``regex`` is a Python-style regular expression run on the message.
    """

    source_ids: tuple[str, ...]
    severities: frozenset[Severity] | None = None
    since: datetime | None = None
    until: datetime | None = None
    text: str = ""
    regex: str | None = None
    ignore_case: bool = True

    def accepts(self, entry: LogEntry) -> bool:
        """Whether ``entry`` belongs to this view, ignoring ``text``/``regex``."""
        return (
            entry.source_id in self.source_ids
            and (self.severities is None or entry.severity in self.severities)
            and (self.since is None or entry.timestamp >= self.since)
            and (self.until is None or entry.timestamp <= self.until)
        )


@dataclass(frozen=True, slots=True)
class RetentionPolicy:
    """Delete entries older than ``max_age`` and keep at most ``max_rows_per_source``.

    ``None`` disables that rule.
    """

    max_age: timedelta | None = timedelta(days=7)
    max_rows_per_source: int | None = 100_000


def default_db_path() -> Path:
    """``$XDG_DATA_HOME/loglens/loglens.db`` (``~/.local/share/loglens/loglens.db``)."""
    base = os.environ.get("XDG_DATA_HOME") or str(Path.home() / ".local" / "share")
    return Path(base) / "loglens" / "loglens.db"


class Storage:
    """The LogLens database. Use as a context manager or call ``close()``."""

    def __init__(self, path: Path | str) -> None:
        in_memory = str(path) == ":memory:"
        if not in_memory:
            path = Path(path)
            path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            path.touch(mode=0o600, exist_ok=True)  # logs are sensitive: owner-only
        self._conn = sqlite3.connect(str(path), check_same_thread=False, isolation_level=None)
        self._lock = threading.Lock()
        self._keys: dict[str, int] = {}
        mode = self._conn.execute("PRAGMA journal_mode=WAL").fetchone()[0]
        if not in_memory and mode != "wal":
            raise StorageError(f"cannot enable WAL mode on {path} (got {mode!r})")
        self._conn.execute("PRAGMA synchronous=NORMAL")  # durable at checkpoints; fast
        self._conn.execute("PRAGMA busy_timeout=5000")
        migrate(self._conn)

    def __enter__(self) -> Storage:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def close(self) -> None:
        """Close the connection."""
        with self._lock:
            self._conn.close()

    # -- writes ------------------------------------------------------------------------

    def upsert_source(self, source: LogSource) -> None:
        """Record (or refresh) a source's kind and display name."""
        with self._lock:
            self._conn.execute(
                "INSERT INTO sources(id, kind, display_name) VALUES (?, ?, ?) "
                "ON CONFLICT(id) DO UPDATE SET kind=excluded.kind, "
                "display_name=excluded.display_name",
                (source.id, source.kind.value, source.display_name),
            )

    def write_batch(
        self, entries: Sequence[LogEntry], cursors: Mapping[str, str]
    ) -> list[LogEntry]:
        """Insert entries and update resume cursors atomically; return entries with ids."""
        rows = []
        with self._lock, self._transaction():
            seq = self._conn.execute(
                "SELECT seq FROM sqlite_sequence WHERE name = 'entries'"
            ).fetchone()
            first_id = (seq[0] if seq else 0) + 1
            for e in entries:
                fields = json.dumps(dict(e.fields), separators=(",", ":"), default=str)
                rows.append((
                    self._key(e.source_id),
                    (e.timestamp - _EPOCH) // _US,
                    int(e.severity),
                    e.message,
                    None if e.raw == e.message else e.raw,
                    fields if e.fields else None,
                    int(e.parsed),
                ))  # fmt: skip
            self._conn.executemany(
                "INSERT INTO entries(id, source, ts, severity, message, raw, fields, parsed) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                [(first_id + i, *row) for i, row in enumerate(rows)],
            )
            if rows:
                self._conn.execute(
                    "INSERT INTO entries_fts(rowid, message) "
                    "SELECT id, message FROM entries WHERE id BETWEEN ? AND ?",
                    (first_id, first_id + len(rows) - 1),
                )
            now = (utc_now() - _EPOCH) // _US
            self._conn.executemany(
                "UPDATE sources SET cursor = ?, updated_at = ? WHERE key = ?",
                [(cur, now, self._key(sid)) for sid, cur in cursors.items()],
            )
        return [replace(e, id=first_id + i) for i, e in enumerate(entries)]

    def apply_retention(self, policy: RetentionPolicy, now: datetime | None = None) -> int:
        """Delete entries the policy no longer allows; return how many were deleted."""
        deleted = 0
        with self._lock, self._transaction():
            keys = [k for (k,) in self._conn.execute("SELECT key FROM sources")]
            for key in keys:
                if policy.max_age is not None:
                    cutoff = ((now or utc_now()) - policy.max_age - _EPOCH) // _US
                    deleted += self._conn.execute(
                        "DELETE FROM entries WHERE source = ? AND ts < ?", (key, cutoff)
                    ).rowcount
                if policy.max_rows_per_source is not None:
                    boundary = self._conn.execute(
                        "SELECT ts, id FROM entries WHERE source = ? "
                        "ORDER BY ts DESC, id DESC LIMIT 1 OFFSET ?",
                        (key, policy.max_rows_per_source),
                    ).fetchone()
                    if boundary is not None:
                        deleted += self._conn.execute(
                            "DELETE FROM entries WHERE source = ? "
                            "AND (ts < ? OR (ts = ? AND id <= ?))",
                            (key, boundary[0], boundary[0], boundary[1]),
                        ).rowcount
        if deleted:
            log.info("retention deleted entries", extra={"deleted": deleted})
        return deleted

    # -- reads -------------------------------------------------------------------------

    def cursor_for(self, source_id: str) -> str | None:
        """The resume cursor stored for ``source_id``, if any."""
        with self._lock:
            row = self._conn.execute(
                "SELECT cursor FROM sources WHERE id = ?", (source_id,)
            ).fetchone()
        return row[0] if row else None

    def tail(
        self, source_id: str, *, since: datetime | None = None, limit: int = 100
    ) -> list[LogEntry]:
        """The newest ``limit`` entries of a source (optionally since a time), oldest first."""
        since_us = (since - _EPOCH) // _US if since is not None else -(2**62)
        with self._lock:
            rows = self._conn.execute(
                f"{_SELECT} WHERE s.id = ? AND e.ts >= ? ORDER BY e.ts DESC, e.id DESC LIMIT ?",
                (source_id, since_us, limit),
            ).fetchall()
        return [_entry(r) for r in reversed(rows)]

    def search(
        self, text: str, *, source_ids: Iterable[str] = (), limit: int = 100
    ) -> list[LogEntry]:
        """Full-text search on messages, newest first.

        Every whitespace-separated word must match as a prefix (``fail`` finds "Failed";
        ``10.0.0.5`` works as a phrase);
        FTS5 query syntax is neutralized, so user input cannot break the query.
        """
        query = _fts_query(text)
        if not query:
            return []
        ids = list(source_ids)
        source_filter = f"AND s.id IN ({','.join('?' * len(ids))})" if ids else ""
        sql = (
            f"{_SELECT} JOIN entries_fts f ON f.rowid = e.id "
            f"WHERE entries_fts MATCH ? {source_filter} ORDER BY e.id DESC LIMIT ?"
        )
        with self._lock:
            rows = self._conn.execute(sql, (query, *ids, limit)).fetchall()
        return [_entry(r) for r in rows]

    def entry_ids(self, query: EntryQuery) -> tuple[array[int], array[int]]:
        """Ids (ascending) and severities of every entry the query selects.

        Two compact arrays (9 bytes per row) instead of entries, so a view of millions of
        rows can be paged by row number. Raises ``SearchError`` for a bad or too slow regex.
        """
        ids: array[int] = array("q")
        severities: array[int] = array("b")
        with self._lock:
            sql, params = self._query_sql(query)
            matcher = _RegexMatcher(query) if query.regex else None
            if matcher is not None:
                self._conn.create_function("loglens_match", 1, matcher, deterministic=True)
                deadline = time.monotonic() + REGEX_BUDGET_S
                self._conn.set_progress_handler(lambda: time.monotonic() > deadline, 10_000)
            try:
                for entry_id, severity in self._conn.execute(sql, params):
                    ids.append(entry_id)
                    severities.append(severity)
            except sqlite3.OperationalError as exc:
                if matcher is None:
                    raise
                if matcher.timed_out:
                    raise SearchError(
                        "regex is too slow on a line (catastrophic backtracking)"
                    ) from None
                if "interrupted" in str(exc):
                    raise SearchError(f"regex search stopped after {REGEX_BUDGET_S:g} s") from None
                raise
            finally:
                if matcher is not None:
                    self._conn.set_progress_handler(None, 0)
        return ids, severities

    def severity_histogram(
        self,
        source_ids: Sequence[str],
        since: datetime,
        bucket: timedelta,
        until: datetime | None = None,
    ) -> list[tuple[datetime, Severity, int]]:
        """Entry counts per ``bucket``-long interval and severity since ``since``: exact
        numbers for timelines however many entries there are."""
        size = max(bucket // _US, 1)
        start = (since - _EPOCH) // _US
        end = (until - _EPOCH) // _US if until is not None else 2**62
        with self._lock:
            keys = self._source_keys(source_ids)
            rows = self._conn.execute(
                f"SELECT ts / ? AS b, severity, COUNT(*) FROM entries "  # noqa: S608
                f"WHERE source IN ({_marks(keys)}) AND ts >= ? AND ts <= ? "
                "GROUP BY b, severity ORDER BY b",
                (size, *keys, start, end),
            ).fetchall()
        return [(_EPOCH + b * size * _US, Severity(sev), n) for b, sev, n in rows]

    def entries_by_id(self, ids: Sequence[int]) -> list[LogEntry]:
        """Entries for ``ids`` in the given order; ids that no longer exist are skipped."""
        if not ids:
            return []
        marks = ",".join("?" * len(ids))
        with self._lock:
            rows = self._conn.execute(f"{_SELECT} WHERE e.id IN ({marks})", list(ids)).fetchall()
        by_id = {r[0]: _entry(r) for r in rows}
        return [by_id[i] for i in ids if i in by_id]

    def _query_sql(self, query: EntryQuery) -> tuple[str, list[Any]]:
        """SQL for ``entry_ids`` (call with the lock held). Source keys are resolved first:
        with one source, ``source = ?`` lets the covering index return rows in id order
        (no sort); several sources need a sort, which SQLite does in its temp B-tree."""
        keys = self._source_keys(query.source_ids)
        where = ["source = ?" if len(keys) == 1 else f"source IN ({_marks(keys)})"]
        params: list[Any] = list(keys)
        if query.severities is not None:
            where.append(f"severity IN ({_marks(query.severities)})")
            params += sorted(int(s) for s in query.severities)
        if query.since is not None:
            where.append("ts >= ?")
            params.append((query.since - _EPOCH) // _US)
        if query.until is not None:
            where.append("ts <= ?")
            params.append((query.until - _EPOCH) // _US)
        if query.regex:
            where.append("loglens_match(message)")
        elif fts := _fts_query(query.text):
            where.append("id IN (SELECT rowid FROM entries_fts WHERE entries_fts MATCH ?)")
            params.append(fts)
        # Only "?" placeholders and fixed SQL fragments are interpolated; values are params.
        sql = f"SELECT id, severity FROM entries WHERE {' AND '.join(where)} ORDER BY id"  # noqa: S608
        return sql, params

    def _source_keys(self, source_ids: Sequence[str]) -> list[int]:
        """Integer keys of known source ids (call with the lock held)."""
        return [
            key
            for (key,) in self._conn.execute(
                f"SELECT key FROM sources WHERE id IN ({_marks(source_ids)})",  # noqa: S608
                list(source_ids),
            )
        ]

    def count(self, source_id: str | None = None) -> int:
        """Number of stored entries (for one source or all)."""
        with self._lock:
            if source_id is None:
                return int(self._conn.execute("SELECT COUNT(*) FROM entries").fetchone()[0])
            return int(
                self._conn.execute(
                    "SELECT COUNT(*) FROM entries e JOIN sources s ON s.key = e.source "
                    "WHERE s.id = ?",
                    (source_id,),
                ).fetchone()[0]
            )

    # -- internals ---------------------------------------------------------------------

    def _transaction(self) -> _Transaction:
        return _Transaction(self._conn, self._keys)

    def _key(self, source_id: str) -> int:
        """Integer key for a source id, creating a minimal row on first use."""
        key = self._keys.get(source_id)
        if key is None:
            kind = source_id.partition(":")[0]
            self._conn.execute(
                "INSERT INTO sources(id, kind, display_name) VALUES (?, ?, ?) "
                "ON CONFLICT(id) DO NOTHING",
                (source_id, kind, source_id),
            )
            key = int(
                self._conn.execute("SELECT key FROM sources WHERE id = ?", (source_id,)).fetchone()[
                    0
                ]
            )
            self._keys[source_id] = key
        return key


class _Transaction:
    """``BEGIN IMMEDIATE`` ... ``COMMIT``; on error roll back and forget cached keys."""

    def __init__(self, conn: sqlite3.Connection, keys: dict[str, int]) -> None:
        self._conn = conn
        self._keys = keys

    def __enter__(self) -> None:
        self._conn.execute("BEGIN IMMEDIATE")

    def __exit__(self, exc_type: object, *_: object) -> None:
        if exc_type is None:
            self._conn.execute("COMMIT")
        else:
            self._conn.execute("ROLLBACK")
            self._keys.clear()  # keys created inside the rolled-back transaction are gone


def migrate(conn: sqlite3.Connection) -> int:
    """Bring the schema to the latest version; return that version.

    Raises:
        StorageError: if the database was created by a newer version of LogLens.
    """
    conn.execute("CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL)")
    row = conn.execute("SELECT version FROM schema_version").fetchone()
    version = row[0] if row else 0
    if version > len(MIGRATIONS):
        raise StorageError(
            f"database schema v{version} is newer than this LogLens (v{len(MIGRATIONS)})"
        )
    for target, script in enumerate(MIGRATIONS[version:], start=version + 1):
        # executescript() cannot take parameters; the version is our own integer.
        try:
            conn.executescript(
                f"BEGIN IMMEDIATE;\n{script}\n"
                "DELETE FROM schema_version;\n"
                f"INSERT INTO schema_version(version) VALUES ({int(target)});\n"
                "COMMIT;"
            )
        except sqlite3.Error:
            if conn.in_transaction:
                conn.execute("ROLLBACK")
            raise
        log.info("database migrated", extra={"version": target})
    return len(MIGRATIONS)


def _fts_query(text: str) -> str:
    """Every word as a quoted prefix phrase (``"fail"*`` finds "Failed"): FTS5 syntax in
    user input cannot break the query."""
    return " ".join('"' + word.replace('"', '""') + '"*' for word in text.split())


def _marks(values: Iterable[object]) -> str:
    return ",".join("?" for _ in values) or "NULL"


class _RegexMatcher:
    """SQL function body. ``regex`` (not ``re``) so one line can time out, and
    ``concurrent=True`` so matching releases the GIL and never freezes the GUI thread.
    SQLite hides the exception a function raises, so a timeout is also flagged here."""

    def __init__(self, query: EntryQuery) -> None:
        flags = regex.IGNORECASE if query.ignore_case else 0
        try:
            self._pattern = regex.compile(query.regex or "", flags)
        except regex.error as exc:
            raise SearchError(f"invalid regex: {exc}") from None
        self.timed_out = False

    def __call__(self, message: str) -> bool:
        try:
            found = self._pattern.search(message, timeout=REGEX_LINE_TIMEOUT_S, concurrent=True)
        except TimeoutError:
            self.timed_out = True
            raise
        return found is not None


def _entry(row: tuple[Any, ...]) -> LogEntry:
    entry_id, source_id, ts, severity, message, raw, fields, parsed = row
    return LogEntry(
        id=entry_id,
        source_id=source_id,
        timestamp=_EPOCH + ts * _US,
        severity=Severity(severity),
        message=message,
        raw=message if raw is None else raw,
        fields=json.loads(fields) if fields else {},
        parsed=bool(parsed),
    )
