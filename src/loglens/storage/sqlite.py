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
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

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
)

_SELECT = """
    SELECT e.id, s.id, e.ts, e.severity, e.message, e.raw, e.fields, e.parsed
    FROM entries e JOIN sources s ON s.key = e.source
"""


class StorageError(RuntimeError):
    """The database cannot be used (e.g. created by a newer LogLens)."""


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

        Every whitespace-separated word must match (as a phrase: ``10.0.0.5`` works);
        FTS5 query syntax is neutralized, so user input cannot break the query.
        """
        query = " ".join('"' + word.replace('"', '""') + '"' for word in text.split())
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
