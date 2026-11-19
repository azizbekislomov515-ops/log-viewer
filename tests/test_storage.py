import sqlite3
import stat
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from loglens.collectors import source_from_id
from loglens.core.models import LogEntry, Severity
from loglens.storage import RetentionPolicy, Storage, StorageError
from loglens.storage.sqlite import MIGRATIONS, migrate

T0 = datetime(2026, 11, 17, 12, 0, tzinfo=UTC)


def entry(source: str, msg: str, at: datetime = T0, **fields: object) -> LogEntry:
    return LogEntry(0, source, at, Severity.INFO, msg, msg, fields)


@pytest.fixture
def db(tmp_path: Path):  # type: ignore[no-untyped-def]
    with Storage(tmp_path / "loglens.db") as storage:
        yield storage


def test_creates_private_wal_database_with_schema_version(tmp_path: Path) -> None:
    path = tmp_path / "sub" / "loglens.db"
    Storage(path).close()
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700
    conn = sqlite3.connect(path)
    assert conn.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
    assert conn.execute("SELECT version FROM schema_version").fetchone()[0] == len(MIGRATIONS)
    assert migrate(conn) == len(MIGRATIONS)  # idempotent


def test_refuses_newer_schema(tmp_path: Path) -> None:
    path = tmp_path / "x.db"
    Storage(path).close()
    with sqlite3.connect(path) as conn:
        conn.execute("UPDATE schema_version SET version = 999")
    with pytest.raises(StorageError, match="newer"):
        Storage(path)


def test_write_batch_assigns_monotonic_ids_and_saves_cursors(db: Storage) -> None:
    db.upsert_source(source_from_id("docker:web"))
    first = db.write_batch([entry("docker:web", "a"), entry("file:/x", "b")], {"docker:web": "c1"})
    second = db.write_batch([entry("docker:web", "c", stream="stderr")], {"docker:web": "c2"})
    assert [e.id for e in first + second] == [1, 2, 3]
    assert db.cursor_for("docker:web") == "c2"
    assert db.cursor_for("file:/x") is None
    assert db.cursor_for("nope") is None
    stored = db.tail("docker:web")
    assert [(e.message, dict(e.fields)) for e in stored] == [("a", {}), ("c", {"stream": "stderr"})]
    assert stored[0].timestamp == T0


def test_ids_never_reused_after_deleting_newest(db: Storage) -> None:
    db.write_batch([entry("s:a", "old", T0 - timedelta(days=30))], {})
    db.apply_retention(RetentionPolicy(max_age=timedelta(days=1)), now=T0)
    assert db.count() == 0
    assert db.write_batch([entry("s:a", "new")], {})[0].id == 2


def test_failed_batch_rolls_back_entries_and_cursor(db: Storage) -> None:
    db.write_batch([entry("s:a", "ok")], {"s:a": "c1"})
    with pytest.raises(TypeError):
        db.write_batch([entry("s:a", "x"), _unserializable(entry("s:a", "bad"))], {"s:a": "c2"})
    assert db.cursor_for("s:a") == "c1"
    assert [e.message for e in db.tail("s:a")] == ["ok"]


def _unserializable(e: LogEntry) -> LogEntry:
    class Boom:
        def __str__(self) -> str:
            raise TypeError("cannot serialize")

    return LogEntry(0, e.source_id, e.timestamp, e.severity, e.message, e.raw, {"x": Boom()})


def test_tail_since_and_limit(db: Storage) -> None:
    db.write_batch([entry("s:a", f"m{i}", T0 + timedelta(minutes=i)) for i in range(10)], {})
    assert [e.message for e in db.tail("s:a", limit=3)] == ["m7", "m8", "m9"]
    since = T0 + timedelta(minutes=8)
    assert [e.message for e in db.tail("s:a", since=since)] == ["m8", "m9"]


def test_search(db: Storage) -> None:
    db.write_batch(
        [
            entry("squid:x", "TCP_DENIED 10.0.0.5 GET http://facebook.com/"),
            entry("squid:x", "TCP_MISS 10.0.0.7 GET http://example.com/"),
            entry("nginx:x", 'client 10.0.0.5 said "hi" (AND) NOT* col:on'),
        ],
        {},
    )
    assert [e.source_id for e in db.search("10.0.0.5")] == ["nginx:x", "squid:x"]  # newest first
    assert len(db.search("10.0.0.5", source_ids=["squid:x"])) == 1
    assert len(db.search("denied facebook")) == 1  # all words, case-insensitive
    # FTS syntax in user input is treated as text, never as query operators
    for query in ['"hi"', "(AND)", "NOT*", "col:on", "'", '"']:
        db.search(query)
    assert db.search("   ") == []


def test_retention_by_age_and_rows(db: Storage) -> None:
    old = [entry("s:a", f"old{i}", T0 - timedelta(days=10, minutes=i)) for i in range(3)]
    new = [entry("s:a", f"new{i}", T0 + timedelta(seconds=i)) for i in range(5)]
    other = [entry("s:b", f"b{i}", T0) for i in range(3)]  # same timestamp everywhere
    db.write_batch(old + new + other, {})
    deleted = db.apply_retention(
        RetentionPolicy(max_age=timedelta(days=7), max_rows_per_source=2), now=T0
    )
    assert deleted == 3 + 3 + 1
    assert [e.message for e in db.tail("s:a")] == ["new3", "new4"]
    assert [e.message for e in db.tail("s:b")] == ["b1", "b2"]  # ties broken by id
    assert db.search("old0") == []  # FTS index cleaned too
    assert db.apply_retention(RetentionPolicy(max_age=None, max_rows_per_source=None)) == 0


def test_concurrent_reader_sees_committed_data(tmp_path: Path) -> None:
    path = tmp_path / "x.db"
    with Storage(path) as writer, Storage(path) as reader:
        writer.write_batch([entry("s:a", "visible")], {})
        assert [e.message for e in reader.search("visible")] == ["visible"]
