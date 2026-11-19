"""Phase 5 storage reads for the GUI: filtered id lists, pages by id, timed regex search."""

import sqlite3
from datetime import UTC, datetime, timedelta

import pytest

from loglens.core.models import LogEntry, Severity
from loglens.storage import EntryQuery, SearchError, Storage
from loglens.storage import sqlite as sqlite_mod

T0 = datetime(2026, 11, 18, 12, 0, tzinfo=UTC)


def entry(source: str, minute: int, severity: Severity, message: str) -> LogEntry:
    return LogEntry(0, source, T0 + timedelta(minutes=minute), severity, message, message)


@pytest.fixture
def db() -> Storage:
    storage = Storage(":memory:")
    storage.write_batch(
        [
            entry("a", 0, Severity.INFO, "service started on port 80"),
            entry("b", 1, Severity.ERROR, "connection refused from 10.0.0.5"),
            entry("a", 2, Severity.WARNING, "slow request 10.0.0.5"),
            entry("a", 3, Severity.ERROR, "Failed password for root"),
            entry("c", 4, Severity.CRITICAL, "out of memory"),
        ],
        {},
    )
    return storage


def ids(db: Storage, **kw: object) -> list[int]:
    return list(db.entry_ids(EntryQuery(**kw))[0])  # type: ignore[arg-type]


def test_entry_ids_filters_and_order(db: Storage) -> None:
    assert ids(db, source_ids=("a",)) == [1, 3, 4]
    assert ids(db, source_ids=("a", "b")) == [1, 2, 3, 4]
    assert list(db.entry_ids(EntryQuery(("a",)))[1]) == [2, 4, 5]  # severities alongside
    errors = frozenset({Severity.ERROR, Severity.CRITICAL})
    assert ids(db, source_ids=("a", "b", "c"), severities=errors) == [2, 4, 5]
    assert ids(db, source_ids=("a",), since=T0 + timedelta(minutes=2)) == [3, 4]
    assert ids(db, source_ids=("a",), until=T0 + timedelta(minutes=2)) == [1, 3]
    assert ids(db, source_ids=("nope",)) == []
    assert ids(db, source_ids=()) == []


def test_entry_ids_full_text(db: Storage) -> None:
    assert ids(db, source_ids=("a", "b"), text="10.0.0.5") == [2, 3]
    assert ids(db, source_ids=("a", "b"), text='refused "10.0.0.5') == [2]  # quotes neutralized


def test_entry_ids_regex(db: Storage) -> None:
    assert ids(db, source_ids=("a", "b", "c"), regex=r"port \d+$") == [1]
    assert ids(db, source_ids=("a",), regex="failed") == [4]  # ignore_case by default
    assert ids(db, source_ids=("a",), regex="failed", ignore_case=False) == []
    with pytest.raises(SearchError, match="invalid regex"):
        ids(db, source_ids=("a",), regex="(unclosed")


def test_catastrophic_regex_is_stopped_not_hung(db: Storage) -> None:
    db.write_batch([entry("a", 5, Severity.INFO, "a" * 40 + "!")], {})
    with pytest.raises(SearchError, match="too slow"):
        ids(db, source_ids=("a",), regex=r"(a|aa)+$")
    assert ids(db, source_ids=("a",), regex="started") == [1]  # connection still usable


def test_regex_search_has_a_total_time_budget(db: Storage, monkeypatch: pytest.MonkeyPatch) -> None:
    db.write_batch([entry("a", 6, Severity.INFO, f"line {i}") for i in range(20_000)], {})
    monkeypatch.setattr(sqlite_mod, "REGEX_BUDGET_S", 0.0)
    with pytest.raises(SearchError, match="stopped after"):
        ids(db, source_ids=("a",), regex="never matches")


def test_entries_by_id_keeps_order_and_skips_missing(db: Storage) -> None:
    got = db.entries_by_id([4, 1, 999, 2])
    assert [e.id for e in got] == [4, 1, 2]
    assert got[0].message == "Failed password for root"
    assert db.entries_by_id([]) == []


def test_query_accepts_mirrors_the_sql_filter() -> None:
    query = EntryQuery(("a",), frozenset({Severity.ERROR}), since=T0, until=T0 + timedelta(1))
    assert query.accepts(entry("a", 1, Severity.ERROR, "x"))
    assert not query.accepts(entry("b", 1, Severity.ERROR, "x"))
    assert not query.accepts(entry("a", 1, Severity.INFO, "x"))
    assert not query.accepts(entry("a", -1, Severity.ERROR, "x"))
    assert not query.accepts(entry("a", 60 * 25, Severity.ERROR, "x"))


def test_covering_index_serves_the_view_query(db: Storage) -> None:
    sql, params = db._query_sql(EntryQuery(("a",)))
    plan = " ".join(str(r) for r in db._conn.execute(f"EXPLAIN QUERY PLAN {sql}", params))
    assert "entries_source_id" in plan
    assert "TEMP B-TREE" not in plan  # one source: the index is already in id order


def test_other_operational_errors_propagate(db: Storage) -> None:
    db._conn.execute("DROP TABLE entries_fts")
    with pytest.raises(sqlite3.OperationalError):
        ids(db, source_ids=("a",), text="x")
