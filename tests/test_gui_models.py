"""View-model tests (no widgets): the virtualized log model and the source tree."""

from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from pytestqt.qtbot import QtBot

from loglens.core.models import (
    GroupKind,
    LogEntry,
    LogSource,
    ServiceGroup,
    Severity,
    SourceKind,
    SourceStatus,
)
from loglens.gui import log_model
from loglens.gui.log_model import Column, Highlighter, LogTableModel, Role, SearchSpec
from loglens.gui.source_tree import NodeKind, SourceTreeModel, TreeRole
from loglens.gui.workers import SyncWorker
from loglens.storage import EntryQuery, Storage

T0 = datetime(2026, 11, 18, 12, 0, tzinfo=UTC)


class ManualWorker(SyncWorker):
    """Holds jobs until ``run_all`` (to test races with live appends)."""

    def __init__(self, storage: Storage) -> None:
        super().__init__(storage)
        self.jobs: list[tuple[Any, Callable[[Any], None], Any]] = []

    def submit(self, job: Any, done: Callable[[Any], None], failed: Any = None) -> None:
        self.jobs.append((job, done, failed))

    def run_all(self) -> None:
        while self.jobs:
            job, done, failed = self.jobs.pop(0)
            SyncWorker.submit(self, job, done, failed)


def make(
    source: str, i: int, severity: Severity = Severity.INFO, message: str | None = None
) -> LogEntry:
    text = message or f"{source} line {i}"
    return LogEntry(0, source, T0 + timedelta(seconds=i), severity, text, text)


@pytest.fixture
def db() -> Storage:
    storage = Storage(":memory:")
    storage.write_batch(
        [make("a", i, Severity.ERROR if i % 5 == 0 else Severity.INFO) for i in range(50)]
        + [make("b", i) for i in range(10)],
        {},
    )
    return storage


def store(db: Storage, *entries: LogEntry) -> list[LogEntry]:
    return db.write_batch(list(entries), {})


def test_initial_load_pages_and_display(qapp: Any, db: Storage) -> None:
    model = LogTableModel(SyncWorker(db), EntryQuery(("a",)), {"a": "Alpha"})
    model.reload()
    assert model.rowCount() == 50 and model.columnCount() == 4
    assert not model.loading
    index = model.index(3, Column.MESSAGE)
    assert index.data() == "a line 3"
    assert model.index(3, Column.SOURCE).data() == "Alpha"
    assert model.index(0, Column.SEVERITY).data() == "ERROR"
    assert model.index(0, Column.TIME).data().endswith(".000")
    assert index.data(Role.SEVERITY) == Severity.INFO
    assert index.data(Role.ENTRY).id == 4
    assert "info" in index.data(Qt_accessible()) and "a line 3" in index.data(Qt_accessible())
    assert model.headerData(Column.TIME, Qt_h()) == "Time"
    assert model.index(99, 0).data() is None
    assert model.rowCount(model.index(0, 0)) == 0


def Qt_accessible() -> int:
    from PySide6.QtCore import Qt  # noqa: PLC0415

    return int(Qt.ItemDataRole.AccessibleTextRole)


def Qt_h() -> Any:
    from PySide6.QtCore import Qt  # noqa: PLC0415

    return Qt.Orientation.Horizontal


def test_unloaded_rows_show_placeholder_until_the_page_arrives(
    qapp: Any, db: Storage, qtbot: QtBot
) -> None:
    worker = ManualWorker(db)
    model = LogTableModel(worker, EntryQuery(("a",)))
    model.reload()
    worker.run_all()
    index = model.index(10, Column.MESSAGE)
    assert index.data() == "…"
    assert index.data(Role.SEVERITY) == Severity.ERROR  # always known, before the page
    with qtbot.waitSignal(model.dataChanged):
        worker.run_all()
    assert index.data() == "a line 10"
    assert model.stats["pages"] == 1


def test_live_entries_are_filtered_and_appended(qapp: Any, db: Storage, qtbot: QtBot) -> None:
    query = EntryQuery(("a",), frozenset({Severity.ERROR}))
    model = LogTableModel(SyncWorker(db), query)
    model.reload()
    assert model.rowCount() == 10
    new = store(db, make("a", 100, Severity.ERROR), make("a", 101), make("b", 102, Severity.ERROR))
    with qtbot.waitSignal(model.rowsAppended) as blocker:
        assert model.append_live(new) == 1
    assert blocker.args == [1]
    assert model.rowCount() == 11
    assert model.index(10, Column.MESSAGE).data() == "a line 100"  # cached, no fetch
    assert model.append_live(new) == 1 and model.rowCount() == 11  # duplicate id ignored
    assert model.append_live([LogEntry(-1, "a", T0, Severity.ERROR, "mem", "mem")]) == 0


def test_live_entries_during_initial_load_are_not_duplicated(qapp: Any, db: Storage) -> None:
    worker = ManualWorker(db)
    model = LogTableModel(worker, EntryQuery(("a",)))
    model.reload()
    assert model.loading
    late = store(db, make("a", 200))  # stored before the query runs: it will return it too
    model.append_live(late)
    later = make("a", 201)
    worker.run_all()  # the id query sees id 61 (late), not id 62 yet
    model.append_live(store(db, later))
    assert model.rowCount() == 52
    assert [model.id_at(r) for r in (50, 51)] == [61, 62]


def test_pause_holds_entries_and_overflow_reloads(
    qapp: Any, db: Storage, monkeypatch: pytest.MonkeyPatch
) -> None:
    model = LogTableModel(SyncWorker(db), EntryQuery(("a",)))
    model.reload()
    model.set_paused(True)
    model.set_paused(True)
    model.append_live(store(db, make("a", 300), make("a", 301)))
    assert model.rowCount() == 50 and model.held_count == 2 and model.paused
    model.set_paused(False)
    assert model.rowCount() == 52 and model.held_count == 0
    monkeypatch.setattr(log_model, "PAUSE_BUFFER", 1)
    model.set_paused(True)
    model.append_live(store(db, make("a", 302), make("a", 303)))
    model.append_live(store(db, make("a", 304)))  # stale: ignored, reload on resume
    assert model.held_count == 0
    model.set_paused(False)
    assert model.rowCount() == 55


def test_search_highlights_and_navigates(qapp: Any, db: Storage, qtbot: QtBot) -> None:
    model = LogTableModel(SyncWorker(db), EntryQuery(("a",)))
    model.reload()
    with qtbot.waitSignal(model.searchFinished) as blocker:
        model.set_search(SearchSpec("line 1"))
    assert blocker.args == [len(model.match_rows), ""]
    assert model.match_rows[:2] == [1, 10]
    assert model.index(1, Column.MESSAGE).data(Role.MATCH)
    assert not model.index(2, Column.MESSAGE).data(Role.MATCH)
    assert model.next_match(1) == 10
    assert model.next_match(1, forward=False) == model.match_rows[-1]  # wraps
    assert model.next_match(model.match_rows[-1]) == 1
    model.append_live(store(db, make("a", 400, message="new line 1 here")))
    assert model.match_rows[-1] == 50  # live match picked up
    model.set_search(SearchSpec(r"line 4\d$", is_regex=True))
    assert len(model.match_rows) == 10
    with qtbot.waitSignal(model.searchFinished) as blocker:
        model.set_search(SearchSpec("(bad", is_regex=True))
    assert "invalid regex" in blocker.args[1]
    model.set_search(SearchSpec(""))
    assert model.next_match(0) is None and not model.search.active


def test_search_error_from_storage_is_reported(qapp: Any, db: Storage, qtbot: QtBot) -> None:
    db.write_batch([make("a", 500, message="a" * 40 + "!")], {})
    model = LogTableModel(SyncWorker(db), EntryQuery(("a",)))
    model.reload()
    with qtbot.waitSignal(model.searchFinished) as blocker:
        model.set_search(SearchSpec("(a|aa)+$", is_regex=True))
    assert "too slow" in blocker.args[1]


def test_highlighter_spans() -> None:
    plain = Highlighter(SearchSpec("Fail root"))
    assert plain.spans("Failed for ROOT, failed again") == [(0, 4), (11, 15), (17, 21)]
    assert plain.matches(make("a", 0, message="fail as root"))
    assert not plain.matches(make("a", 0, message="fail only"))
    rx = Highlighter(SearchSpec(r"\d+", is_regex=True))
    assert rx.spans("port 80 and 443") == [(5, 7), (12, 15)]
    assert Highlighter(SearchSpec("x*", is_regex=True)).spans("abc") == []  # empty matches
    slow = Highlighter(SearchSpec("(a|aa)+$", is_regex=True))
    assert slow.spans("a" * 40 + "!") == []  # timed out: no highlight, no hang
    assert Highlighter(SearchSpec("(", is_regex=True)).error


def test_multiline_collapse(qapp: Any, db: Storage) -> None:
    stack = store(
        db, make("a", 600, message="Traceback (most recent call last):\n  File x\nValueError")
    )
    model = LogTableModel(SyncWorker(db), EntryQuery(("a",)))
    model.reload()
    row = model.row_of(stack[0].id)
    assert row is not None
    index = model.index(row, Column.MESSAGE)
    assert index.data() == "Traceback (most recent call last):"
    assert index.data(Role.EXTRA_LINES) == 2
    assert model.toggle_expanded(row) is True
    assert index.data(Role.EXPANDED) and index.data().count("\n") == 2
    assert model.toggle_expanded(row) is False
    assert model.toggle_expanded(0) is False  # single-line entries don't expand
    assert model.row_of(10**9) is None


def test_copy_formats_and_unloaded_rows(qapp: Any, db: Storage) -> None:
    worker = ManualWorker(db)
    model = LogTableModel(worker, EntryQuery(("a",)))
    model.reload()
    worker.run_all()
    got: list[list[LogEntry]] = []
    model.entries_for_rows([2, 0, 2], got.append)
    worker.run_all()  # rows were not loaded: fetched in the background
    assert [e.id for e in got[0]] == [1, 3]
    text = LogTableModel.as_text(got[0])
    assert "ERROR" in text.splitlines()[0] and text.splitlines()[1].endswith("a line 2")
    data = __import__("json").loads(LogTableModel.as_json(got[0]))
    assert data[0]["severity"] == "error" and data[1]["message"] == "a line 2"
    model.entries_for_rows([0], got.append)  # cached now: immediate
    assert len(got) == 2


def test_rows_deleted_by_retention_are_not_refetched(qapp: Any, db: Storage) -> None:
    worker = ManualWorker(db)
    model = LogTableModel(worker, EntryQuery(("a",)))
    model.reload()
    worker.run_all()
    db.apply_retention(
        __import__("loglens.storage", fromlist=["RetentionPolicy"]).RetentionPolicy(None, 10)
    )
    assert model.index(0, Column.MESSAGE).data() == "…"
    worker.run_all()
    assert model.index(0, Column.MESSAGE).data() == log_model.GONE  # remembered as gone
    assert worker.jobs == []


def test_severity_blocks_and_row_cap(
    qapp: Any, db: Storage, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(log_model, "BLOCK_ROWS", 4)
    model = LogTableModel(SyncWorker(db), EntryQuery(("a",)))
    model.reload()
    size, blocks = model.severity_blocks()
    assert size == 4 and len(blocks) == 13 and blocks[0] == Severity.ERROR
    assert blocks[1] == Severity.ERROR and blocks[2] == Severity.ERROR  # 5, 10 in blocks 1, 2
    monkeypatch.setattr(log_model, "MAX_ROWS", 50)
    model.append_live(store(db, *[make("a", 700 + i) for i in range(5)]))
    assert model.rowCount() < 50 and model.id_at(model.rowCount() - 1) == 65


def test_set_query_reloads_and_failures_are_survived(qapp: Any, db: Storage) -> None:
    model = LogTableModel(SyncWorker(db), EntryQuery(("a",)))
    model.reload()
    model.set_query(EntryQuery(("a", "b")))
    assert model.rowCount() == 60
    model.set_display_names({"b": "Beta"})

    class Broken(SyncWorker):
        def submit(self, job: Any, done: Any, failed: Any = None) -> None:
            failed(RuntimeError("db gone"))

    broken = LogTableModel(Broken(db), EntryQuery(("a",)))
    broken.reload()
    assert not broken.loading and broken.rowCount() == 0


# ---------------------------------------------------------------- source tree


def groups(status: SourceStatus = SourceStatus.RUNNING) -> tuple[ServiceGroup, ...]:
    def src(sid: str, kind: SourceKind, name: str, gid: str) -> LogSource:
        return LogSource(sid, kind, name, gid, status)

    return (
        ServiceGroup(
            "systemd",
            "System services",
            GroupKind.SYSTEM,
            (
                src("systemd:ssh.service", SourceKind.SYSTEMD, "ssh", "systemd"),
                src("systemd:session-2.scope", SourceKind.SYSTEMD, "session-2", "systemd"),
            ),
        ),
        ServiceGroup(
            "compose:shop",
            "shop",
            GroupKind.DOCKER_COMPOSE,
            (
                src("docker:shop-web-1", SourceKind.DOCKER_CONTAINER, "web", "compose:shop"),
                src("docker:shop-api-1", SourceKind.DOCKER_CONTAINER, "api", "compose:shop"),
            ),
        ),
        ServiceGroup(
            "files:squid",
            "Squid proxy",
            GroupKind.FILES,
            (src("file:/var/log/squid/access.log", SourceKind.FILE, "access", "files:squid"),),
        ),
    )


def test_tree_layout_badges_pins(qapp: Any) -> None:
    model = SourceTreeModel()
    assert model.update(groups(), lambda sid: sid.endswith(".scope")) is True
    cats = [model.item(i).text() for i in range(model.rowCount())]
    assert cats == ["System services", "Docker Compose", "Log files"]
    system = model.item_for("cat:system")
    assert system is not None and system.rowCount() == 1  # the scope is hidden
    shop = model.item_for("compose:shop")
    assert shop is not None and shop.data(TreeRole.KIND) == NodeKind.GROUP
    assert [shop.child(i).text() for i in range(shop.rowCount())] == ["api", "web"]  # sorted
    assert model.item_for("cat:compose").data(TreeRole.COUNT) == 2  # type: ignore[union-attr]
    assert model.source("systemd:ssh.service") is not None and model.group("compose:shop")
    assert len(model.sources()) == 4 and model.display_names()["docker:shop-web-1"] == "web"

    assert model.update(groups(SourceStatus.FAILED)) is True  # the scope is back: rebuild
    assert model.update(groups(SourceStatus.STOPPED)) is False  # status only: in place
    item = model.item_for("systemd:ssh.service")
    assert item is not None and item.data(TreeRole.SOURCE).status == SourceStatus.STOPPED

    model.add_unread({"systemd:ssh.service": 3, "ghost": 1})
    model.add_unread({"systemd:ssh.service": 2})
    assert model.unread("systemd:ssh.service") == 5 and item.data(TreeRole.UNREAD) == 5
    model.clear_unread(["systemd:ssh.service"])
    assert item.data(TreeRole.UNREAD) == 0
    model.set_pinned({"systemd:ssh.service"})
    assert item.data(TreeRole.PINNED) and model.pinned == {"systemd:ssh.service"}
    assert model.update(()) is True and model.rowCount() == 0


def test_tooltips_show_log_text_literally(qapp: Any, db: Storage) -> None:
    """Log lines are attacker-controlled; Qt would render HTML-looking tooltips as HTML."""
    from PySide6.QtCore import Qt  # noqa: PLC0415

    evil = '<a href="https://evil.example">Click</a><img src="file:///etc/shadow">\nline 2'
    store(db, make("a", 800, message=evil))
    model = LogTableModel(SyncWorker(db), EntryQuery(("a",)))
    model.reload()
    tip = model.index(model.rowCount() - 1, Column.MESSAGE).data(Qt.ItemDataRole.ToolTipRole)
    assert "<a " not in tip and "<img" not in tip
    assert "&lt;a href=&quot;https://evil.example&quot;&gt;Click&lt;/a&gt;" in tip
    assert "\nline 2" in tip  # line breaks kept (pre-wrap)
    assert (
        log_model.plain_tooltip("<b>x</b>")
        == '<p style="white-space:pre-wrap">&lt;b&gt;x&lt;/b&gt;</p>'
    )
    tree = SourceTreeModel()
    tree.update(
        (
            ServiceGroup(
                "g",
                "<b>proj</b>",
                GroupKind.DOCKER_COMPOSE,
                (LogSource("docker:<i>x</i>", SourceKind.DOCKER_CONTAINER, "x", "g"),),
            ),
        )
    )
    item = tree.item_for("docker:<i>x</i>")
    assert item is not None and "<i>" not in item.data(Qt.ItemDataRole.ToolTipRole)
