"""Stress: the real pipeline replays 20k lines/s into one tab; the GUI must stay responsive.

Everything is real except the collector (demo replay): assembler, parsers, SQLite writes
with FTS, the backend thread, the drain timer, the model and the painted view. GUI
responsiveness = how late a 16 ms timer fires (event-loop stall). Prints a table; the
numbers in docs/GUI.md come from this test.
"""

import time
from pathlib import Path
from typing import Any

import pytest
from pytestqt.qtbot import QtBot

from loglens.config import Settings
from loglens.gui.app import launch

pytestmark = pytest.mark.perf

RATE = 20_000  # lines/s into one tab
SECONDS = 6
MAX_P99_MS = 100.0  # a frame later than this feels sluggish


def test_twenty_thousand_lines_per_second_keep_the_ui_responsive(
    qtbot: QtBot, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    launched = launch(
        settings=Settings(theme="dark", discovery_interval_s=3600),
        db_path=tmp_path / "stress.db",
        demo=True,
        replay_rate=RATE,
    )
    window = launched.window
    try:
        window.resize(1440, 900)
        window.show()
        qtbot.waitUntil(
            lambda: window.tree_model.source("systemd:myapp.service") is not None, timeout=10_000
        )
        tab = window.open_source("systemd:myapp.service")
        assert tab is not None
        view = tab.views[0]
        stats: list[Any] = []
        launched.backend.statsChanged.connect(stats.append)
        qtbot.wait(1500)  # warm-up: collector, writer and FTS reach steady state
        window.frame_meter.samples.clear()
        drains: list[float] = []
        window._drain_timer.timeout.connect(lambda: drains.append(window._last_drain_ms))
        rows_before, start = view.model.rowCount(), time.perf_counter()
        for step in range(SECONDS * 4):  # the user scrolls around while it streams
            qtbot.wait(250)
            if step % 4 == 1:
                view.tree.verticalScrollBar().setValue(view.tree.verticalScrollBar().maximum() // 2)
            elif step % 4 == 3:
                view.set_follow(True)
        elapsed = time.perf_counter() - start
        rows = view.model.rowCount() - rows_before
        avg, p99, worst = window.frame_meter.summary()
        ingest = [s.lines_per_s for s in stats[2:]] or [0.0]
        with capsys.disabled():
            print(f"\n[stress] {RATE:,} lines/s replayed into one tab for {elapsed:.1f} s")
            print(f"  pipeline ingest      {sum(ingest) / len(ingest):10,.0f} lines/s (avg)")
            print(f"  rows shown in tab    {rows / elapsed:10,.0f} rows/s ({rows:,} rows)")
            print(
                f"  GUI frame interval   avg {avg:.1f} ms, p99 {p99:.1f} ms, max {worst:.1f} ms "
                "(16 ms = perfect)"
            )
            print(
                f"  drain per tick       avg {sum(drains) / max(len(drains), 1):.1f} ms, "
                f"max {max(drains, default=0):.1f} ms"
            )
            print(f"  backend backlog      {launched.backend.backlog:,} entries at the end")
        assert rows / elapsed > RATE * 0.5, "the tab fell far behind the pipeline"
        assert p99 < MAX_P99_MS, f"GUI stalled: p99 frame interval {p99:.1f} ms"
    finally:
        launched.close()


def test_one_million_rows_scroll_smoothly(
    qtbot: QtBot, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A tab over 1M stored entries: open, jump anywhere, page in, without stalling."""
    from datetime import UTC, datetime, timedelta  # noqa: PLC0415

    from loglens.core.models import LogEntry, Severity  # noqa: PLC0415
    from loglens.gui.log_model import LogTableModel  # noqa: PLC0415
    from loglens.gui.log_view import LogView  # noqa: PLC0415
    from loglens.gui.widgets import FrameMeter  # noqa: PLC0415
    from loglens.gui.workers import DbWorker  # noqa: PLC0415
    from loglens.storage import EntryQuery, Storage  # noqa: PLC0415

    db_path = tmp_path / "million.db"
    t0 = datetime(2026, 11, 18, tzinfo=UTC)
    levels = list(Severity)
    with Storage(db_path) as storage:
        for batch in range(100):
            storage.write_batch(
                [
                    LogEntry(
                        0,
                        "s",
                        t0 + timedelta(milliseconds=batch * 10_000 + i),
                        levels[(i * 7) % 7 if i % 97 else 5],
                        f"request {batch}-{i} from 10.0.{i % 250}.1",
                        "",
                    )
                    for i in range(10_000)
                ],
                {},
            )
    worker = DbWorker(db_path)
    meter = FrameMeter()
    try:
        model = LogTableModel(worker, EntryQuery(("s",)))
        view = LogView(model)
        qtbot.addWidget(view)
        view.resize(1200, 800)
        view.show()
        start = time.perf_counter()
        model.reload()
        qtbot.waitUntil(lambda: not model.loading, timeout=20_000)
        load_s = time.perf_counter() - start
        assert model.rowCount() == 1_000_000
        meter.start()
        bar = view.tree.verticalScrollBar()
        jumps: list[float] = []
        for k in range(20):  # jump to 20 places and wait for the rows to appear
            bar.setValue(bar.maximum() * k // 19)
            begin = time.perf_counter()
            row = max(view.tree.rowAt(0), 0)
            qtbot.waitUntil(lambda r=row: model.entry_at(r) is not None, timeout=5_000)
            qtbot.wait(20)
            jumps.append((time.perf_counter() - begin) * 1000)
        for _ in range(60):  # wheel-like scrolling
            bar.setValue(bar.value() - 120)
            qtbot.wait(16)
        avg, p99, worst = meter.summary()
        with capsys.disabled():
            print(f"\n[1M rows] id list loaded in {load_s:.2f} s (background thread)")
            print(
                f"  jump anywhere -> rows painted   avg {sum(jumps) / len(jumps):.0f} ms, "
                f"max {max(jumps):.0f} ms"
            )
            print(
                f"  GUI frame interval while scrolling  avg {avg:.1f} ms, p99 {p99:.1f} ms, "
                f"max {worst:.1f} ms"
            )
        assert p99 < MAX_P99_MS
        assert max(jumps) < 1000
    finally:
        meter.stop()
        worker.shutdown()
