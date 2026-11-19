"""Render documentation screenshots offscreen from demo data (never from real logs).

QT_QPA_PLATFORM=offscreen python -m loglens.gui.screenshots docs/screenshots
"""

from __future__ import annotations

import os
import sys
import tempfile
import time
from dataclasses import replace
from pathlib import Path
from typing import Any

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtCore import QCoreApplication, QPoint
from PySide6.QtGui import QPainter, QPixmap
from PySide6.QtWidgets import QWidget

from loglens.config import Settings
from loglens.gui import theme as themes
from loglens.gui.app import Launched, launch
from loglens.gui.widgets import SettingsDialog


def _pump(seconds: float) -> None:
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        QCoreApplication.processEvents()
        time.sleep(0.01)


def _with_popup(window: QWidget, popup: QWidget) -> QPixmap:
    """The window with a popup (palette) painted where it would appear."""
    shot = window.grab()
    painter = QPainter(shot)
    offset = popup.mapToGlobal(QPoint(0, 0)) - window.mapToGlobal(QPoint(0, 0))
    painter.drawPixmap(offset, popup.grab())
    painter.end()
    return shot


def capture(out: Path) -> list[Path]:
    """Write every screenshot into ``out``; returns the paths."""
    out.mkdir(parents=True, exist_ok=True)
    saved: list[Path] = []
    with tempfile.TemporaryDirectory() as tmp:
        launched: Launched | None = None
        for theme_name in ("dark", "light"):
            settings = Settings(theme=theme_name, discovery_interval_s=3600)
            launched = launch(
                settings=settings, db_path=Path(tmp) / f"{theme_name}.db", demo=True, replay_rate=25
            )
            window = launched.window
            window.resize(1440, 900)
            window.show()
            _pump(1.0)
            window.tree.expandAll()
            window.open_group("compose:shop")
            ssh = window.open_source("systemd:ssh.service")
            assert ssh is not None  # noqa: S101 (the demo layout has it)
            _pump(4.0)

            def save(name: str, pixmap: QPixmap, theme_name: str = theme_name) -> None:
                path = out / f"{name}-{theme_name}.png"
                pixmap.save(str(path))
                saved.append(path)

            window.search.setText("Failed")
            window._apply_search()
            _pump(0.5)
            window.tree_model.add_unread({"docker:shop-api-1": 7, "systemd:worker.service": 2})
            save("main-search", window.grab())

            window.tabs.setCurrentIndex(0)
            window.search.clear()
            window._apply_search()
            _pump(0.6)
            save("compose-merged", window.grab())
            window.split_btn.setChecked(True)
            _pump(0.8)
            save("compose-split", window.grab())
            window.split_btn.setChecked(False)

            window.issues_dock.show()
            _pump(0.3)
            save("issues", window.grab())
            window.issues_dock.hide()

            window.show_palette()
            QCoreApplication.processEvents()
            window.palette_popup.input.setText("clam")
            _pump(0.3)
            save("command-palette", _with_popup(window, window.palette_popup))
            window.palette_popup.close()

            window.tabs.setCurrentWidget(ssh)
            window.overlay.toggle()
            _pump(0.6)
            save("debug-overlay", window.grab())
            window.overlay.toggle()

            dialog = SettingsDialog(settings, window)
            dialog.show()
            _pump(0.2)
            save("settings", dialog.grab())
            dialog.close()
            launched.close()
            themes.apply(launched.app, themes.resolve(theme_name))
    return saved


class DemoStackOnly:
    """Discovers only the ``loglens-demo`` Compose project (no private services leak into
    documentation screenshots)."""

    name = "docker"

    def __init__(self) -> None:
        from loglens.collectors.discovery import DockerDiscoverer  # noqa: PLC0415

        self._inner = DockerDiscoverer()

    def discover(self) -> Any:
        """Docker discovery filtered to the demo project."""
        result = self._inner.discover()
        groups = tuple(g for g in result.groups if g.name == "loglens-demo")
        return replace(result, groups=groups, issues=())


def capture_stack(out: Path, *, warmup_s: float = 45.0) -> list[Path]:
    """Screenshots of the real demo stack (``demo/docker-compose.yml`` must be running)."""
    out.mkdir(parents=True, exist_ok=True)
    saved: list[Path] = []
    with tempfile.TemporaryDirectory() as tmp:
        for theme_name in ("dark", "light"):
            settings = Settings(theme=theme_name, discovery_interval_s=3600, notify_on=())
            launched = launch(
                settings=settings,
                db_path=Path(tmp) / f"{theme_name}.db",
                discoverers=[DemoStackOnly()],
            )
            try:
                saved += _stack_shots(launched, out, theme_name, Path(tmp), warmup_s)
            finally:
                launched.close()
    return saved


def _stack_shots(
    launched: Launched, out: Path, theme_name: str, tmp: Path, warmup_s: float
) -> list[Path]:
    from loglens.gui.dialogs import RuleEditorDialog  # noqa: PLC0415

    saved: list[Path] = []
    window = launched.window
    window.resize(1600, 980)
    window.show()
    _pump(2.0)
    window.tree.expandAll()
    ids = {s.display_name: s.id for s in window.tree_model.sources()}
    for name in ("web", "flaky", "scanner", "clamav", "squid"):
        if name in ids:
            window.open_source(ids[name])
    _pump(warmup_s)

    def save(name: str, pixmap: QPixmap) -> None:
        path = out / f"{name}-{theme_name}.png"
        pixmap.save(str(path))
        saved.append(path)

    squid_tab = window.open_source(ids["squid"])
    assert squid_tab is not None  # noqa: S101
    view = squid_tab.views[0]
    model = view.model
    _pump(1.0)
    denied = next(
        (
            r
            for r in range(model.rowCount() - 1, -1, -1)
            if (e := model.entry_at(r)) and "TCP_DENIED/403" in e.message and "CONNECT" in e.message
        ),
        0,
    )
    view.go_to_row(denied)
    window.insights.set_inline_mode("full")
    _pump(1.0)
    save("explain-squid", window.grab())
    window.insights.set_inline_mode("off")
    for name in ("squid", "clamav", "flaky", "web"):
        window.insights.open_overview([ids[name]])
        _pump(3.0)
        save(f"overview-{name}", window.grab())
    window.insights.open_dashboard("compose:loglens-demo")
    _pump(3.0)
    save("compose-dashboard", window.grab())
    clam_tab = window.open_source(ids["clamav"])
    assert clam_tab is not None  # noqa: S101
    cmodel = clam_tab.views[0].model
    _pump(1.0)
    row = next(
        (
            r
            for r in range(cmodel.rowCount())
            if (e := cmodel.entry_at(r)) and window.insights.explain(e) is None
        ),
        None,
    )
    source = window.tree_model.source(ids["clamav"])
    entry = cmodel.entry_at(row) if row is not None else None
    if entry is not None and source is not None:
        clam_tab.views[0].go_to_row(row or 0)
        _pump(0.5)
        save("explain-unmatched", window.grab())
        counter = window.insights._counter_line(entry)
        dialog = RuleEditorDialog(entry, source, counter, directory=tmp / "rules", parent=window)
        dialog.theme = themes.resolve(theme_name)
        dialog.refresh()
        dialog.show()
        _pump(0.5)
        save("rule-editor", dialog.grab())
        dialog.close()
    return saved


if __name__ == "__main__":
    target = Path(sys.argv[2] if len(sys.argv) > 2 else "docs/screenshots")
    if len(sys.argv) > 1 and sys.argv[1] == "--stack":
        paths = capture_stack(target)
    else:
        paths = capture(Path(sys.argv[1] if len(sys.argv) > 1 else "docs/screenshots"))
    for path in paths:
        print(path)
