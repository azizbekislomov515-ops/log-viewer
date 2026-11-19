"""Render documentation screenshots offscreen from demo data (never from real logs).

QT_QPA_PLATFORM=offscreen python -m loglens.gui.screenshots docs/screenshots
"""

from __future__ import annotations

import os
import sys
import tempfile
import time
from pathlib import Path

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


if __name__ == "__main__":
    for path in capture(Path(sys.argv[1] if len(sys.argv) > 1 else "docs/screenshots")):
        print(path)
