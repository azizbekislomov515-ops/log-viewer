"""Drive the installed GUI (offscreen): onboarding shown on first run, its pages, the
main window with discovered sources, an opened log with explanations, a clean exit.
Run with the bundled interpreter: /opt/loglens/python/bin/python3.12 -I gui_check.py OUT"""

import sys
import time
from pathlib import Path

from PySide6.QtCore import QTimer
from PySide6.QtWidgets import QApplication

from loglens.config import default_config_path, load_settings
from loglens.gui import main_window
from loglens.gui.app import main

OUT = Path(sys.argv[1])
SOURCE = sys.argv[2]
started = time.monotonic()
report: dict[str, object] = {}
orig_show = main_window.MainWindow.showEvent


def fail(message: str) -> None:
    print(f"GUI FAIL: {message}", flush=True)
    QApplication.instance().exit(3)  # type: ignore[union-attr]


def show_event(self, event):  # type: ignore[no-untyped-def]
    orig_show(self, event)
    if "first_frame_s" in report:
        return
    report["first_frame_s"] = round(time.monotonic() - started, 2)
    QTimer.singleShot(1500, lambda: onboarding(self))


def onboarding(window):  # type: ignore[no-untyped-def]
    wizard = getattr(window, "onboarding", None)
    if wizard is None or not wizard.isVisible():
        fail("the first-run guide did not open")
        return
    for page in range(4):
        wizard.grab().save(str(OUT / f"qa-onboarding-{page}.png"))
        if page < 3:
            wizard.next()
    report["access_rows"] = len(wizard.access.rows)
    wizard.accept()
    QTimer.singleShot(1500, lambda: browse(window))


def browse(window, attempts: int = 0):  # type: ignore[no-untyped-def]
    if not load_settings(default_config_path()).onboarded:
        fail("onboarding choices were not saved")
        return
    tab = window.open_source(SOURCE)
    if tab is None:
        if attempts > 20:
            fail(f"{SOURCE} was not discovered")
            return
        QTimer.singleShot(500, lambda: browse(window, attempts + 1))
        return
    QTimer.singleShot(3000, lambda: finish(window, tab))


def finish(window, tab):  # type: ignore[no-untyped-def]
    view = tab.views[0]
    report["rows"] = view.model.rowCount()
    if report["rows"] == 0:
        fail("the opened log shows no rows")
        return
    view.tree.selectRow(view.model.rowCount() - 1)
    window.toggle_explain_panel()
    QApplication.processEvents()
    explain = window.insights.explain_panel
    report["explained_title"] = explain.title.text() if hasattr(explain, "title") else "?"
    window.grab().save(str(OUT / "qa-main-window.png"))
    window.close()


main_window.MainWindow.showEvent = show_event
code = main([])
print(f"GUI REPORT {report} exit={code}", flush=True)
sys.exit(code)
