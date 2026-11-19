"""``loglens``: start the desktop app.

loglens                      discover this machine's sources
loglens --demo               fake sources replaying sample logs (no Docker/root needed)
loglens --demo --replay-rate 20000 --open systemd:ssh.service    stress one tab
"""

from __future__ import annotations

import argparse
import logging
import os
import signal
import sys
import tempfile
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from PySide6.QtCore import QTimer
from PySide6.QtGui import QIcon
from PySide6.QtWidgets import QApplication

from loglens.collectors.discovery.base import Discoverer
from loglens.config import THEMES, Settings, default_config_path, load_settings
from loglens.core.models import SourceKind
from loglens.gui import theme as themes
from loglens.gui.backend import Backend
from loglens.gui.main_window import MainWindow, session_path
from loglens.gui.workers import DbWorker
from loglens.resources import APP_ID, data_path
from loglens.storage import default_db_path

log = logging.getLogger(__name__)


@dataclass
class Launched:
    """Everything ``launch`` started; ``close()`` stops it in the right order."""

    app: QApplication
    backend: Backend
    worker: DbWorker
    analytics: DbWorker
    window: MainWindow

    def close(self) -> None:
        """Close the window, stop the backend thread, then the worker threads."""
        self.window.close()
        self.backend.stop()
        self.worker.shutdown()
        self.analytics.shutdown()


def launch(
    *,
    settings: Settings,
    db_path: Path,
    demo: bool = False,
    replay_rate: float = 4.0,
    config_path: Path | None = None,
    state_path: Path | None = None,
    start: bool = True,
    discoverers: Sequence[Discoverer] | None = None,
) -> Launched:
    """Create the QApplication (if needed), theme, backend, reader and window.

    With ``start=False`` the caller connects to the backend's signals first and then calls
    ``backend.start()``; signals emitted before anyone listens are lost.
    """
    # A fixed argv[0]: the X11 window class must be "loglens" even when started via
    # "python -c" (the packaged launchers), so docks match the desktop entry.
    app = QApplication.instance() or QApplication(["loglens"])
    assert isinstance(app, QApplication)  # noqa: S101
    app.setApplicationName("LogLens")
    app.setDesktopFileName(APP_ID)  # Wayland app id = desktop entry name
    app.setWindowIcon(QIcon.fromTheme(APP_ID, QIcon(str(data_path("share") / f"{APP_ID}.svg"))))
    theme = themes.resolve(settings.theme)
    themes.apply(app, theme)
    if demo:
        from loglens.gui.demo import DemoDiscoverer, DemoNormalizer, ReplayCollector  # noqa: PLC0415

        replay = ReplayCollector(replay_rate)
        backend = Backend(
            db_path,
            [DemoDiscoverer()],
            dict.fromkeys(SourceKind, replay),
            retention=None,
            normalizer=DemoNormalizer(),
            discovery_interval=settings.discovery_interval_s,
            redactor=settings.redactor(),
        )
    else:
        from loglens.collectors import default_collectors  # noqa: PLC0415
        from loglens.collectors.discovery import default_discoverers  # noqa: PLC0415

        backend = Backend(
            db_path,
            default_discoverers() if discoverers is None else discoverers,
            default_collectors(),
            retention=settings.retention,
            discovery_interval=settings.discovery_interval_s,
            redactor=settings.redactor(),
            max_sources=settings.max_collectors or 10_000,
        )
    # The reader opens its connection lazily (first job), after the backend migrated the DB.
    worker = DbWorker(db_path)
    analytics = DbWorker(db_path, name="loglens-analytics")
    window = MainWindow(
        backend,
        worker,
        settings,
        settings_path=config_path,
        state_path=state_path,
        analytics=analytics,
    )
    window.apply_theme(theme)
    if start:
        backend.start()  # after the window is connected: the first discovery is not lost

    def follow_system(*_: object) -> None:
        if window.settings.theme == "system":
            new = themes.resolve("system")
            themes.apply(app, new)
            window.apply_theme(new)

    app.styleHints().colorSchemeChanged.connect(follow_system)
    return Launched(app, backend, worker, analytics, window)


def _quit_on_signals(launched: Launched) -> None:
    """SIGTERM/SIGINT/SIGHUP (logout, ``kill``, Ctrl-C) close the window and quit, so the
    session is saved and the backend flushes, instead of the process dying mid-write."""

    def stop(*_: object) -> None:
        launched.window.close()
        launched.app.quit()

    for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(sig, stop)
    # Python runs signal handlers only when it gets control; Qt's loop is C++.
    wake = QTimer(launched.app)
    wake.timeout.connect(lambda: None)
    wake.start(250)


def main(argv: Sequence[str] | None = None) -> int:
    """Entry point of the ``loglens`` script."""
    parser = argparse.ArgumentParser(prog="loglens", description="LogLens desktop app")
    parser.add_argument("--demo", action="store_true", help="replay sample logs instead")
    parser.add_argument(
        "--replay-rate",
        type=float,
        default=4.0,
        help="demo lines per second per source (default 4)",
    )
    parser.add_argument(
        "--open",
        action="append",
        default=[],
        metavar="SOURCE_ID",
        help="open a tab for this source at start",
    )
    parser.add_argument("--db", type=Path, help="database (default: XDG data dir)")
    parser.add_argument("--config", type=Path, help="settings file (default: ~/.config/...)")
    parser.add_argument("--theme", choices=THEMES, help="override the theme setting")
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO if args.verbose else logging.WARNING)
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        print(
            "loglens: refusing to run the GUI as root: it parses hostile log text and needs "
            "only read access. Run it as your user; the Issues panel shows the exact group "
            "or ACL fix for each log you cannot read (see docs/SECURITY.md).",
            file=sys.stderr,
        )
        return 2
    config_path = args.config or default_config_path()
    settings = load_settings(config_path)
    if args.theme:
        from dataclasses import replace  # noqa: PLC0415

        settings = replace(settings, theme=args.theme)
    tmp = tempfile.TemporaryDirectory(prefix="loglens-demo-") if args.demo else None
    db_path = args.db or (Path(tmp.name) / "demo.db" if tmp else default_db_path())
    launched = launch(
        settings=settings,
        db_path=db_path,
        demo=args.demo,
        replay_rate=args.replay_rate,
        config_path=config_path,
        state_path=None if args.demo else session_path(),
        start=False,
    )
    if args.open:
        pending = list(args.open)

        def open_requested(*_: object) -> None:
            for source_id in list(pending):
                if launched.window.open_source(source_id) is not None:
                    pending.remove(source_id)

        launched.backend.sourcesChanged.connect(open_requested)
    launched.backend.start()
    launched.window.show()
    if not settings.onboarded and not args.demo:
        QTimer.singleShot(0, launched.window.show_onboarding)
    _quit_on_signals(launched)
    try:
        return launched.app.exec()
    finally:
        launched.backend.stop()
        launched.worker.shutdown()
        launched.analytics.shutdown()
        if tmp is not None:
            tmp.cleanup()


if __name__ == "__main__":
    sys.exit(main())
