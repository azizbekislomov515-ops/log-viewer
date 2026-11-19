"""Background database reads for the GUI.

``DbWorker.submit(job, done)`` runs ``job(storage)`` on a worker thread that owns its own
SQLite connection (WAL lets it read while the pipeline writes) and calls ``done(result)``
back on the GUI thread through a queued signal. The GUI thread never touches SQLite.

``SyncWorker`` has the same interface but runs jobs immediately: view-model tests use it
without threads or a display.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from pathlib import Path
from typing import Any, Protocol

from PySide6.QtCore import QObject, QThread, Signal, Slot

from loglens.storage import Storage

log = logging.getLogger(__name__)

Job = Callable[[Storage], Any]
Done = Callable[[Any], None]
Failed = Callable[[Exception], None]


class Worker(Protocol):
    """Something that runs storage jobs and reports back on the GUI thread."""

    def submit(self, job: Job, done: Done, failed: Failed | None = None) -> None:
        """Run ``job`` later; call ``done(result)`` or ``failed(exc)`` on the GUI thread."""
        ...


class SyncWorker:
    """Runs jobs inline (tests, tools)."""

    def __init__(self, storage: Storage) -> None:
        self.storage = storage

    def submit(self, job: Job, done: Done, failed: Failed | None = None) -> None:
        """Run now."""
        try:
            result = job(self.storage)
        except Exception as exc:
            if failed is None:
                raise
            failed(exc)
            return
        done(result)


class _Runner(QObject):
    """Lives on the worker thread."""

    finished = Signal(object, object, object)  # done, failed, result-or-exception

    def __init__(self, db_path: Path | str) -> None:
        super().__init__()
        self._db_path = db_path
        self._storage: Storage | None = None

    @Slot(object, object, object)
    def run(self, job: Job, done: Done, failed: Failed | None) -> None:
        if self._storage is None:
            self._storage = Storage(self._db_path)
        try:
            result: Any = job(self._storage)
        except Exception as exc:
            log.debug("db job failed", exc_info=True)
            self.finished.emit(done, failed, exc)
            return
        self.finished.emit(done, failed, _Ok(result))

    @Slot()
    def close(self) -> None:
        if self._storage is not None:
            self._storage.close()
            self._storage = None


class _Ok:
    __slots__ = ("value",)

    def __init__(self, value: Any) -> None:
        self.value = value


class DbWorker(QObject):
    """One reader thread; jobs run in submission order."""

    _request = Signal(object, object, object)
    _close = Signal()
    #: Emitted when a job fails and the caller gave no ``failed`` callback.
    error = Signal(str)

    def __init__(
        self, db_path: Path | str, parent: QObject | None = None, name: str = "loglens-db-reader"
    ) -> None:
        super().__init__(parent)
        self.pending = 0
        self._thread = QThread()
        self._thread.setObjectName(name)
        self._runner = _Runner(db_path)
        self._runner.moveToThread(self._thread)
        self._request.connect(self._runner.run)
        self._close.connect(self._runner.close)
        self._runner.finished.connect(self._finished)
        self._thread.start()

    def submit(self, job: Job, done: Done, failed: Failed | None = None) -> None:
        """Queue ``job``; ``done``/``failed`` are called on this (GUI) thread."""
        self.pending += 1
        self._request.emit(job, done, failed)

    @Slot(object, object, object)
    def _finished(self, done: Done, failed: Failed | None, outcome: Any) -> None:
        self.pending -= 1
        if isinstance(outcome, _Ok):
            done(outcome.value)
        elif failed is not None:
            failed(outcome)
        else:
            self.error.emit(f"{type(outcome).__name__}: {outcome}")

    def shutdown(self) -> None:
        """Close the connection and stop the thread (waits for the running job)."""
        self._close.emit()
        self._thread.quit()
        self._thread.wait(5000)
