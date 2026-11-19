"""Background analysis for the GUI: overview reports, the Compose dashboard, and the
explanations behind desktop notifications.

All heavy work runs as jobs on a dedicated "analytics" worker thread (separate from the
reader that pages log views, so a refresh never delays scrolling). Each model refreshes at
most once per ``REFRESH_MS`` and only when new entries arrived for its sources.

``Analyst`` (an explanation engine plus a per-entry cache) is used only on that thread.
"""

from __future__ import annotations

import logging
from collections import OrderedDict
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta
from itertools import batched
from pathlib import Path
from typing import Any

from PySide6.QtCore import QObject, QTimer, Signal

from loglens.config import Settings
from loglens.core.models import Explanation, LogEntry, LogSource, Severity, SourceStatus, utc_now
from loglens.explain import DEFAULT_RULES_DIR, ExplanationEngine
from loglens.explain.editor import user_rules_dir
from loglens.explain.overview import OverviewReport, build_report
from loglens.gui.notify import DesktopNotifier, Notification, NotificationCenter
from loglens.gui.workers import Worker
from loglens.storage import EntryQuery, Storage

log = logging.getLogger(__name__)

REFRESH_MS = 1000
#: Cards and the summary look at the newest this-many entries of the window.
MAX_ENTRIES = 20_000
#: Notifications: at most this many live entries are explained per drain tick.
LIVE_BUDGET = 3000
#: Overview periods: label -> (window, timeline bucket).
WINDOWS: Mapping[str, tuple[timedelta, timedelta]] = {
    "15m": (timedelta(minutes=15), timedelta(seconds=30)),
    "1h": (timedelta(hours=1), timedelta(minutes=1)),
    "6h": (timedelta(hours=6), timedelta(minutes=5)),
    "24h": (timedelta(hours=24), timedelta(minutes=15)),
}


def rule_dirs(settings: Settings) -> list[Path]:
    """Built-in packs, then the user's editor pack, then extra folders from Settings."""
    dirs = [DEFAULT_RULES_DIR]
    if user_rules_dir().is_dir():
        dirs.append(user_rules_dir())
    dirs += [Path(d).expanduser() for d in settings.rule_dirs]
    return dirs


def make_engine(settings: Settings) -> ExplanationEngine:
    """An explanation engine over every configured rule directory."""
    return ExplanationEngine.from_directory(rule_dirs(settings))


class Analyst:
    """Explanation engine + cache for the analytics thread (never touched elsewhere,
    except ``reload`` which only sets a flag)."""

    def __init__(self, factory: Callable[[], ExplanationEngine], cache_size: int = 200_000) -> None:
        self._factory = factory
        self._engine: ExplanationEngine | None = None
        self._cache: OrderedDict[int, Explanation | None] = OrderedDict()
        self._cache_size = cache_size
        self._reload = False

    def reload(self) -> None:
        """Rules changed: rebuild the engine before the next job (thread-safe flag)."""
        self._reload = True

    @property
    def engine(self) -> ExplanationEngine:
        """The engine (built lazily on the analytics thread)."""
        if self._engine is None or self._reload:
            self._reload = False
            self._engine = self._factory()
            self._cache.clear()
        return self._engine

    def explain(self, entry: LogEntry, source: LogSource | None = None) -> Explanation | None:
        """Explanation for ``entry`` (cached by id)."""
        engine = self.engine
        if entry.id > 0 and entry.id in self._cache:
            self._cache.move_to_end(entry.id)
            return self._cache[entry.id]
        explanation = engine.explain(entry, source)
        if entry.id > 0:
            self._cache[entry.id] = explanation
            if len(self._cache) > self._cache_size:
                self._cache.popitem(last=False)
        return explanation


def load_window(
    storage: Storage, source_ids: Sequence[str], since: datetime, limit: int = MAX_ENTRIES
) -> tuple[list[LogEntry], bool]:
    """The newest ``limit`` entries since ``since`` (ascending), and whether more existed."""
    ids, _ = storage.entry_ids(EntryQuery(tuple(source_ids), since=since))
    chosen = list(ids[-limit:])
    entries: list[LogEntry] = []
    for chunk in batched(chosen, 900):
        entries += storage.entries_by_id(chunk)
    return entries, len(ids) > limit


class _Throttled(QObject):
    """Shared refresh logic: dirty flag + one job in flight + a 1 s timer."""

    failed = Signal(str)

    def __init__(self, worker: Worker, parent: QObject | None = None) -> None:
        super().__init__(parent)
        self._worker = worker
        self._dirty = True
        self._pending = False
        self.refreshes = 0
        self._timer = QTimer(self)
        self._timer.setInterval(REFRESH_MS)
        self._timer.timeout.connect(self._tick)
        self._timer.start()

    def mark_dirty(self) -> None:
        """New data arrived; refresh on the next tick."""
        self._dirty = True

    def _tick(self) -> None:
        if self._dirty and not self._pending:
            self.refresh()

    def refresh(self) -> None:
        """Run the job now (unless one is already running)."""
        if self._pending:
            self._dirty = True
            return
        self._dirty = False
        self._pending = True
        self._worker.submit(self._job, self._done, self._failed)

    def _job(self, storage: Storage) -> Any:  # pragma: no cover - overridden
        raise NotImplementedError

    def _done(self, result: Any) -> None:
        self._pending = False
        self.refreshes += 1
        self._publish(result)

    def _publish(self, result: Any) -> None:  # pragma: no cover - overridden
        raise NotImplementedError

    def _failed(self, exc: Exception) -> None:
        self._pending = False
        log.warning("analysis failed: %s", exc)
        self.failed.emit(str(exc))

    def stop(self) -> None:
        """Stop refreshing (the page closed)."""
        self._timer.stop()


class OverviewModel(_Throttled):
    """Keeps an ``OverviewReport`` for some sources up to date."""

    reportChanged = Signal(object)

    def __init__(
        self,
        worker: Worker,
        analyst: Analyst,
        title: str,
        sources: Sequence[LogSource],
        *,
        window: str = "1h",
        parent: QObject | None = None,
    ) -> None:
        self.title = title
        self.sources = list(sources)
        self.window = window
        self.report: OverviewReport | None = None
        self._analyst = analyst
        super().__init__(worker, parent)

    @property
    def source_ids(self) -> tuple[str, ...]:
        """The sources this overview covers."""
        return tuple(s.id for s in self.sources)

    def set_sources(self, sources: Sequence[LogSource]) -> None:
        """Discovery updated statuses."""
        self.sources = list(sources)
        self.mark_dirty()

    def set_window(self, window: str) -> None:
        """Change the period (15m, 1h, 6h, 24h) and refresh now."""
        self.window = window
        self.refresh()

    def _job(self, storage: Storage) -> OverviewReport:
        span, bucket = WINDOWS[self.window]
        now = utc_now()
        sources = list(self.sources)
        by_id = {s.id: s for s in sources}
        entries, capped = load_window(storage, [s.id for s in sources], now - span)
        explanations = {e.id: self._analyst.explain(e, by_id.get(e.source_id)) for e in entries}
        histogram = storage.severity_histogram([s.id for s in sources], now - span, bucket)
        return build_report(
            self.title,
            sources,
            entries,
            explanations,
            histogram,
            packs=self._analyst.engine.packs,
            now=now,
            window=span,
            bucket=bucket,
            capped=capped,
        )

    def _publish(self, result: OverviewReport) -> None:
        self.report = result
        self.reportChanged.emit(result)


@dataclass(frozen=True, slots=True)
class ServiceSummary:
    """One tile of the Compose dashboard."""

    source: LogSource
    entries: int
    errors: int
    restarts: int
    last_error: datetime | None
    last_error_text: str
    depends_on: tuple[tuple[str, str], ...]
    hints: tuple[str, ...]


def parse_depends_on(label: str) -> tuple[tuple[str, str], ...]:
    """Compose's ``com.docker.compose.depends_on`` label: ``db:service_healthy:false,...``."""
    out = []
    for item in label.split(","):
        parts = item.strip().split(":")
        if parts and parts[0]:
            out.append((parts[0], parts[1] if len(parts) > 1 else "service_started"))
    return tuple(out)


def summarize_service(
    source: LogSource,
    entries: Sequence[LogEntry],
    explanations: Mapping[int, Explanation | None],
    statuses: Mapping[str, SourceStatus],
) -> ServiceSummary:
    """Tile data for one service of a Compose project."""
    errors = [e for e in entries if e.severity >= Severity.ERROR]
    restarts = sum(1 for e in entries if (x := explanations.get(e.id)) and "restart" in x.tags)
    last = errors[-1] if errors else None
    last_text = ""
    if last is not None:
        exp = explanations.get(last.id)
        last_text = exp.title if exp else last.message.split("\n", 1)[0][:160]
    depends = parse_depends_on(str(source.metadata.get("compose_depends_on", "")))
    hints = []
    for service, condition in depends:
        status = statuses.get(service)
        wanted = {"service_healthy": "healthy", "service_completed_successfully": "finished"}.get(
            condition, "started"
        )
        if status in (SourceStatus.FAILED, SourceStatus.STOPPED):
            hints.append(f"needs {service} ({wanted}), which is {status.value}")
        else:
            hints.append(f"starts after {service} is {wanted}")
    dependency = [x for e in entries if (x := explanations.get(e.id)) and "dependency" in x.tags]
    if dependency:
        hints.append(dependency[-1].plain_text)
    return ServiceSummary(
        source,
        len(entries),
        len(errors),
        restarts,
        last.timestamp if last else None,
        last_text,
        depends,
        tuple(hints),
    )


class ComposeModel(_Throttled):
    """Keeps the Compose dashboard (one ``ServiceSummary`` per service) up to date."""

    servicesChanged = Signal(object)

    def __init__(
        self,
        worker: Worker,
        analyst: Analyst,
        title: str,
        sources: Sequence[LogSource],
        *,
        window: timedelta = timedelta(hours=1),
        parent: QObject | None = None,
    ) -> None:
        self.title = title
        self.sources = list(sources)
        self.window = window
        self.services: list[ServiceSummary] = []
        self._analyst = analyst
        super().__init__(worker, parent)

    @property
    def source_ids(self) -> tuple[str, ...]:
        """The project's services."""
        return tuple(s.id for s in self.sources)

    def set_sources(self, sources: Sequence[LogSource]) -> None:
        """Discovery updated statuses (or the project gained/lost services)."""
        self.sources = list(sources)
        self.mark_dirty()

    def _job(self, storage: Storage) -> list[ServiceSummary]:
        since = utc_now() - self.window
        statuses = {
            str(s.metadata.get("compose_service") or s.display_name): s.status for s in self.sources
        }
        out = []
        for source in self.sources:
            entries, _ = load_window(storage, [source.id], since, limit=2000)
            explanations = {e.id: self._analyst.explain(e, source) for e in entries}
            out.append(summarize_service(source, entries, explanations, statuses))
        return out

    def _publish(self, result: list[ServiceSummary]) -> None:
        self.services = result
        self.servicesChanged.emit(result)


class LiveExplainer(QObject):
    """Explains live entries on the analytics thread and raises desktop notifications."""

    notified = Signal(object)  # Notification
    unavailable = Signal(str)

    def __init__(
        self,
        worker: Worker,
        analyst: Analyst,
        center: NotificationCenter,
        notifier: DesktopNotifier,
        *,
        sources: Callable[[], Mapping[str, LogSource]],
        parent: QObject | None = None,
    ) -> None:
        super().__init__(parent)
        self._worker = worker
        self._analyst = analyst
        self.center = center
        self._notifier = notifier
        self._sources = sources
        self._pending: list[LogEntry] = []
        self._in_flight = False
        self.skipped = 0
        self._warned = False

    def feed(self, entries: Iterable[LogEntry]) -> None:
        """New live entries (GUI thread)."""
        if not self.center.conditions:
            return
        self._pending.extend(entries)
        if not self._in_flight:
            self._run()

    def _run(self) -> None:
        if not self._pending:
            return
        batch = self._pending[-LIVE_BUDGET:]
        self.skipped += len(self._pending) - len(batch)
        self._pending = []
        self._in_flight = True
        sources = dict(self._sources())

        def job(_: Storage) -> list[tuple[LogEntry, Explanation | None]]:
            return [(e, self._analyst.explain(e, sources.get(e.source_id))) for e in batch]

        self._worker.submit(job, self._done, self._failed)

    def _done(self, pairs: list[tuple[LogEntry, Explanation | None]]) -> None:
        self._in_flight = False
        names = {sid: s.display_name for sid, s in self._sources().items()}
        for note in self.center.consider(pairs, names):
            if self._notifier.send(note):
                self.notified.emit(note)
            elif not self._warned:
                self._warned = True
                self.unavailable.emit(
                    "Desktop notifications need notify-send (package libnotify-bin)."
                )
        self._run()

    def _failed(self, exc: Exception) -> None:
        self._in_flight = False
        log.warning("live explanation failed: %s", exc)

    def send_test(self) -> Notification:
        """Show a sample notification (Settings > Notifications > Test)."""
        note = Notification("LogLens", "Notifications are working.", "", "test")
        self._notifier.send(note)
        return note
