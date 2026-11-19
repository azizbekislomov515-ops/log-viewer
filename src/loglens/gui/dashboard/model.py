"""What the Overview and Timeline pages show, computed in one background job.

``build_dashboard`` is pure (a ``Storage`` and an explain function in, a frozen
``Dashboard`` out) so it is tested without Qt. Counts are exact SQL aggregates; the
"latest explanations" come from the newest notable entries, explained by the rule packs.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta
from itertools import batched

from PySide6.QtCore import QObject, Signal

from loglens.core.models import Explanation, LogEntry, LogSource, Severity, utc_now
from loglens.explain.insights import Thresholds
from loglens.explain.overview import Bucket, timeline_buckets
from loglens.gui.analyst import WINDOWS, Analyst, _Throttled
from loglens.gui.workers import Worker
from loglens.storage import EntryQuery, Storage

#: The dashboard refreshes at most this often (and only while a page shows it).
REFRESH_MS = 5000
#: Latest explanations: the newest this-many NOTICE-or-worse entries are explained.
EXPLAIN_LIMIT = 400
#: Rows in "Latest explanations" / "Notable moments" and in "Busiest sources".
TOP = 6
HOUR = timedelta(hours=1)
DAY = timedelta(days=1)
NOTABLE = frozenset(s for s in Severity if s >= Severity.NOTICE)


@dataclass(frozen=True, slots=True)
class Moment:
    """Explained entries grouped by what happened and where: the newest time and a count."""

    title: str
    source_id: str
    when: datetime
    severity: Severity
    count: int
    tags: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class Dashboard:
    """Every number on the Overview and Timeline pages."""

    now: datetime
    #: Entries per minute over the last hour, and over the hour before.
    per_minute: float
    per_minute_before: float
    #: ERROR-or-worse entries in the last 24 hours, and in the 24 hours before.
    errors_24h: int
    errors_before: int
    #: The last 24 hours: (hour start, all entries, ERROR-or-worse), oldest first.
    hourly: tuple[tuple[datetime, int, int], ...]
    #: The last 7 days: (day start, ERROR-or-worse), oldest first.
    daily_errors: tuple[tuple[datetime, int], ...]
    #: Entries in the last 24 hours per stored source kind (systemd, docker, file).
    by_kind: Mapping[str, int]
    #: (source id, entries in the last 24 hours), busiest first.
    busiest: tuple[tuple[str, int], ...]
    latest: tuple[Moment, ...]
    #: The Timeline page's bars for ``window`` (see ``analyst.WINDOWS``).
    timeline: tuple[Bucket, ...]
    window: str

    @property
    def total_24h(self) -> int:
        """All entries in the last 24 hours."""
        return sum(self.by_kind.values())


def _floor(when: datetime, size: timedelta) -> datetime:
    epoch = datetime(1970, 1, 1, tzinfo=when.tzinfo)
    return epoch + ((when - epoch) // size) * size


def build_dashboard(
    storage: Storage,
    explain: Callable[[LogEntry], Explanation | None],
    *,
    now: datetime | None = None,
    window: str = "24h",
) -> Dashboard:
    """Compute the dashboard from ``storage`` (run it on a worker thread)."""
    now = now or utc_now()
    ids = storage.source_ids()

    minutes = storage.severity_histogram(ids, now - 2 * HOUR, timedelta(minutes=1))
    last_hour = sum(n for when, _, n in minutes if when >= now - HOUR)
    hour_before = sum(n for when, _, n in minutes if when < now - HOUR)

    hours = storage.severity_histogram(ids, _floor(now, HOUR) - 47 * HOUR, HOUR)
    per_hour: dict[datetime, list[int]] = {}
    for when, severity, n in hours:
        slot = per_hour.setdefault(when, [0, 0])
        slot[0] += n
        if severity >= Severity.ERROR:
            slot[1] += n
    starts = [_floor(now, HOUR) - i * HOUR for i in range(47, -1, -1)]
    series = [(s, per_hour.get(s, [0, 0])[0], per_hour.get(s, [0, 0])[1]) for s in starts]
    hourly = tuple(series[24:])

    days = storage.severity_histogram(ids, _floor(now, DAY) - 6 * DAY, DAY)
    per_day: dict[datetime, int] = {}
    for when, severity, n in days:
        if severity >= Severity.ERROR:
            per_day[when] = per_day.get(when, 0) + n
    daily = tuple(
        (d, per_day.get(d, 0)) for d in (_floor(now, DAY) - i * DAY for i in range(6, -1, -1))
    )

    by_kind: dict[str, int] = {}
    by_source: dict[str, int] = {}
    for sid, kind, _, n in storage.source_counts(now - DAY):
        by_kind[kind] = by_kind.get(kind, 0) + n
        by_source[sid] = by_source.get(sid, 0) + n
    busiest = tuple(sorted(by_source.items(), key=lambda kv: (-kv[1], kv[0]))[:TOP])

    span, bucket = WINDOWS[window]
    timeline = timeline_buckets(
        storage.severity_histogram(ids, now - span, bucket), now - span, now, bucket, Thresholds()
    )

    return Dashboard(
        now=now,
        per_minute=last_hour / 60,
        per_minute_before=hour_before / 60,
        errors_24h=sum(e for _, _, e in series[24:]),
        errors_before=sum(e for _, _, e in series[:24]),
        hourly=hourly,
        daily_errors=daily,
        by_kind=by_kind,
        busiest=busiest,
        latest=latest_moments(storage, ids, explain, since=now - DAY),
        timeline=timeline,
        window=window,
    )


def latest_moments(
    storage: Storage,
    ids: Sequence[str],
    explain: Callable[[LogEntry], Explanation | None],
    *,
    since: datetime,
) -> tuple[Moment, ...]:
    """The newest notable entries that a rule explained, grouped by (title, source)."""
    found, _ = storage.entry_ids(EntryQuery(tuple(ids), NOTABLE, since=since))
    chosen = list(found[-EXPLAIN_LIMIT:])
    entries: list[LogEntry] = []
    for chunk in batched(chosen, 900):
        entries += storage.entries_by_id(chunk)
    groups: dict[tuple[str, str], Moment] = {}
    for entry in reversed(entries):  # newest first: the first seen sets time and severity
        explanation = explain(entry)
        if explanation is None:
            continue
        key = (explanation.title, entry.source_id)
        if (seen := groups.get(key)) is not None:
            groups[key] = Moment(
                seen.title,
                seen.source_id,
                max(seen.when, entry.timestamp),
                max(seen.severity, explanation.severity_assessment),
                seen.count + 1,
                seen.tags,
            )
        else:
            groups[key] = Moment(
                explanation.title,
                entry.source_id,
                entry.timestamp,
                explanation.severity_assessment,
                1,
                explanation.tags,
            )
    return tuple(groups.values())[: TOP * 2]


class DashboardModel(_Throttled):
    """Keeps a ``Dashboard`` up to date while one of its pages is visible."""

    changed = Signal(object)  # Dashboard

    def __init__(
        self,
        worker: Worker,
        analyst: Analyst,
        sources: Callable[[], Mapping[str, LogSource]],
        parent: QObject | None = None,
    ) -> None:
        self.dashboard: Dashboard | None = None
        self.window = "24h"
        #: Pages showing the dashboard set this; hidden pages cost nothing.
        self.active = False
        #: Set by the window after the first discovery result: by then the backend has
        #: created and migrated the database the worker reads.
        self.ready = False
        self._analyst = analyst
        self._sources = sources
        super().__init__(worker, parent)
        self._timer.setInterval(REFRESH_MS)

    def set_active(self, active: bool) -> None:
        """A page showing the dashboard appeared (refresh now) or went away."""
        self.active = active
        if active and self.ready:
            self.refresh()

    def set_ready(self) -> None:
        """The database exists; refresh now if a page is waiting."""
        if not self.ready:
            self.ready = True
            self.set_active(self.active)

    def set_window(self, window: str) -> None:
        """The Timeline period (15m, 1h, 6h, 24h)."""
        self.window = window
        if self.ready:
            self.refresh()

    def _tick(self) -> None:
        if self.active and self.ready:
            super()._tick()

    def _job(self, storage: Storage) -> Dashboard:
        sources = dict(self._sources())
        return build_dashboard(
            storage,
            lambda e: self._analyst.explain(e, sources.get(e.source_id)),
            window=self.window,
        )

    def _publish(self, result: Dashboard) -> None:
        self.dashboard = result
        self.changed.emit(result)
