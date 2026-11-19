"""Aggregate insights: "what is happening now" per source, over a window of entries.

``analyze`` is a pure function of the entries it is given (e.g. the live ring buffer) and
``now``, so the GUI can call it on a timer and tests are deterministic.

* **Rate / errors**: events per minute and the share of ERROR-or-worse entries in the window.
* **Spike**: errors in the last minute vs. a baseline of per-minute error counts over the
  preceding ``baseline`` period (z-score). Needs ``MIN_BASELINE_MINUTES`` of history.
* **Top values**: most frequent values of ``KEY_FIELDS`` (clients, domains, status codes...).
* **Restarts**: entries whose explanation carries the ``restart`` tag.
* **Repeats**: messages that only differ in numbers/hex ids, collapsed with a count.
"""

from __future__ import annotations

import re
import statistics
from collections import Counter, defaultdict
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, replace
from datetime import datetime, timedelta

from loglens.core.models import Explanation, LogEntry, Severity

#: Fields worth a "top N" listing, with the label used in summaries.
KEY_FIELDS: Mapping[str, str] = {
    "client_ip": "client",
    "src_ip": "source IP",
    "domain": "domain",
    "status": "status code",
    "user": "user",
}
MIN_BASELINE_MINUTES = 5
#: A spike needs at least this many errors in the last minute, and this z-score.
SPIKE_MIN_ERRORS = 5
SPIKE_Z = 3.0
_MINUTE = timedelta(minutes=1)
_VARIABLE = re.compile(r"\b[0-9a-fA-F]{8,}\b|\d+")

Explain = Callable[[LogEntry], Explanation | None]


@dataclass(frozen=True, slots=True)
class Spike:
    """Errors in the last minute compared with the per-minute baseline."""

    errors_last_minute: int
    baseline_mean: float
    baseline_stdev: float
    z_score: float


@dataclass(frozen=True, slots=True)
class Repeat:
    """Messages that differ only in numbers/ids, collapsed. ``example`` is the first one."""

    example: str
    count: int
    first: datetime
    last: datetime


@dataclass(frozen=True, slots=True)
class SourceInsight:
    """Aggregates for one source over ``[start, end]``; ``summary`` is one paragraph."""

    source_id: str
    start: datetime
    end: datetime
    total: int
    events_per_min: float
    errors: int
    error_rate: float
    spike: Spike | None
    top: Mapping[str, tuple[tuple[str, int], ...]]
    restarts: int
    last_restart: datetime | None
    repeated: tuple[Repeat, ...]
    summary: str


def analyze(
    entries: Iterable[LogEntry],
    *,
    now: datetime | None = None,
    window: timedelta = timedelta(minutes=5),
    baseline: timedelta = timedelta(hours=1),
    explain: Explain | None = None,
    top_n: int = 5,
    repeat_threshold: int = 10,
) -> dict[str, SourceInsight]:
    """Insights per source id. ``now`` defaults to the newest entry's timestamp.

    Entries older than ``now - window - baseline`` are ignored; ``explain`` (usually
    ``ExplanationEngine.explain``) is only called for entries inside the window.
    """
    by_source: dict[str, list[LogEntry]] = defaultdict(list)
    for entry in entries:
        by_source[entry.source_id].append(entry)
    if now is None:
        stamps = [e.timestamp for group in by_source.values() for e in group]
        if not stamps:
            return {}
        now = max(stamps)
    return {
        source_id: _one(
            source_id,
            group,
            now=now,
            window=window,
            baseline=baseline,
            explain=explain,
            top_n=top_n,
            repeat_threshold=repeat_threshold,
        )
        for source_id, group in sorted(by_source.items())
    }


def _one(
    source_id: str,
    entries: Sequence[LogEntry],
    *,
    now: datetime,
    window: timedelta,
    baseline: timedelta,
    explain: Explain | None,
    top_n: int,
    repeat_threshold: int,
) -> SourceInsight:
    start = now - window
    recent = [e for e in entries if start < e.timestamp <= now]
    errors = sum(e.severity >= Severity.ERROR for e in recent)
    minutes = window / _MINUTE
    top = _top(recent, top_n)
    restarts = _restarts(recent, explain)
    repeated = _repeats(recent, repeat_threshold)
    spike = _spike(entries, now, baseline)
    insight = SourceInsight(
        source_id=source_id,
        start=start,
        end=now,
        total=len(recent),
        events_per_min=len(recent) / minutes,
        errors=errors,
        error_rate=errors / len(recent) if recent else 0.0,
        spike=spike,
        top=top,
        restarts=len(restarts),
        last_restart=max(restarts, default=None),
        repeated=repeated,
        summary="",
    )
    return _with_summary(insight, minutes)


def _top(entries: Sequence[LogEntry], n: int) -> dict[str, tuple[tuple[str, int], ...]]:
    counters: dict[str, Counter[str]] = {key: Counter() for key in KEY_FIELDS}
    for entry in entries:
        for key, counter in counters.items():
            value = entry.fields.get(key)
            if value is not None and value != "":
                counter[str(value)] += 1
    return {key: tuple(c.most_common(n)) for key, c in counters.items() if c}


def _restarts(entries: Sequence[LogEntry], explain: Explain | None) -> list[datetime]:
    if explain is None:
        return []
    found = []
    for entry in entries:
        explanation = explain(entry)
        if explanation is not None and "restart" in explanation.tags:
            found.append(entry.timestamp)
    return found


def _repeats(entries: Sequence[LogEntry], threshold: int) -> tuple[Repeat, ...]:
    groups: dict[str, list[LogEntry]] = defaultdict(list)
    for entry in entries:
        groups[_VARIABLE.sub("#", entry.message)].append(entry)
    repeats = [
        Repeat(group[0].message, len(group), group[0].timestamp, group[-1].timestamp)
        for group in groups.values()
        if len(group) >= threshold
    ]
    return tuple(sorted(repeats, key=lambda r: -r.count))


def _spike(entries: Sequence[LogEntry], now: datetime, baseline: timedelta) -> Spike | None:
    current_start = now - _MINUTE
    history_start = now - _MINUTE - baseline
    first = min((e.timestamp for e in entries), default=now)
    history_start = max(history_start, first)  # don't count minutes before the source existed
    bins = int((current_start - history_start) / _MINUTE)
    if bins < MIN_BASELINE_MINUTES:
        return None
    counts = [0] * bins
    current = 0
    for entry in entries:
        if entry.severity < Severity.ERROR or not history_start <= entry.timestamp <= now:
            continue
        if entry.timestamp > current_start:
            current += 1
        else:
            index = int((current_start - entry.timestamp) / _MINUTE)
            if index < bins:
                counts[index] += 1
    mean = statistics.fmean(counts)
    stdev = statistics.pstdev(counts)
    # ponytail: stdev floor of 1 so a flat-zero baseline doesn't make every error a spike;
    # switch to a robust (median/MAD) baseline if noisy sources trip it.
    z = (current - mean) / max(stdev, 1.0)
    if current >= SPIKE_MIN_ERRORS and z >= SPIKE_Z:
        return Spike(current, mean, stdev, z)
    return None


def _with_summary(insight: SourceInsight, minutes: float) -> SourceInsight:
    span = f"{minutes:g} min"
    if insight.total == 0:
        parts = [f"{insight.source_id}: quiet, no events in the last {span}."]
    else:
        parts = [
            f"{insight.source_id}: {insight.total} event{_s(insight.total)} in the last "
            f"{span} ({insight.events_per_min:.1f}/min)."
        ]
        if insight.errors:
            parts.append(
                f"{insight.errors} error{_s(insight.errors)} ({insight.error_rate:.0%} of events)."
            )
        else:
            parts.append("No errors.")
    if spike := insight.spike:
        parts.append(
            f"Error spike: {spike.errors_last_minute} errors in the last minute against a "
            f"usual {spike.baseline_mean:.1f} per minute."
        )
    if insight.restarts and insight.last_restart is not None:
        parts.append(
            f"Restarted {insight.restarts} time{_s(insight.restarts)}, most recently at "
            f"{insight.last_restart.astimezone():%H:%M:%S}."
        )
    for key, label in KEY_FIELDS.items():
        if values := insight.top.get(key):
            value, count = values[0]
            parts.append(f"Most frequent {label}: {value} ({count} event{_s(count)}).")
    if insight.repeated:
        top = insight.repeated[0]
        example = top.example if len(top.example) <= 80 else top.example[:79] + "…"
        parts.append(f'"{example}" (or similar) repeated {top.count} times in {span}.')
    if insight.total and not (insight.errors or insight.spike or insight.restarts):
        parts.append("Looks healthy.")
    return replace(insight, summary=" ".join(parts))


def _s(n: int) -> str:
    return "" if n == 1 else "s"
