"""Service Overview: health header, "what's happening" paragraph, cards and a timeline.

Pure functions (no Qt, no storage): the GUI runs ``build_report`` on a worker thread
with entries, their explanations and a severity histogram it loaded, and only renders
the result.

Cards and thresholds come from the rule packs (``overview:`` in ``rules/*.yaml``), never
from per-service code: a pack applies when its ``overview.applies_to`` (or its own
``applies_to``) selects one of the sources, or when one of its rules explained an entry.
"""

from __future__ import annotations

import statistics
from collections import Counter
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from loglens.core.models import Explanation, LogEntry, LogSource, Severity, SourceStatus
from loglens.explain.insights import KEY_FIELDS, Thresholds, summarize
from loglens.explain.rules import CardSpec, Pack

#: Default share of ERROR-or-worse entries that makes a service "degraded".
DEFAULT_ERROR_RATE = 0.05
#: The "now" part of the health header (error rate, the summary) looks at this period.
RECENT = timedelta(minutes=5)
#: Spike detection compares a bucket with up to this many buckets before it ...
BASELINE_BUCKETS = 30
#: ... and needs at least this many of them.
MIN_BASELINE_BUCKETS = 5
#: This many restarts in the period make a service at least "degraded".
RESTARTS_OF_CONCERN = 3
#: Timeline stacks, worst first.
SEVERITY_GROUPS: tuple[tuple[str, Severity], ...] = (
    ("critical", Severity.CRITICAL),
    ("error", Severity.ERROR),
    ("warning", Severity.WARNING),
    ("other", Severity.TRACE),
)
_STATUS_RANK = {
    SourceStatus.FAILED: 3,
    SourceStatus.UNKNOWN: 1,
    SourceStatus.STOPPED: 2,
    SourceStatus.RUNNING: 0,
}


@dataclass(frozen=True, slots=True)
class CardResult:
    """A rendered card. ``rows`` are display strings; ``total`` is how many entries fed it."""

    title: str
    kind: str
    headers: tuple[str, ...]
    rows: tuple[tuple[str, ...], ...]
    total: int
    warn: bool
    empty: str


@dataclass(frozen=True, slots=True)
class Bucket:
    """One timeline bar: counts per severity group (critical, error, warning, other)."""

    start: datetime
    end: datetime
    counts: tuple[int, int, int, int]
    spike: bool = False

    @property
    def total(self) -> int:
        """All entries in the bucket."""
        return sum(self.counts)

    @property
    def errors(self) -> int:
        """ERROR-or-worse entries in the bucket."""
        return self.counts[0] + self.counts[1]


@dataclass(frozen=True, slots=True)
class Health:
    """The header: one state word plus the facts behind it."""

    state: str  # healthy | degraded | failing | quiet
    status: SourceStatus
    error_rate: float
    baseline_error_rate: float | None
    last_error: datetime | None
    last_error_text: str
    last_restart: datetime | None
    restarts: int
    reasons: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class OverviewReport:
    """Everything the Overview page shows."""

    title: str
    source_ids: tuple[str, ...]
    health: Health
    summary: str
    cards: tuple[CardResult, ...]
    timeline: tuple[Bucket, ...]
    start: datetime
    end: datetime
    analyzed: int
    capped: bool
    packs: tuple[str, ...] = field(default_factory=tuple)


def applicable_packs(
    packs: Iterable[Pack],
    sources: Sequence[LogSource],
    explanations: Iterable[Explanation | None],
) -> list[Pack]:
    """Packs with overview cards that apply to these sources (statically or because one
    of their rules explained an entry), in pack order."""
    explained = {e.rule_id.split(".", 1)[0] for e in explanations if e is not None}
    own, seen, generic = [], [], []
    for pack in packs:
        if pack.overview is None:
            continue
        selects = any(pack.selector.matches_source(s) for s in sources)
        wide = pack.overview.selector is not None and any(
            pack.overview.selector.matches_source(s) for s in sources
        )
        if selects and not pack.selector.everything:
            own.append(pack)  # the service's own pack (squid for a Squid container): first
        elif pack.name in explained:
            seen.append(pack)
        elif wide:
            generic.append(pack)  # e.g. Docker lifecycle cards for any container: last
    return own + seen + generic


def build_report(
    title: str,
    sources: Sequence[LogSource],
    entries: Sequence[LogEntry],
    explanations: Mapping[int, Explanation | None],
    histogram: Iterable[tuple[datetime, Severity, int]],
    *,
    packs: Sequence[Pack],
    now: datetime,
    window: timedelta,
    bucket: timedelta,
    capped: bool = False,
) -> OverviewReport:
    """Assemble the Overview for ``sources`` over ``[now - window, now]``.

    ``entries`` are the newest entries of the window (ascending), ``explanations`` their
    explanations by entry id, ``histogram`` exact counts for the whole window.
    """
    start = now - window
    chosen = applicable_packs(packs, sources, explanations.values())
    error_rate_limit = (
        next((p.overview.error_rate for p in chosen if p.overview and p.overview.error_rate), None)
        or DEFAULT_ERROR_RATE
    )
    thresholds = _thresholds(chosen)
    key_fields: dict[str, str] = {}
    for pack in chosen:
        if pack.overview is not None:
            key_fields.update(pack.overview.key_fields)

    def explain(entry: LogEntry) -> Explanation | None:
        return explanations.get(entry.id)

    insight = summarize(
        title,
        entries,
        now=now,
        window=RECENT,
        baseline=window,
        explain=explain,
        key_fields=key_fields or KEY_FIELDS,
        thresholds=thresholds,
    )
    timeline = _timeline(histogram, start, now, bucket, thresholds)
    health = _health(
        sources,
        entries,
        explanations,
        error_rate=insight.error_rate,
        timeline=timeline,
        limit=error_rate_limit,
        now=now,
    )
    pairs = [(e, explanations.get(e.id)) for e in entries]
    cards = tuple(
        card_result(spec, pairs) for p in chosen if p.overview for spec in p.overview.cards
    )
    return OverviewReport(
        title=title,
        source_ids=tuple(s.id for s in sources),
        health=health,
        summary=insight.summary,
        cards=cards,
        timeline=timeline,
        start=start,
        end=now,
        analyzed=len(entries),
        capped=capped,
        packs=tuple(p.name for p in chosen),
    )


def card_result(spec: CardSpec, pairs: Sequence[tuple[LogEntry, Explanation | None]]) -> CardResult:
    """Evaluate one declared card over ``(entry, explanation)`` pairs (oldest first)."""
    selected = [
        (entry, exp)
        for entry, exp in pairs
        if spec.selects(
            exp.rule_id if exp else None,
            exp.tags if exp else (),
            exp.severity_assessment if exp else entry.severity,
        )
    ]
    warn = spec.warn_at is not None and len(selected) >= spec.warn_at
    if spec.kind == "top":
        assert spec.field is not None  # noqa: S101 (schema: top needs a field)
        counts = Counter(
            str(value) for entry, exp in selected if (value := value_of(spec.field, entry, exp))
        )
        top: tuple[tuple[str, ...], ...] = tuple(
            (value, f"{n:,}") for value, n in counts.most_common(spec.limit)
        )
        total = sum(counts.values())
        return CardResult(spec.title, "top", (spec.field, "count"), top, total, warn, spec.empty)
    if spec.kind == "count":
        return CardResult(spec.title, "count", (), (), len(selected), warn, spec.empty)
    newest = selected[-spec.limit :][::-1]
    recent: tuple[tuple[str, ...], ...] = tuple(
        (
            entry.timestamp.astimezone().strftime("%H:%M:%S"),
            exp.title if exp else entry.message.split("\n", 1)[0][:160],
            *(str(value_of(c, entry, exp) or "") for c in spec.columns),
        )
        for entry, exp in newest
    )
    headers = ("time", "what", *spec.columns)
    return CardResult(spec.title, "recent", headers, recent, len(selected), warn, spec.empty)


def value_of(name: str, entry: LogEntry, explanation: Explanation | None) -> object:
    """A value the rule extracted, else a parsed field of the entry."""
    if explanation is not None and explanation.extracted.get(name) not in (None, ""):
        return explanation.extracted[name]
    value = entry.fields.get(name)
    return None if value in (None, "") else value


def _thresholds(packs: Sequence[Pack]) -> Thresholds:
    z = next((p.overview.spike_z for p in packs if p.overview and p.overview.spike_z), None)
    n = next(
        (p.overview.spike_min_errors for p in packs if p.overview and p.overview.spike_min_errors),
        None,
    )
    default = Thresholds()
    return Thresholds(z or default.spike_z, n or default.spike_min_errors)


def _timeline(
    histogram: Iterable[tuple[datetime, Severity, int]],
    start: datetime,
    end: datetime,
    bucket: timedelta,
    thresholds: Thresholds,
) -> tuple[Bucket, ...]:
    count = max(1, int((end - start) / bucket + 0.999))
    first = start
    totals = [[0, 0, 0, 0] for _ in range(count)]
    for when, severity, n in histogram:
        index = int((when - first) / bucket)
        if not 0 <= index < count:
            continue
        group = next(i for i, (_, floor) in enumerate(SEVERITY_GROUPS) if severity >= floor)
        totals[index][group] += n
    buckets = []
    for i, counts in enumerate(totals):
        errors = counts[0] + counts[1]
        history = [t[0] + t[1] for t in totals[max(0, i - BASELINE_BUCKETS) : i]]
        spike = False
        if len(history) >= MIN_BASELINE_BUCKETS and errors >= thresholds.spike_min_errors:
            mean, stdev = statistics.fmean(history), statistics.pstdev(history)
            spike = (errors - mean) / max(stdev, 1.0) >= thresholds.spike_z
        begin = first + i * bucket
        buckets.append(
            Bucket(begin, begin + bucket, (counts[0], counts[1], counts[2], counts[3]), spike)
        )
    return tuple(buckets)


def _health(
    sources: Sequence[LogSource],
    entries: Sequence[LogEntry],
    explanations: Mapping[int, Explanation | None],
    *,
    error_rate: float,
    timeline: Sequence[Bucket],
    limit: float,
    now: datetime,
) -> Health:
    status = max(
        (s.status for s in sources), key=lambda st: _STATUS_RANK[st], default=SourceStatus.UNKNOWN
    )
    recent_start = now - RECENT
    older = [e for e in entries if e.timestamp <= recent_start]
    baseline = sum(e.severity >= Severity.ERROR for e in older) / len(older) if older else None
    last_error = next((e for e in reversed(entries) if e.severity >= Severity.ERROR), None)
    last_error_text = ""
    if last_error is not None:
        exp = explanations.get(last_error.id)
        last_error_text = exp.title if exp else last_error.message.split("\n", 1)[0][:200]
    restarts = [
        e.timestamp for e in entries if (x := explanations.get(e.id)) and "restart" in x.tags
    ]
    loops = any((x := explanations.get(e.id)) and "restart_loop" in x.tags for e in entries)
    reasons: list[str] = []
    if status == SourceStatus.FAILED:
        reasons.append("the service is in a failed state")
    if error_rate >= 2 * limit:
        reasons.append(f"{error_rate:.0%} of recent entries are errors")
    elif error_rate >= limit:
        reasons.append(f"{error_rate:.0%} of recent entries are errors (limit {limit:.0%})")
    if timeline and timeline[-1].spike:
        reasons.append("errors are spiking right now")
    elif any(b.spike for b in timeline):
        reasons.append("there was an error spike in this period")
    if loops:
        reasons.append("it is restarting in a loop")
    elif len(restarts) >= RESTARTS_OF_CONCERN:
        reasons.append(f"it restarted {len(restarts)} times in this period")
    if not entries and not any(b.total for b in timeline):
        state = "quiet"
    elif (
        status == SourceStatus.FAILED
        or error_rate >= 2 * limit
        or (timeline and timeline[-1].spike)
        or loops
    ):
        state = "failing"
    elif reasons:
        state = "degraded"
    else:
        state = "healthy"
    return Health(
        state=state,
        status=status,
        error_rate=error_rate,
        baseline_error_rate=baseline,
        last_error=last_error.timestamp if last_error else None,
        last_error_text=last_error_text,
        last_restart=max(restarts, default=None),
        restarts=len(restarts),
        reasons=tuple(reasons),
    )
