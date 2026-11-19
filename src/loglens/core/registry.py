"""SourceRegistry: runs discoverers, merges their groups, and emits change events."""

from __future__ import annotations

import asyncio
import logging
import threading
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, replace
from enum import StrEnum
from types import MappingProxyType
from typing import TYPE_CHECKING

from loglens.core.models import DiscoveryIssue, DiscoveryResult, LogSource, ServiceGroup, Severity

if TYPE_CHECKING:
    from loglens.collectors.discovery.base import Discoverer

log = logging.getLogger(__name__)


class ChangeKind(StrEnum):
    """What happened to a source between two refreshes."""

    ADDED = "added"
    REMOVED = "removed"
    STATUS_CHANGED = "status_changed"


@dataclass(frozen=True, slots=True)
class SourceChange:
    """One source-level change. For REMOVED, ``source`` is the last known state."""

    kind: ChangeKind
    source: LogSource
    previous: LogSource | None = None


ChangeListener = Callable[[Sequence[SourceChange]], None]


def diff_sources(old: Mapping[str, LogSource], new: Mapping[str, LogSource]) -> list[SourceChange]:
    """Compare two ``{source_id: LogSource}`` snapshots. Only id and status matter."""
    changes = [SourceChange(ChangeKind.ADDED, s) for i, s in new.items() if i not in old]
    changes += [SourceChange(ChangeKind.REMOVED, s) for i, s in old.items() if i not in new]
    changes += [
        SourceChange(ChangeKind.STATUS_CHANGED, s, old[i])
        for i, s in new.items()
        if i in old and old[i].status != s.status
    ]
    return changes


class SourceRegistry:
    """Holds the current view of all log sources.

    ``refresh()`` is synchronous and thread-safe (refreshes are serialized); listeners
    are called on the refreshing thread, once per refresh that produced changes.
    If a discoverer raises, its previous groups are kept and an issue is recorded,
    so a transient failure does not look like every source vanished.
    """

    def __init__(self, discoverers: Sequence[Discoverer]) -> None:
        self._discoverers = tuple(discoverers)
        self._results: dict[str, DiscoveryResult] = {}
        self._groups: tuple[ServiceGroup, ...] = ()
        self._issues: tuple[DiscoveryIssue, ...] = ()
        self._sources: Mapping[str, LogSource] = MappingProxyType({})
        self._listeners: list[ChangeListener] = []
        self._lock = threading.Lock()

    @property
    def groups(self) -> tuple[ServiceGroup, ...]:
        """Groups from the last refresh, in discoverer order."""
        return self._groups

    @property
    def issues(self) -> tuple[DiscoveryIssue, ...]:
        """Issues reported during the last refresh."""
        return self._issues

    @property
    def sources(self) -> Mapping[str, LogSource]:
        """Read-only ``{source_id: LogSource}`` snapshot from the last refresh."""
        return self._sources

    def subscribe(self, listener: ChangeListener) -> Callable[[], None]:
        """Register a change listener; returns a function that unsubscribes it."""
        self._listeners.append(listener)
        return lambda: self._listeners.remove(listener)

    def refresh(self) -> list[SourceChange]:
        """Run every discoverer once, update state, notify listeners, return the changes."""
        with self._lock:
            for discoverer in self._discoverers:
                self._results[discoverer.name] = self._run_one(discoverer)

            old = self._sources
            groups = tuple(
                _keep_first_seen(g, old) for r in self._results.values() for g in r.groups
            )
            new = {s.id: s for g in groups for s in g.sources}
            changes = diff_sources(old, new)

            self._groups = groups
            self._issues = tuple(i for r in self._results.values() for i in r.issues)
            self._sources = MappingProxyType(new)

        if changes:
            for listener in list(self._listeners):
                try:
                    listener(changes)
                except Exception:
                    log.exception("source change listener failed")
        return changes

    async def run_periodic(self, interval: float) -> None:
        """Refresh now and then every ``interval`` seconds until cancelled."""
        while True:
            await asyncio.to_thread(self.refresh)
            await asyncio.sleep(interval)

    def _run_one(self, discoverer: Discoverer) -> DiscoveryResult:
        try:
            return discoverer.discover()
        except Exception as exc:
            log.exception("discoverer crashed", extra={"discoverer": discoverer.name})
            previous = self._results.get(discoverer.name, DiscoveryResult())
            issue = DiscoveryIssue(
                discoverer.name,
                "discoverer_crashed",
                f"{discoverer.name} discovery failed unexpectedly: {exc}",
                Severity.ERROR,
                "Showing the last known sources. See the application log for details.",
            )
            return DiscoveryResult(previous.groups, (issue,))


def _keep_first_seen(group: ServiceGroup, old: Mapping[str, LogSource]) -> ServiceGroup:
    """Carry ``discovered_at`` over for sources we already knew about."""
    sources = tuple(
        replace(s, discovered_at=old[s.id].discovered_at) if s.id in old else s
        for s in group.sources
    )
    return replace(group, sources=sources)
