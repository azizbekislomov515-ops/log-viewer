import asyncio
from collections.abc import Sequence
from datetime import UTC, datetime

from loglens.core.models import (
    DiscoveryIssue,
    DiscoveryResult,
    GroupKind,
    LogSource,
    ServiceGroup,
    SourceKind,
    SourceStatus,
)
from loglens.core.registry import ChangeKind, SourceChange, SourceRegistry, diff_sources
from tests.fakes import FakeDiscoverer

T0 = datetime(2026, 1, 1, tzinfo=UTC)
T1 = datetime(2026, 1, 2, tzinfo=UTC)


def src(name: str, status: SourceStatus = SourceStatus.RUNNING, at: datetime = T0) -> LogSource:
    return LogSource(f"systemd:{name}", SourceKind.SYSTEMD, name, "g", status, discovered_at=at)


def result(*sources: LogSource, issues: tuple[DiscoveryIssue, ...] = ()) -> DiscoveryResult:
    return DiscoveryResult((ServiceGroup("g", "G", GroupKind.SYSTEM, sources),), issues)


def test_diff_sources() -> None:
    a, b, c = src("a"), src("b"), src("c")
    b_failed = src("b", SourceStatus.FAILED)
    c_newer = src("c", at=T1)  # only timestamp differs -> not a change
    changes = diff_sources({"a": a, "b": b, "c": c}, {"b": b_failed, "c": c_newer, "d": src("d")})
    assert sorted((ch.kind, ch.source.display_name) for ch in changes) == [
        (ChangeKind.ADDED, "d"),
        (ChangeKind.REMOVED, "a"),
        (ChangeKind.STATUS_CHANGED, "b"),
    ]
    status = next(ch for ch in changes if ch.kind is ChangeKind.STATUS_CHANGED)
    assert status.previous is b
    assert status.source is b_failed


def test_refresh_emits_events_and_keeps_first_seen_time() -> None:
    disc = FakeDiscoverer(
        "fake",
        [
            result(src("a"), src("b")),
            result(src("a", SourceStatus.FAILED, at=T1), src("c", at=T1)),
            result(src("a", SourceStatus.FAILED, at=T1), src("c", at=T1)),
        ],
    )
    registry = SourceRegistry([disc])
    events: list[Sequence[SourceChange]] = []
    registry.subscribe(events.append)

    first = registry.refresh()
    assert {(c.kind, c.source.display_name) for c in first} == {
        (ChangeKind.ADDED, "a"),
        (ChangeKind.ADDED, "b"),
    }
    second = registry.refresh()
    assert {(c.kind, c.source.display_name) for c in second} == {
        (ChangeKind.STATUS_CHANGED, "a"),
        (ChangeKind.REMOVED, "b"),
        (ChangeKind.ADDED, "c"),
    }
    assert registry.sources["systemd:a"].discovered_at == T0  # first seen preserved
    assert registry.sources["systemd:a"].status is SourceStatus.FAILED
    assert registry.groups[0].sources[0].discovered_at == T0

    assert registry.refresh() == []
    assert len(events) == 2  # no event for a no-op refresh


def test_merges_discoverers_and_collects_issues() -> None:
    issue = DiscoveryIssue("d2", "docker_permission_denied", "nope")
    d1 = FakeDiscoverer("d1", [result(src("a"))])
    d2 = FakeDiscoverer("d2", [DiscoveryResult(issues=(issue,))])
    registry = SourceRegistry([d1, d2])
    registry.refresh()
    assert list(registry.sources) == ["systemd:a"]
    assert registry.issues == (issue,)


def test_crashing_discoverer_keeps_last_known_sources() -> None:
    disc = FakeDiscoverer("flaky", [result(src("a")), RuntimeError("socket hiccup")])
    registry = SourceRegistry([disc])
    registry.refresh()
    assert registry.refresh() == []  # nothing "removed"
    assert "systemd:a" in registry.sources
    (issue,) = registry.issues
    assert issue.code == "discoverer_crashed"
    assert "socket hiccup" in issue.message


def test_bad_listener_does_not_break_refresh_or_other_listeners() -> None:
    registry = SourceRegistry([FakeDiscoverer("d", [result(src("a"))])])
    seen: list[Sequence[SourceChange]] = []

    def boom(_: Sequence[SourceChange]) -> None:
        raise RuntimeError("listener bug")

    registry.subscribe(boom)
    unsubscribe = registry.subscribe(seen.append)
    assert len(registry.refresh()) == 1
    assert len(seen) == 1
    unsubscribe()
    registry._discoverers = (FakeDiscoverer("d", [result()]),)
    registry.refresh()
    assert len(seen) == 1


def test_run_periodic_refreshes_repeatedly() -> None:
    disc = FakeDiscoverer("d", [result(src("a"))])
    registry = SourceRegistry([disc])

    async def scenario() -> None:
        task = asyncio.create_task(registry.run_periodic(0.01))
        while disc.runs < 3:
            await asyncio.sleep(0.005)
        task.cancel()

    asyncio.run(asyncio.wait_for(scenario(), timeout=5))
    assert disc.runs >= 3
