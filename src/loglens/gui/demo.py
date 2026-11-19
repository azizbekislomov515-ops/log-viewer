"""Demo mode: fake sources that replay the fixture corpus through the real pipeline.

Used by ``loglens --demo`` (try the GUI without Docker or root), the stress test
(``--replay-rate``) and the screenshot tool. Everything after the collector (assembler,
parsers, storage, GUI) is the production code path. Timestamps are replaced by the
replay time so the demo looks live and time filters work.
"""

from __future__ import annotations

import asyncio
import itertools
from collections.abc import AsyncIterator
from dataclasses import replace
from datetime import datetime
from pathlib import Path

from loglens.collectors.base import ErrorCallback
from loglens.core.models import (
    DiscoveryIssue,
    DiscoveryResult,
    GroupKind,
    LogEntry,
    LogSource,
    RawRecord,
    ServiceGroup,
    Severity,
    SourceKind,
    SourceStatus,
    utc_now,
)
from loglens.parsers import Normalizer
from loglens.resources import data_path

FIXTURES = data_path("demo_logs")

_R, _S, _F = SourceStatus.RUNNING, SourceStatus.STOPPED, SourceStatus.FAILED
#: (group id, group name, kind, [(source id, display name, status, fixture, metadata)])
_Layout = tuple[
    tuple[str, str, GroupKind, tuple[tuple[str, str, SourceStatus, str, dict[str, str]], ...]], ...
]
_LAYOUT: _Layout = (
    (
        "systemd",
        "System services",
        GroupKind.SYSTEM,
        (
            ("systemd:ssh.service", "ssh", _R, "auth.log", {"unit": "ssh.service"}),
            ("systemd:docker.service", "docker", _R, "dockerd.log", {"unit": "docker.service"}),
            (
                "systemd:clamav-daemon.service",
                "clamav-daemon",
                _R,
                "clamav.log",
                {"unit": "clamav-daemon.service"},
            ),
            (
                "systemd:clamav-freshclam.service",
                "clamav-freshclam",
                _R,
                "freshclam.log",
                {"unit": "clamav-freshclam.service"},
            ),
            (
                "systemd:worker.service",
                "worker",
                _F,
                "python_traceback.log",
                {"unit": "worker.service"},
            ),
            ("systemd:myapp.service", "myapp", _R, "iso_text.log", {"unit": "myapp.service"}),
            ("systemd:cron.service", "cron", _S, "", {"unit": "cron.service"}),
        ),
    ),
    (
        "compose:shop",
        "shop",
        GroupKind.DOCKER_COMPOSE,
        (
            (
                "docker:shop-web-1",
                "web",
                _R,
                "nginx_access.log",
                {"container_name": "shop-web-1", "image": "nginx:1.27", "compose_service": "web"},
            ),
            (
                "docker:shop-api-1",
                "api",
                _R,
                "jsonlines.log",
                {"container_name": "shop-api-1", "image": "shop/api:2.3", "compose_service": "api"},
            ),
            (
                "docker:shop-orders-1",
                "orders",
                _R,
                "java_stacktrace.log",
                {
                    "container_name": "shop-orders-1",
                    "image": "shop/orders:1.9",
                    "compose_service": "orders",
                },
            ),
            (
                "docker:shop-loki-1",
                "loki",
                _S,
                "logfmt.log",
                {
                    "container_name": "shop-loki-1",
                    "image": "grafana/loki:3",
                    "compose_service": "loki",
                },
            ),
        ),
    ),
    (
        "docker:standalone",
        "Standalone containers",
        GroupKind.DOCKER_STANDALONE,
        (
            (
                "docker:metrics",
                "metrics",
                _R,
                "syslog_rfc5424.log",
                {"container_name": "metrics", "image": "busybox"},
            ),
        ),
    ),
    (
        "files:squid",
        "Squid proxy",
        GroupKind.FILES,
        (
            (
                "file:/var/log/squid/access.log",
                "Squid access log",
                _R,
                "squid_access.log",
                {"path": "/var/log/squid/access.log"},
            ),
            (
                "file:/var/log/squid/cache.log",
                "Squid cache log",
                _R,
                "squid_cache.log",
                {"path": "/var/log/squid/cache.log"},
            ),
        ),
    ),
    (
        "files:nginx",
        "Nginx",
        GroupKind.FILES,
        (
            (
                "file:/var/log/nginx/error.log",
                "Nginx error log",
                _R,
                "nginx_error.log",
                {"path": "/var/log/nginx/error.log"},
            ),
        ),
    ),
)

_KIND = {
    "systemd": SourceKind.SYSTEMD,
    "docker": SourceKind.DOCKER_CONTAINER,
    "file": SourceKind.FILE,
}


def demo_fixture(source_id: str) -> Path | None:
    """The fixture a demo source replays."""
    for _, _, _, sources in _LAYOUT:
        for sid, _, _, fixture, _ in sources:
            if sid == source_id and fixture:
                return FIXTURES / fixture
    return None


class DemoDiscoverer:
    """Always "discovers" the demo layout, plus one realistic issue."""

    name = "demo"

    def discover(self) -> DiscoveryResult:
        """The fixed demo groups."""
        groups = tuple(
            ServiceGroup(
                gid,
                name,
                kind,
                tuple(
                    LogSource(sid, _KIND[sid.partition(":")[0]], label, gid, status, meta)
                    for sid, label, status, _, meta in sources
                ),
            )
            for gid, name, kind, sources in _LAYOUT
        )
        issue = DiscoveryIssue(
            "files",
            "file_not_readable",
            "/var/log/clamav/clamav.log exists but is not readable by your user.",
            Severity.WARNING,
            "Add yourself to the group that owns it (usually 'adm'): "
            "sudo usermod -aG adm $USER, then log out and back in.",
        )
        return DiscoveryResult(groups, (issue,))


class ReplayCollector:
    """Replays a source's fixture lines forever at ``rate`` lines per second."""

    def __init__(self, rate: float = 5.0, *, burst_ms: int = 10) -> None:
        self.rate = rate
        self._burst = burst_ms / 1000

    async def stream(
        self,
        source: LogSource,
        *,
        cursor: str | None = None,
        since: datetime | None = None,
        lines: int = 0,
        follow: bool = True,
        on_error: ErrorCallback | None = None,
    ) -> AsyncIterator[RawRecord]:
        """Yield fixture lines in small bursts, paced to ``rate``."""
        path = demo_fixture(source.id)
        if path is None:
            return
        text = path.read_text(encoding="utf-8", errors="replace").splitlines()
        loop = asyncio.get_running_loop()
        start = loop.time()
        for sent, line in enumerate(itertools.cycle(text), 1):
            yield RawRecord(source.id, line, utc_now())
            due = start + sent / self.rate
            if due - loop.time() > self._burst:
                await asyncio.sleep(due - loop.time())


class DemoNormalizer:
    """The production normalizer, with the replay time as the entry's timestamp."""

    def __init__(self) -> None:
        self._normalize = Normalizer()

    def __call__(self, source: LogSource, record: RawRecord) -> LogEntry:
        """Parse normally, then use the collector's (replay) time."""
        entry = self._normalize(source, record)
        return replace(entry, timestamp=record.timestamp or entry.timestamp)
