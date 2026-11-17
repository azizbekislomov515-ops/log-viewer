"""Discover systemd service units via ``systemctl list-units``."""

from __future__ import annotations

import json
import logging
from collections.abc import Sequence
from fnmatch import fnmatchcase

from loglens.collectors.discovery.base import (
    EXIT_NOT_FOUND,
    CommandRunner,
    run_command,
)
from loglens.core.models import (
    DiscoveryIssue,
    DiscoveryResult,
    GroupKind,
    LogSource,
    ServiceGroup,
    Severity,
    SourceKind,
    SourceStatus,
)

log = logging.getLogger(__name__)

GROUP_ID = "system:systemd"

#: Per-device / per-boot / transient template instances that add noise, not insight.
DEFAULT_EXCLUDES: tuple[str, ...] = (
    "run-*.service",
    "dbus-:*.service",
    "modprobe@*.service",
    "systemd-fsck@*.service",
    "systemd-backlight@*.service",
    "systemd-pcrlogin@*.service",
    "user-runtime-dir@*.service",
)

_BASE_CMD = ("systemctl", "list-units", "--type=service", "--all", "--no-pager")

_STATUS_BY_ACTIVE_STATE: dict[str, SourceStatus] = {
    "active": SourceStatus.RUNNING,
    "reloading": SourceStatus.RUNNING,
    "activating": SourceStatus.RUNNING,
    "inactive": SourceStatus.STOPPED,
    "deactivating": SourceStatus.STOPPED,
    "maintenance": SourceStatus.STOPPED,
    "failed": SourceStatus.FAILED,
}


class SystemdDiscoverer:
    """Lists service units. JSON output first; plain-text parsing for systemd < 246."""

    name = "systemd"

    def __init__(
        self,
        runner: CommandRunner = run_command,
        *,
        exclude: Sequence[str] = DEFAULT_EXCLUDES,
        include_not_found: bool = False,
    ) -> None:
        self._run = runner
        self._exclude = tuple(exclude)
        self._include_not_found = include_not_found

    def discover(self) -> DiscoveryResult:
        """List service units and return them as one SYSTEM group."""
        result = self._run([*_BASE_CMD, "--output=json"])
        if result.returncode == EXIT_NOT_FOUND:
            return DiscoveryResult(
                issues=(
                    DiscoveryIssue(
                        self.name,
                        "systemd_unavailable",
                        "systemctl was not found; systemd services cannot be listed.",
                        Severity.INFO,
                        "This machine may not use systemd. File and Docker sources still work.",
                    ),
                )
            )
        units = _parse_json(result.stdout) if result.ok else None
        if units is None:
            log.info("systemctl JSON output unavailable, falling back to plain text")
            result = self._run([*_BASE_CMD, "--plain", "--no-legend"])
            if not result.ok:
                return DiscoveryResult(
                    issues=(
                        DiscoveryIssue(
                            self.name,
                            "systemd_list_failed",
                            f"systemctl failed: {result.stderr.strip() or result.returncode}",
                            Severity.ERROR,
                        ),
                    )
                )
            units = _parse_plain(result.stdout)

        sources = tuple(
            _to_source(u)
            for u in sorted(units, key=lambda u: u["unit"].casefold())
            if self._keep(u)
        )
        group = ServiceGroup(GROUP_ID, "System services", GroupKind.SYSTEM, sources)
        return DiscoveryResult(groups=(group,))

    def _keep(self, unit: dict[str, str]) -> bool:
        if unit["load"] == "not-found" and not self._include_not_found:
            return False
        return not any(fnmatchcase(unit["unit"], pat) for pat in self._exclude)


def _parse_json(stdout: str) -> list[dict[str, str]] | None:
    try:
        data = json.loads(stdout)
    except json.JSONDecodeError:
        return None
    if not isinstance(data, list):
        return None
    keys = ("unit", "load", "active", "sub", "description")
    return [
        {k: str(item.get(k, "")) for k in keys}
        for item in data
        if isinstance(item, dict) and item.get("unit")
    ]


def _parse_plain(stdout: str) -> list[dict[str, str]]:
    """Parse ``UNIT LOAD ACTIVE SUB DESCRIPTION`` rows (``--plain --no-legend``)."""
    units = []
    for line in stdout.splitlines():
        parts = line.lstrip("● ").split(None, 4)
        if len(parts) < 4:
            continue
        unit, load, active, sub = parts[:4]
        units.append(
            {
                "unit": unit,
                "load": load,
                "active": active,
                "sub": sub,
                "description": parts[4] if len(parts) == 5 else "",
            }
        )
    return units


def unit_status(active: str, sub: str) -> SourceStatus:
    """Map systemd ActiveState/SubState to a SourceStatus.

    "active (exited)" is a oneshot that finished successfully: nothing is running.
    """
    if active == "active" and sub == "exited":
        return SourceStatus.STOPPED
    return _STATUS_BY_ACTIVE_STATE.get(active, SourceStatus.UNKNOWN)


def _to_source(unit: dict[str, str]) -> LogSource:
    name = unit["unit"]
    return LogSource(
        id=f"systemd:{name}",
        kind=SourceKind.SYSTEMD,
        display_name=name.removesuffix(".service"),
        group_id=GROUP_ID,
        status=unit_status(unit["active"], unit["sub"]),
        metadata={
            "unit": name,
            "load_state": unit["load"],
            "active_state": unit["active"],
            "sub_state": unit["sub"],
            "description": unit["description"],
        },
    )
