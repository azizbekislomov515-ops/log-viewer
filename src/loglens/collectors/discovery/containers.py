"""Discover Docker containers (running and stopped), grouped by Compose project."""

from __future__ import annotations

import json
import logging
import re
from collections import defaultdict
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any, Protocol

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

COMPOSE_PROJECT = "com.docker.compose.project"
COMPOSE_SERVICE = "com.docker.compose.service"
COMPOSE_NUMBER = "com.docker.compose.container-number"
COMPOSE_ONEOFF = "com.docker.compose.oneoff"
COMPOSE_WORKDIR = "com.docker.compose.project.working_dir"

STANDALONE_GROUP_ID = "docker:standalone"
SDK_TIMEOUT = 10

#: Exit codes that mean "stopped on purpose" (clean exit, SIGINT, SIGTERM).
#: 137 (SIGKILL) is deliberately absent: it is also what an OOM kill looks like.
_CLEAN_EXIT_CODES = frozenset({0, 130, 143})
_EXIT_CODE_RE = re.compile(r"^Exited \((-?\d+)\)")
_CONTAINER_ID_RE = re.compile(r"^[0-9a-f]{12,64}$")


class _ContainerAPI(Protocol):
    def containers(self, *, all: bool = ...) -> Any: ...


class DockerClientLike(Protocol):
    """The slice of ``docker.DockerClient`` we use: the low-level list endpoint."""

    @property
    def api(self) -> _ContainerAPI:
        """Low-level API client."""
        ...

    def close(self) -> None:
        """Release the connection pool."""
        ...


DockerClientFactory = Callable[[], DockerClientLike]


def default_client_factory() -> DockerClientLike:
    """Connect to Docker the way the ``docker`` CLI does (DOCKER_HOST or the default socket)."""
    import docker  # noqa: PLC0415 - optional at runtime; ImportError triggers CLI fallback

    client: DockerClientLike = docker.from_env(timeout=SDK_TIMEOUT)
    return client


@dataclass(frozen=True, slots=True)
class _Container:
    id: str
    name: str
    image: str
    state: str
    exit_code: int | None
    labels: Mapping[str, str]


class DockerDiscoverer:
    """Lists all containers via the Docker SDK, falling back to the ``docker`` CLI."""

    name = "docker"

    def __init__(
        self,
        client_factory: DockerClientFactory = default_client_factory,
        runner: CommandRunner = run_command,
    ) -> None:
        self._client_factory = client_factory
        self._run = runner

    def discover(self) -> DiscoveryResult:
        """List containers; never raises for missing Docker or denied socket access."""
        try:
            containers = self._list_via_sdk()
        except Exception as sdk_error:
            log.info("docker SDK failed, trying CLI", extra={"error": str(sdk_error)})
            containers_or_issue = self._list_via_cli(sdk_error)
            if isinstance(containers_or_issue, DiscoveryIssue):
                return DiscoveryResult(issues=(containers_or_issue,))
            containers = containers_or_issue
        return DiscoveryResult(groups=_group_containers(containers))

    def _list_via_sdk(self) -> list[_Container]:
        client = self._client_factory()
        try:
            rows = client.api.containers(all=True)
        finally:
            client.close()
        return [_from_api_row(row) for row in rows]

    def _list_via_cli(self, sdk_error: Exception) -> list[_Container] | DiscoveryIssue:
        ids_result = self._run(["docker", "ps", "--all", "--quiet", "--no-trunc"])
        if not ids_result.ok:
            return _classify_failure(
                f"{sdk_error}\n{ids_result.stderr}",
                cli_missing=ids_result.returncode == EXIT_NOT_FOUND,
            )
        ids = [i for i in ids_result.stdout.split() if _CONTAINER_ID_RE.match(i)]
        if not ids:
            return []
        inspect = self._run(["docker", "inspect", *ids])
        try:
            rows = json.loads(inspect.stdout) if inspect.ok else None
        except json.JSONDecodeError:
            rows = None
        if not isinstance(rows, list):
            return DiscoveryIssue(
                self.name,
                "docker_inspect_failed",
                f"docker inspect failed: {inspect.stderr.strip() or 'invalid output'}",
                Severity.ERROR,
            )
        return [_from_inspect(row) for row in rows if isinstance(row, dict)]


def _group_containers(containers: list[_Container]) -> tuple[ServiceGroup, ...]:
    """Group containers by Compose project; everything else lands in one standalone group."""
    by_group: dict[str, list[LogSource]] = defaultdict(list)
    names: dict[str, tuple[str, GroupKind]] = {}
    for c in containers:
        project = c.labels.get(COMPOSE_PROJECT)
        if project:
            group_id = f"compose:{project}"
            names[group_id] = (project, GroupKind.DOCKER_COMPOSE)
        else:
            group_id = STANDALONE_GROUP_ID
            names[group_id] = ("Standalone containers", GroupKind.DOCKER_STANDALONE)
        by_group[group_id].append(_to_source(c, group_id))

    groups = [
        ServiceGroup(
            gid,
            names[gid][0],
            names[gid][1],
            tuple(sorted(sources, key=lambda s: s.display_name.casefold())),
        )
        for gid, sources in by_group.items()
    ]
    # Compose projects first (alphabetical), standalone last.
    groups.sort(key=lambda g: (g.kind is GroupKind.DOCKER_STANDALONE, g.name.casefold()))
    return tuple(groups)


def _to_source(c: _Container, group_id: str) -> LogSource:
    service = c.labels.get(COMPOSE_SERVICE)
    number = c.labels.get(COMPOSE_NUMBER, "1")
    oneoff = c.labels.get(COMPOSE_ONEOFF, "").lower() == "true"
    display = service if service and number == "1" and not oneoff else c.name
    metadata: dict[str, Any] = {
        "container_id": c.id[:12],
        "container_name": c.name,
        "image": c.image,
        "state": c.state,
    }
    if c.exit_code is not None:
        metadata["exit_code"] = c.exit_code
    if COMPOSE_PROJECT in c.labels:
        metadata["compose_project"] = c.labels[COMPOSE_PROJECT]
        metadata["compose_service"] = service or ""
        metadata["compose_working_dir"] = c.labels.get(COMPOSE_WORKDIR, "")
    return LogSource(
        id=f"docker:{c.name}",
        kind=SourceKind.DOCKER_CONTAINER,
        display_name=display,
        group_id=group_id,
        status=container_status(c.state, c.exit_code),
        metadata=metadata,
    )


def container_status(state: str, exit_code: int | None) -> SourceStatus:
    """Map Docker's container state (+ exit code) to a SourceStatus."""
    match state:
        case "running":
            return SourceStatus.RUNNING
        case "restarting" | "dead":  # restarting == crash loop in practice
            return SourceStatus.FAILED
        case "exited":
            ok = exit_code is None or exit_code in _CLEAN_EXIT_CODES
            return SourceStatus.STOPPED if ok else SourceStatus.FAILED
        case "created" | "paused" | "removing":
            return SourceStatus.STOPPED
        case _:
            return SourceStatus.UNKNOWN


def _from_api_row(row: Mapping[str, Any]) -> _Container:
    """Row from ``GET /containers/json`` (low-level ``api.containers``)."""
    names = row.get("Names") or [row.get("Id", "")[:12]]
    match = _EXIT_CODE_RE.match(row.get("Status") or "")
    return _Container(
        id=row.get("Id", ""),
        name=str(names[0]).lstrip("/"),
        image=row.get("Image", ""),
        state=row.get("State", ""),
        exit_code=int(match.group(1)) if match else None,
        labels=row.get("Labels") or {},
    )


def _from_inspect(row: Mapping[str, Any]) -> _Container:
    """Object from ``docker inspect``."""
    config = row.get("Config") or {}
    state = row.get("State") or {}
    status = state.get("Status", "")
    return _Container(
        id=row.get("Id", ""),
        name=str(row.get("Name", "")).lstrip("/"),
        image=config.get("Image", ""),
        state=status,
        exit_code=state.get("ExitCode") if status == "exited" else None,
        labels=config.get("Labels") or {},
    )


def _classify_failure(error_text: str, *, cli_missing: bool) -> DiscoveryIssue:
    text = error_text.lower()
    if "permission denied" in text:
        return DiscoveryIssue(
            DockerDiscoverer.name,
            "docker_permission_denied",
            "Docker socket not accessible: permission denied.",
            Severity.WARNING,
            "Add your user to the 'docker' group (sudo usermod -aG docker $USER), then log out "
            "and back in. Note: docker group membership is equivalent to root access.",
        )
    if cli_missing:  # SDK could not connect and there is no docker binary either
        return DiscoveryIssue(
            DockerDiscoverer.name,
            "docker_not_installed",
            "Docker does not appear to be installed.",
            Severity.INFO,
        )
    return DiscoveryIssue(
        DockerDiscoverer.name,
        "docker_daemon_unavailable",
        "Cannot connect to the Docker daemon.",
        Severity.WARNING,
        "Check that Docker is running (systemctl status docker) and that DOCKER_HOST, "
        "if set, points to the right socket.",
    )
