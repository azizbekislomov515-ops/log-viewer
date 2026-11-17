"""Test doubles for systemctl, the docker CLI/SDK, and discoverers."""

from __future__ import annotations

from collections.abc import Callable, Iterable, Sequence
from typing import Any

from loglens.collectors.discovery.base import EXIT_NOT_FOUND, CommandResult
from loglens.core.models import DiscoveryResult


class FakeRunner:
    """CommandRunner that answers by argv prefix. Unmatched commands look 'not installed'."""

    def __init__(self, responses: dict[tuple[str, ...], CommandResult] | None = None) -> None:
        self.responses = responses or {}
        self.calls: list[list[str]] = []

    def __call__(self, args: Sequence[str], timeout: float = 10.0) -> CommandResult:
        argv = list(args)
        self.calls.append(argv)
        # Longest matching prefix wins so specific entries override generic ones.
        for prefix in sorted(self.responses, key=len, reverse=True):
            if tuple(argv[: len(prefix)]) == prefix:
                return self.responses[prefix]
        return CommandResult(EXIT_NOT_FOUND, "", f"command not found: {argv[0]}")


def ok(stdout: str = "") -> CommandResult:
    return CommandResult(0, stdout, "")


def fail(stderr: str, code: int = 1) -> CommandResult:
    return CommandResult(code, "", stderr)


class _FakeAPI:
    def __init__(self, rows: list[dict[str, Any]]) -> None:
        self.rows = rows
        self.list_calls: list[bool] = []

    def containers(self, *, all: bool = False) -> list[dict[str, Any]]:
        self.list_calls.append(all)
        return self.rows


class FakeDockerClient:
    def __init__(self, rows: list[dict[str, Any]]) -> None:
        self.api = _FakeAPI(rows)
        self.closed = False

    def close(self) -> None:
        self.closed = True


def raising_factory(exc: Exception) -> Callable[[], FakeDockerClient]:
    def factory() -> FakeDockerClient:
        raise exc

    return factory


def api_row(
    name: str,
    *,
    state: str = "running",
    status: str = "Up 2 hours",
    image: str = "nginx:latest",
    labels: dict[str, str] | None = None,
    container_id: str | None = None,
) -> dict[str, Any]:
    """A row shaped like Docker's ``GET /containers/json``."""
    return {
        "Id": container_id or (name.encode().hex() * 8)[:64],
        "Names": [f"/{name}"],
        "Image": image,
        "State": state,
        "Status": status,
        "Labels": labels or {},
    }


def compose_labels(project: str, service: str, number: int = 1) -> dict[str, str]:
    return {
        "com.docker.compose.project": project,
        "com.docker.compose.service": service,
        "com.docker.compose.container-number": str(number),
        "com.docker.compose.project.working_dir": f"/srv/{project}",
    }


class FakeDiscoverer:
    """Returns queued results in order (repeating the last); an Exception entry is raised."""

    def __init__(self, name: str, results: Iterable[DiscoveryResult | Exception]) -> None:
        self.name = name
        self._results = list(results)
        self.runs = 0

    def discover(self) -> DiscoveryResult:
        item = self._results[min(self.runs, len(self._results) - 1)]
        self.runs += 1
        if isinstance(item, Exception):
            raise item
        return item
