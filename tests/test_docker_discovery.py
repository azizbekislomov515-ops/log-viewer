import json

import pytest

from loglens.collectors.discovery.containers import DockerDiscoverer, container_status
from loglens.core.models import GroupKind, Severity, SourceStatus
from tests.fakes import (
    FakeDockerClient,
    FakeRunner,
    api_row,
    compose_labels,
    fail,
    ok,
    raising_factory,
)

PERM_ERR = (
    "Error while fetching server API version: ('Connection aborted.', "
    "PermissionError(13, 'Permission denied'))"
)
NOSOCK_ERR = (
    "Error while fetching server API version: ('Connection aborted.', "
    "FileNotFoundError(2, 'No such file or directory'))"
)


def test_compose_grouping() -> None:
    client = FakeDockerClient(
        [
            api_row("shop-web-1", labels=compose_labels("shop", "web")),
            api_row("shop-web-2", labels=compose_labels("shop", "web", 2)),
            api_row("shop-db-1", image="postgres:16", labels=compose_labels("shop", "db")),
            api_row(
                "blog-app-1",
                state="exited",
                status="Exited (1) 3 hours ago",
                labels=compose_labels("blog", "app"),
            ),
            api_row("lonely", image="redis:7"),
        ]
    )
    result = DockerDiscoverer(lambda: client).discover()

    assert result.issues == ()
    assert [(g.id, g.kind) for g in result.groups] == [
        ("compose:blog", GroupKind.DOCKER_COMPOSE),
        ("compose:shop", GroupKind.DOCKER_COMPOSE),
        ("docker:standalone", GroupKind.DOCKER_STANDALONE),
    ]
    shop = result.groups[1]
    assert shop.name == "shop"
    # service name for the first replica, container name for extra replicas
    assert [s.display_name for s in shop.sources] == ["db", "shop-web-2", "web"]
    web = next(s for s in shop.sources if s.display_name == "web")
    assert web.id == "docker:shop-web-1"
    assert web.group_id == "compose:shop"
    assert web.metadata["compose_service"] == "web"
    assert web.metadata["compose_project"] == "shop"
    assert web.metadata["compose_working_dir"] == "/srv/shop"
    assert result.groups[0].sources[0].status is SourceStatus.FAILED
    assert result.groups[0].sources[0].metadata["exit_code"] == 1
    lonely = result.groups[2].sources[0]
    assert lonely.display_name == "lonely"
    assert "compose_project" not in lonely.metadata
    assert client.api.list_calls == [True]  # stopped containers included
    assert client.closed


@pytest.mark.parametrize(
    ("state", "code", "expected"),
    [
        ("running", None, SourceStatus.RUNNING),
        ("exited", 0, SourceStatus.STOPPED),
        ("exited", 143, SourceStatus.STOPPED),
        ("exited", 1, SourceStatus.FAILED),
        ("exited", 137, SourceStatus.FAILED),
        ("restarting", None, SourceStatus.FAILED),
        ("dead", None, SourceStatus.FAILED),
        ("created", None, SourceStatus.STOPPED),
        ("paused", None, SourceStatus.STOPPED),
        ("???", None, SourceStatus.UNKNOWN),
    ],
)
def test_container_status(state: str, code: int | None, expected: SourceStatus) -> None:
    assert container_status(state, code) is expected


def test_permission_denied_is_actionable_issue() -> None:
    runner = FakeRunner(
        {("docker",): fail("permission denied while trying to connect to the Docker daemon socket")}
    )
    result = DockerDiscoverer(raising_factory(Exception(PERM_ERR)), runner).discover()
    assert result.groups == ()
    (issue,) = result.issues
    assert issue.code == "docker_permission_denied"
    assert issue.severity is Severity.WARNING
    assert issue.hint is not None
    assert "docker' group" in issue.hint


def test_docker_not_installed() -> None:
    result = DockerDiscoverer(raising_factory(Exception(NOSOCK_ERR)), FakeRunner()).discover()
    (issue,) = result.issues
    assert issue.code == "docker_not_installed"
    assert issue.severity is Severity.INFO


def test_sdk_missing_and_cli_missing_is_not_installed() -> None:
    factory = raising_factory(ModuleNotFoundError("No module named 'docker'"))
    result = DockerDiscoverer(factory, FakeRunner()).discover()
    assert result.issues[0].code == "docker_not_installed"


def test_daemon_down() -> None:
    runner = FakeRunner(
        {("docker",): fail("Cannot connect to the Docker daemon at unix:///var/run/docker.sock.")}
    )
    result = DockerDiscoverer(raising_factory(Exception(NOSOCK_ERR)), runner).discover()
    assert result.issues[0].code == "docker_daemon_unavailable"


def test_falls_back_to_cli_when_sdk_fails() -> None:
    cid = "a" * 64
    inspect = [
        {
            "Id": cid,
            "Name": "/shop-web-1",
            "Config": {"Image": "nginx:1.27", "Labels": compose_labels("shop", "web")},
            "State": {"Status": "exited", "ExitCode": 0},
        }
    ]
    runner = FakeRunner(
        {
            ("docker", "ps"): ok(f"{cid}\n--evil-flag\n"),
            ("docker", "inspect"): ok(json.dumps(inspect)),
        }
    )
    result = DockerDiscoverer(raising_factory(ImportError("no sdk")), runner).discover()

    assert result.issues == ()
    (group,) = result.groups
    assert group.id == "compose:shop"
    src = group.sources[0]
    assert (src.display_name, src.status) == ("web", SourceStatus.STOPPED)
    # ids that don't look like container ids are never passed as arguments
    assert runner.calls[1] == ["docker", "inspect", cid]


def test_cli_fallback_with_no_containers() -> None:
    runner = FakeRunner({("docker", "ps"): ok("")})
    result = DockerDiscoverer(raising_factory(Exception("x")), runner).discover()
    assert result == type(result)()


def test_cli_inspect_garbage_is_issue() -> None:
    runner = FakeRunner({("docker", "ps"): ok("b" * 64), ("docker", "inspect"): ok("{nope")})
    result = DockerDiscoverer(raising_factory(Exception("x")), runner).discover()
    assert result.issues[0].code == "docker_inspect_failed"
