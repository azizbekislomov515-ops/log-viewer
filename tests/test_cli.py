import io
import json

from loglens import __version__
from loglens.cli import cmd_sources
from loglens.core.models import (
    DiscoveryIssue,
    DiscoveryResult,
    GroupKind,
    LogSource,
    ServiceGroup,
    SourceKind,
    SourceStatus,
)
from tests.fakes import FakeDiscoverer

SOURCES = (
    LogSource("docker:shop-web-1", SourceKind.DOCKER_CONTAINER, "web", "compose:shop",
              SourceStatus.RUNNING, {"image": "nginx:1.27", "state": "running"}),
    LogSource("file:/var/log/auth.log", SourceKind.FILE, "Auth log", "compose:shop",
              metadata={"path": "/var/log/auth.log", "readable": False}),
)  # fmt: skip
ISSUE = DiscoveryIssue("docker", "docker_permission_denied", "Socket denied.", hint="Join docker.")
DISCOVERERS = [
    FakeDiscoverer(
        "d",
        [DiscoveryResult((ServiceGroup("compose:shop", "shop", GroupKind.DOCKER_COMPOSE, SOURCES),),
                         (ISSUE,))],
    )
]  # fmt: skip


def test_version() -> None:
    assert __version__


def test_table_output() -> None:
    out = io.StringIO()
    assert cmd_sources(DISCOVERERS, as_json=False, out=out) == 0
    text = out.getvalue()
    assert "shop  [docker_compose, 2 sources]" in text
    assert "nginx:1.27  (running)" in text
    assert "/var/log/auth.log  [not readable]" in text
    assert "[warning] docker: Socket denied." in text
    assert "-> Join docker." in text


def test_json_output() -> None:
    out = io.StringIO()
    cmd_sources(DISCOVERERS, as_json=True, out=out)
    data = json.loads(out.getvalue())
    (group,) = data["groups"]
    assert group["kind"] == "docker_compose"
    web = group["sources"][0]
    assert web["kind"] == "docker_container"
    assert web["status"] == "running"
    assert web["metadata"]["image"] == "nginx:1.27"
    assert web["discovered_at"].endswith("+00:00")
    assert data["issues"][0]["severity"] == "warning"
    assert data["issues"][0]["hint"] == "Join docker."


def test_empty_machine() -> None:
    out = io.StringIO()
    cmd_sources([FakeDiscoverer("d", [DiscoveryResult()])], as_json=False, out=out)
    assert out.getvalue() == "No log sources found.\n"


def test_table_neutralizes_terminal_escapes() -> None:
    evil = LogSource("docker:x", SourceKind.DOCKER_CONTAINER, "x\x1b]0;pwned\x07", "g",
                     metadata={"image": "img\x1b[2J\x9b31m", "state": "running"})  # fmt: skip
    group = ServiceGroup("g", "grp\x1b[1m", GroupKind.DOCKER_STANDALONE, (evil,))
    out = io.StringIO()
    cmd_sources([FakeDiscoverer("d", [DiscoveryResult((group,))])], as_json=False, out=out)
    text = out.getvalue()
    assert "\x1b" not in text
    assert "\x9b" not in text
    assert "\x07" not in text
    assert "grp?[1m" in text
