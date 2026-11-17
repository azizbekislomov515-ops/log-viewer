import json

from loglens.collectors.discovery.systemd import SystemdDiscoverer
from loglens.core.models import GroupKind, SourceStatus
from tests.fakes import FakeRunner, fail, ok

JSON_CMD = ("systemctl", "list-units", "--type=service", "--all", "--no-pager", "--output=json")
PLAIN_CMD = ("systemctl", "list-units", "--type=service", "--all", "--no-pager", "--plain")

UNITS = [
    {"unit": "nginx.service", "load": "loaded", "active": "active", "sub": "running",
     "description": "A high performance web server"},
    {"unit": "squid.service", "load": "loaded", "active": "failed", "sub": "failed",
     "description": "Squid Web Proxy"},
    {"unit": "cups.service", "load": "loaded", "active": "inactive", "sub": "dead",
     "description": "CUPS Scheduler"},
    {"unit": "alsa-restore.service", "load": "loaded", "active": "active", "sub": "exited",
     "description": "Save/Restore Sound Card State"},
    {"unit": "auditd.service", "load": "not-found", "active": "inactive", "sub": "dead",
     "description": "auditd.service"},
    {"unit": "modprobe@drm.service", "load": "loaded", "active": "inactive", "sub": "dead",
     "description": "Load Kernel Module drm"},
    {"unit": "run-u42.service", "load": "loaded", "active": "active", "sub": "running",
     "description": "transient"},
]  # fmt: skip


def _ids(result):  # type: ignore[no-untyped-def]
    return [s.id for g in result.groups for s in g.sources]


def test_json_output_parsed_and_noise_filtered() -> None:
    runner = FakeRunner({JSON_CMD: ok(json.dumps(UNITS))})
    result = SystemdDiscoverer(runner).discover()

    assert result.issues == ()
    (group,) = result.groups
    assert group.kind is GroupKind.SYSTEM
    assert _ids(result) == [
        "systemd:alsa-restore.service",
        "systemd:cups.service",
        "systemd:nginx.service",
        "systemd:squid.service",
    ]
    by_name = {s.display_name: s for s in group.sources}
    assert by_name["nginx"].status is SourceStatus.RUNNING
    assert by_name["squid"].status is SourceStatus.FAILED
    assert by_name["cups"].status is SourceStatus.STOPPED
    assert by_name["alsa-restore"].status is SourceStatus.STOPPED  # oneshot, finished
    assert by_name["nginx"].metadata["description"] == "A high performance web server"
    assert by_name["squid"].metadata["sub_state"] == "failed"
    # every call is list-args; JSON worked so no fallback
    assert runner.calls == [list(JSON_CMD)]


def test_excludes_and_not_found_are_configurable() -> None:
    runner = FakeRunner({JSON_CMD: ok(json.dumps(UNITS))})
    result = SystemdDiscoverer(runner, exclude=["cups.*"], include_not_found=True).discover()
    ids = _ids(result)
    assert "systemd:auditd.service" in ids
    assert "systemd:modprobe@drm.service" in ids
    assert "systemd:cups.service" not in ids


def test_falls_back_to_plain_output_on_old_systemd() -> None:
    plain = (
        "nginx.service   loaded active running A high performance web server\n"
        "● squid.service loaded failed failed  Squid Web Proxy\n"
        "\n"
        "weird.service   loaded active\n"
    )
    runner = FakeRunner({JSON_CMD: fail("Unknown output 'json'."), PLAIN_CMD: ok(plain)})
    result = SystemdDiscoverer(runner).discover()
    srcs = {s.display_name: s for s in result.groups[0].sources}
    assert set(srcs) == {"nginx", "squid"}
    assert srcs["squid"].status is SourceStatus.FAILED
    assert srcs["nginx"].metadata["description"] == "A high performance web server"
    assert len(runner.calls) == 2


def test_garbage_json_also_falls_back() -> None:
    runner = FakeRunner(
        {JSON_CMD: ok("not json"), PLAIN_CMD: ok("a.service loaded active running A\n")}
    )
    assert _ids(SystemdDiscoverer(runner).discover()) == ["systemd:a.service"]


def test_systemctl_missing_is_an_info_issue() -> None:
    result = SystemdDiscoverer(FakeRunner()).discover()
    assert result.groups == ()
    (issue,) = result.issues
    assert issue.code == "systemd_unavailable"


def test_both_commands_failing_is_an_error_issue() -> None:
    runner = FakeRunner({JSON_CMD: fail("boom"), PLAIN_CMD: fail("Failed to connect to bus")})
    result = SystemdDiscoverer(runner).discover()
    assert result.groups == ()
    assert result.issues[0].code == "systemd_list_failed"
    assert "Failed to connect to bus" in result.issues[0].message
