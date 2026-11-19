import os
from pathlib import Path

import pytest
import yaml

from loglens.collectors.discovery.files import DEFAULT_CATALOG, FileDiscoverer
from loglens.core.models import GroupKind, SourceKind


def _catalog(tmp_path: Path, groups: list[dict[str, object]]) -> Path:
    path = tmp_path / "catalog.yaml"
    path.write_text(yaml.safe_dump({"version": 1, "groups": groups}))
    return path


def test_finds_existing_files_and_prefers_first_existing_candidate(tmp_path: Path) -> None:
    (tmp_path / "squid3").mkdir()
    access = tmp_path / "squid3" / "access.log"
    access.write_text("x")
    cat = _catalog(
        tmp_path,
        [
            {
                "id": "squid",
                "name": "Squid proxy",
                "files": [
                    {
                        "name": "Squid access log",
                        "paths": [str(tmp_path / "squid/access.log"), str(access)],
                    },
                    {"name": "Squid cache log", "paths": [str(tmp_path / "squid/cache.log")]},
                ],
            },
            {"id": "ufw", "name": "UFW", "files": [{"name": "UFW", "paths": ["/nope/ufw.log"]}]},
        ],
    )
    result = FileDiscoverer(cat).discover()

    assert result.issues == ()
    (group,) = result.groups  # ufw had nothing on disk, so no empty group
    assert (group.id, group.name, group.kind) == ("files:squid", "Squid proxy", GroupKind.FILES)
    (src,) = group.sources
    assert src.id == f"file:{access}"
    assert src.kind is SourceKind.FILE
    assert src.metadata == {"path": str(access), "exists": True, "readable": True}


def test_include_missing_reports_absent_files(tmp_path: Path) -> None:
    cat = _catalog(
        tmp_path,
        [{"id": "ufw", "name": "UFW", "files": [{"name": "UFW", "paths": ["/nope/u.log"]}]}],
    )
    (group,) = FileDiscoverer(cat, include_missing=True).discover().groups
    assert group.sources[0].metadata == {"path": "/nope/u.log", "exists": False, "readable": False}


@pytest.mark.skipif(os.geteuid() == 0, reason="root can read anything")
def test_unreadable_file_is_listed_with_actionable_issue(tmp_path: Path) -> None:
    secret = tmp_path / "auth.log"
    secret.write_text("x")
    secret.chmod(0)
    cat = _catalog(
        tmp_path,
        [{"id": "auth", "name": "Auth", "files": [{"name": "Auth", "paths": [str(secret)]}]}],
    )
    result = FileDiscoverer(cat).discover()
    assert result.groups[0].sources[0].metadata["readable"] is False
    (issue,) = result.issues
    assert issue.code == "file_not_readable"
    assert str(secret) in issue.message
    assert issue.hint


@pytest.mark.parametrize(
    "content",
    [
        "groups: [",  # invalid YAML
        "- just a list",
        "groups:\n  - id: x\n    name: X\n    files: []",
        "groups:\n  - id: x\n    name: X\n    files:\n      - name: f\n        paths: [rel/path]",
    ],
)
def test_invalid_catalog_is_an_issue_not_a_crash(tmp_path: Path, content: str) -> None:
    path = tmp_path / "bad.yaml"
    path.write_text(content)
    result = FileDiscoverer(path).discover()
    assert result.groups == ()
    assert result.issues[0].code == "file_catalog_invalid"


def test_missing_catalog_is_an_issue(tmp_path: Path) -> None:
    result = FileDiscoverer(tmp_path / "missing.yaml").discover()
    assert result.issues[0].code == "file_catalog_invalid"


def test_shipped_catalog_is_valid_and_covers_required_services() -> None:
    result = FileDiscoverer(DEFAULT_CATALOG, include_missing=True).discover()
    assert not [i for i in result.issues if i.code == "file_catalog_invalid"]
    ids = {g.id for g in result.groups}
    assert {"files:squid", "files:clamav", "files:nginx", "files:auth", "files:syslog",
            "files:fail2ban", "files:ufw"} <= ids  # fmt: skip
