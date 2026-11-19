"""Privilege model: an unprivileged user gets clear, exact fixes; the GUI refuses root."""

from __future__ import annotations

from pathlib import Path

import pytest

from loglens.collectors.discovery.containers import _classify_failure
from loglens.collectors.discovery.files import _unreadable_issue
from loglens.collectors.discovery.systemd import SystemdDiscoverer
from loglens.gui import app
from loglens.security.privileges import journal_access_issue


def test_journal_access_needs_a_journal_group() -> None:
    issue = journal_access_issue({"users", "plugdev"}, euid=1000)
    assert issue is not None
    assert "sudo usermod -aG systemd-journal $USER" in issue.hint
    for group in ("systemd-journal", "adm", "wheel"):
        assert journal_access_issue({group}, euid=1000) is None
    assert journal_access_issue(set(), euid=0) is None


def test_systemd_discovery_reports_limited_journal() -> None:
    def runner(cmd: list[str]) -> object:
        from loglens.collectors.discovery.base import CommandResult  # noqa: PLC0415

        return CommandResult(0, "[]", "")

    check = lambda: journal_access_issue(set(), euid=1000)  # noqa: E731
    result = SystemdDiscoverer(runner, journal_check=check).discover()  # type: ignore[arg-type]
    assert [i.code for i in result.issues] == ["journal_access_limited"]


def test_docker_hint_warns_root_equivalence_and_offers_rootless() -> None:
    issue = _classify_failure("permission denied while connecting", cli_missing=False)
    assert "usermod -aG docker" in issue.hint
    assert "equivalent to root" in issue.hint
    assert "dockerd-rootless-setuptool.sh install" in issue.hint
    assert "DOCKER_HOST=unix:///run/user/$UID/docker.sock" in issue.hint


def test_unreadable_file_hint_has_acl_with_default_for_rotation(tmp_path: Path) -> None:
    log = tmp_path / "my logs" / "squid.log"
    log.parent.mkdir()
    log.write_text("x")
    hint = _unreadable_issue(log).hint
    assert f"sudo setfacl -m u:$USER:r '{log}'" in hint  # quoted: the path has a space
    assert f"sudo setfacl -d -m u:$USER:r '{log.parent}'" in hint


def test_gui_refuses_to_run_as_root(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(app.os, "geteuid", lambda: 0)
    assert app.main([]) == 2
    assert "refusing to run the GUI as root" in capsys.readouterr().err


def test_vault_clear_forgets_live_secrets_and_rotates_key(tmp_path: Path) -> None:
    from loglens.security.redact import Redactor, SecretVault  # noqa: PLC0415

    vault = SecretVault(tmp_path)
    redactor = Redactor(vault=vault)
    text, _ = redactor.redact("password=hunter22")
    assert vault.reveal(text) == "password=hunter22"
    vault.clear()
    assert vault.reveal(text) == text  # gone from memory
    redactor.redact("token=another1")  # a later write must not bring the old one back
    assert "hunter22" not in (tmp_path / "vault.json").read_text()
    assert oct((tmp_path / "vault.json").stat().st_mode & 0o777) == "0o600"
