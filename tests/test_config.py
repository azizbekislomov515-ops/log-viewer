"""Settings file: defaults, round trip, bad input never blocks start-up."""

import stat
from datetime import timedelta
from pathlib import Path

import pytest

from loglens.config import Settings, config_dir, load_settings, save_settings


def test_missing_file_gives_defaults(tmp_path: Path) -> None:
    assert load_settings(tmp_path / "nope.toml") == Settings()


def test_round_trip_is_private_and_exact(tmp_path: Path) -> None:
    path = tmp_path / "sub" / "config.toml"
    settings = Settings(
        theme="dark",
        retention_days=30,
        max_rows_per_source=5000,
        rule_dirs=('/opt/rules "x"', "C:\\odd\\path"),
        discovery_exclude=("systemd:*.scope",),
        discovery_interval_s=60,
        pinned=("systemd:ssh.service",),
    )
    save_settings(settings, path)
    assert load_settings(path) == settings
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert "[storage]" in path.read_text()


@pytest.mark.parametrize(
    "text",
    [
        "this is = = not toml",
        "[appearance]\ntheme = 'neon'\n",
        "[storage]\nretention_days = -1\nmax_rows_per_source = 'many'\n",
        "[rules]\nrule_dirs = [1, 2]\n",
        "[storage]\nretention_days = true\n",
    ],
)
def test_bad_values_fall_back_to_defaults(tmp_path: Path, text: str) -> None:
    path = tmp_path / "config.toml"
    path.write_text(text, encoding="utf-8")
    assert load_settings(path) == Settings()


def test_unreadable_file_gives_defaults(tmp_path: Path) -> None:
    path = tmp_path / "config.toml"
    path.write_bytes(b"\xff\xfe")
    assert load_settings(path) == Settings()


def test_retention_and_exclusion() -> None:
    settings = Settings(retention_days=3, max_rows_per_source=0)
    assert settings.retention.max_age == timedelta(days=3)
    assert settings.retention.max_rows_per_source is None
    assert Settings(retention_days=0).retention.max_age is None
    assert Settings().excluded("systemd:session-4.scope")
    assert not Settings().excluded("systemd:ssh.service")


def test_config_dir_honours_xdg(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    assert config_dir() == tmp_path / "loglens"
    monkeypatch.delenv("XDG_CONFIG_HOME")
    assert config_dir() == Path.home() / ".config" / "loglens"
