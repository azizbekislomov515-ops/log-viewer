"""User settings in ``$XDG_CONFIG_HOME/loglens/config.toml`` (``~/.config/loglens/``).

Read with the stdlib ``tomllib``; written by a tiny serializer for this fixed schema (strings,
ints, string lists), atomically and owner-only. A missing or broken file gives defaults:
a typo in the config must never stop the app from starting.
"""

from __future__ import annotations

import logging
import os
import tomllib
from dataclasses import dataclass, field, fields, replace
from datetime import timedelta
from fnmatch import fnmatchcase
from pathlib import Path
from typing import Any

from loglens.security.redact import Redactor, SecretVault
from loglens.storage import RetentionPolicy

log = logging.getLogger(__name__)

THEMES = ("system", "light", "dark")
#: How explanations show under log rows: not at all, the title only, or the full sentence.
INLINE_MODES = ("off", "compact", "full")


def config_dir() -> Path:
    """``$XDG_CONFIG_HOME/loglens`` (default ``~/.config/loglens``)."""
    base = os.environ.get("XDG_CONFIG_HOME") or str(Path.home() / ".config")
    return Path(base) / "loglens"


def data_dir() -> Path:
    """``$XDG_DATA_HOME/loglens`` (default ``~/.local/share/loglens``)."""
    base = os.environ.get("XDG_DATA_HOME") or str(Path.home() / ".local" / "share")
    return Path(base) / "loglens"


def default_config_path() -> Path:
    """Where settings live."""
    return config_dir() / "config.toml"


@dataclass(frozen=True, slots=True)
class Settings:
    """Everything the settings dialog edits. Field names are the TOML keys."""

    theme: str = "system"
    retention_days: int = 7
    max_rows_per_source: int = 100_000
    rule_dirs: tuple[str, ...] = ()
    #: Source-id globs hidden from the tree, e.g. ``systemd:*.scope``.
    discovery_exclude: tuple[str, ...] = ("systemd:user@*", "systemd:*.scope")
    discovery_interval_s: int = 30
    #: Sources followed in the background (unread badges) even without an open tab.
    pinned: tuple[str, ...] = field(default=())
    inline_explanations: str = "off"
    #: Desktop notification conditions (see ``gui.notify.CONDITIONS``).
    notify_on: tuple[str, ...] = ("critical", "detection", "restart_loop")
    #: Sources that never raise desktop notifications.
    muted: tuple[str, ...] = ()
    #: Remove secrets before anything is stored (strongly recommended).
    redact_secrets: bool = True
    #: Extra regexes whose matches are redacted (e.g. internal ticket tokens).
    redact_patterns: tuple[str, ...] = ()
    #: Keep originals in an owner-only local vault so they can be revealed in the app.
    redact_reversible: bool = False
    #: Resource budgets (0 = unlimited).
    memory_budget_mb: int = 1024
    disk_budget_mb: int = 2048
    max_collectors: int = 64

    def redactor(self) -> Redactor:
        """The secret redactor these settings describe."""
        vault = SecretVault(data_dir() / "vault") if self.redact_reversible else None
        return Redactor(self.redact_patterns, vault=vault, enabled=self.redact_secrets)

    @property
    def retention(self) -> RetentionPolicy:
        """The storage retention policy these settings describe (0 disables a rule)."""
        return RetentionPolicy(
            max_age=timedelta(days=self.retention_days) if self.retention_days > 0 else None,
            max_rows_per_source=self.max_rows_per_source or None,
            max_bytes=self.disk_budget_mb * 1024 * 1024 or None,
        )

    def excluded(self, source_id: str) -> bool:
        """Whether discovery filters hide ``source_id``."""
        return any(fnmatchcase(source_id, pattern) for pattern in self.discovery_exclude)


def load_settings(path: Path | None = None) -> Settings:
    """Read settings; unknown keys are ignored, bad values fall back to defaults."""
    path = path or default_config_path()
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return Settings()
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        log.warning("ignoring unreadable config %s: %s", path, exc)
        return Settings()
    flat = {
        k: v for section in data.values() if isinstance(section, dict) for k, v in section.items()
    }
    settings = Settings()
    for f in fields(Settings):
        if f.name not in flat:
            continue
        value = _coerce(flat[f.name], getattr(settings, f.name))
        if value is None:
            log.warning("ignoring invalid config value %s = %r", f.name, flat[f.name])
        else:
            settings = replace(settings, **{f.name: value})
    if settings.theme not in THEMES:
        settings = replace(settings, theme="system")
    if settings.inline_explanations not in INLINE_MODES:
        settings = replace(settings, inline_explanations="off")
    return settings


def save_settings(settings: Settings, path: Path | None = None) -> Path:
    """Write settings atomically (temp file + rename), readable only by the owner."""
    path = path or default_config_path()
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    sections = {
        "appearance": ("theme", "inline_explanations"),
        "storage": ("retention_days", "max_rows_per_source"),
        "rules": ("rule_dirs",),
        "discovery": ("discovery_exclude", "discovery_interval_s", "pinned"),
        "notifications": ("notify_on", "muted"),
        "privacy": ("redact_secrets", "redact_patterns", "redact_reversible"),
        "limits": ("memory_budget_mb", "disk_budget_mb", "max_collectors"),
    }
    lines = ["# LogLens settings. Edited by Settings in the app; safe to edit by hand.", ""]
    for section, keys in sections.items():
        lines.append(f"[{section}]")
        lines += [f"{key} = {_toml(getattr(settings, key))}" for key in keys]
        lines.append("")
    tmp = path.with_suffix(".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write("\n".join(lines))
    tmp.replace(path)
    return path


def _coerce(value: Any, default: Any) -> Any:
    if isinstance(default, bool):
        return value if isinstance(value, bool) else None
    if isinstance(default, int):
        return (
            value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else None
        )
    if isinstance(default, str):
        return value if isinstance(value, str) else None
    if isinstance(default, tuple):
        if isinstance(value, list) and all(isinstance(v, str) for v in value):
            return tuple(value)
        return None
    return None  # pragma: no cover - every Settings field is one of the above


def _toml(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, str):
        return _toml_string(value)
    return "[" + ", ".join(_toml_string(v) for v in value) + "]"


def _toml_string(text: str) -> str:
    escaped = text.replace("\\", "\\\\").replace('"', '\\"')
    escaped = "".join(c if c.isprintable() else f"\\u{ord(c):04x}" for c in escaped)
    return f'"{escaped}"'
