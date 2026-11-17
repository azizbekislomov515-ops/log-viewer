"""``loglens-cli``: command-line access to discovery (and later, other core features)."""

from __future__ import annotations

import argparse
import dataclasses
import json
import logging
import sys
from collections.abc import Sequence
from datetime import datetime
from enum import Enum, StrEnum
from typing import Any, TextIO

from loglens.collectors.discovery import Discoverer, default_discoverers
from loglens.core.models import LogSource, SourceKind
from loglens.core.registry import SourceRegistry

_MAX_NAME_WIDTH = 40
# C0 controls, DEL and C1 controls -> "?" so log-derived text can't drive the terminal.
_CONTROL_CHARS = dict.fromkeys([*range(0x20), *range(0x7F, 0xA0)], "?")


def main(argv: Sequence[str] | None = None) -> int:
    """Entry point for the ``loglens-cli`` script."""
    parser = argparse.ArgumentParser(prog="loglens-cli", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    sources = sub.add_parser("sources", help="list discovered log sources grouped by service")
    sources.add_argument("--json", action="store_true", help="print JSON instead of a table")
    parser.add_argument("-v", "--verbose", action="store_true", help="log diagnostics to stderr")
    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.INFO if args.verbose else logging.WARNING)
    return cmd_sources(default_discoverers(), as_json=args.json, out=sys.stdout)


def cmd_sources(discoverers: Sequence[Discoverer], *, as_json: bool, out: TextIO) -> int:
    """Run discovery once and print the result."""
    registry = SourceRegistry(discoverers)
    registry.refresh()
    if as_json:
        payload = {"groups": registry.groups, "issues": registry.issues}
        json.dump(payload, out, default=_to_json, indent=2)
        out.write("\n")
    else:
        out.write(render_table(registry))
    return 0


def render_table(registry: SourceRegistry) -> str:
    """Human-readable listing: one block per group, then issues with hints."""
    names = [s.display_name for g in registry.groups for s in g.sources]
    width = min(max(map(len, names), default=10), _MAX_NAME_WIDTH)
    lines: list[str] = []
    for group in registry.groups:
        n = len(group.sources)
        lines.append(f"{group.name}  [{group.kind.value}, {n} source{'s' * (n != 1)}]")
        for s in group.sources:
            name = s.display_name[:width].ljust(width)
            lines.append(f"  {name}  {s.status.value:<8}  {_detail(s)}".rstrip())
        lines.append("")
    if not registry.groups:
        lines += ["No log sources found.", ""]
    if registry.issues:
        lines.append("Issues:")
        for issue in registry.issues:
            lines.append(f"  [{issue.severity.name.lower()}] {issue.discoverer}: {issue.message}")
            if issue.hint:
                lines.append(f"      -> {issue.hint}")
    return "\n".join(_safe(line) for line in lines).rstrip() + "\n"


def _safe(text: str) -> str:
    """Neutralize terminal escape sequences in untrusted text (labels, stderr, descriptions)."""
    return text.translate(_CONTROL_CHARS)


def _detail(source: LogSource) -> str:
    meta = source.metadata
    match source.kind:
        case SourceKind.SYSTEMD:
            return str(meta.get("description", ""))
        case SourceKind.DOCKER_CONTAINER:
            return f"{meta.get('image', '')}  ({meta.get('state', '')})"
        case SourceKind.FILE:
            return str(meta.get("path", "")) + ("" if meta.get("readable") else "  [not readable]")


def _to_json(obj: Any) -> Any:
    if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
        return {f.name: _plain(getattr(obj, f.name)) for f in dataclasses.fields(obj)}
    if isinstance(obj, datetime):
        return obj.isoformat()
    if hasattr(obj, "items"):  # MappingProxyType
        return dict(obj)
    raise TypeError(f"not JSON serializable: {type(obj).__name__}")


def _plain(value: Any) -> Any:
    if isinstance(value, StrEnum):
        return value.value
    if isinstance(value, Enum):
        return value.name.lower()
    return value


if __name__ == "__main__":
    sys.exit(main())
