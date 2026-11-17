"""Discover well-known log files from a YAML catalog (``rules/file_sources.yaml``)."""

from __future__ import annotations

import grp
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

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

# ponytail: repo-relative default; ship rules/ as package data when packaging (Phase 9).
DEFAULT_CATALOG = Path(__file__).resolve().parents[4] / "rules" / "file_sources.yaml"


@dataclass(frozen=True, slots=True)
class _CatalogFile:
    name: str
    paths: tuple[Path, ...]


@dataclass(frozen=True, slots=True)
class _CatalogGroup:
    id: str
    name: str
    files: tuple[_CatalogFile, ...]


class CatalogError(ValueError):
    """The file-source catalog is missing or malformed."""


class FileDiscoverer:
    """Checks each catalog entry on disk and reports whether it exists and is readable.

    Missing files are skipped unless ``include_missing`` is set. Existing but unreadable
    files are still listed (so the user sees them) and produce an actionable issue.
    """

    name = "files"

    def __init__(self, catalog: Path = DEFAULT_CATALOG, *, include_missing: bool = False) -> None:
        self._catalog = catalog
        self._include_missing = include_missing

    def discover(self) -> DiscoveryResult:
        """Probe every catalog path; never raises for a bad catalog or unreadable files."""
        try:
            catalog = _load_catalog(self._catalog)
        except CatalogError as exc:
            return DiscoveryResult(
                issues=(
                    DiscoveryIssue(self.name, "file_catalog_invalid", str(exc), Severity.ERROR),
                )
            )

        groups: list[ServiceGroup] = []
        issues: list[DiscoveryIssue] = []
        for cat_group in catalog:
            group_id = f"files:{cat_group.id}"
            sources: list[LogSource] = []
            for entry in cat_group.files:
                path = next((p for p in entry.paths if p.is_file()), None)
                if path is None and not self._include_missing:
                    continue
                path = path or entry.paths[0]
                exists = path.is_file()
                readable = exists and os.access(path, os.R_OK)
                sources.append(
                    LogSource(
                        id=f"file:{path}",
                        kind=SourceKind.FILE,
                        display_name=entry.name,
                        group_id=group_id,
                        status=SourceStatus.UNKNOWN,
                        metadata={"path": str(path), "exists": exists, "readable": readable},
                    )
                )
                if exists and not readable:
                    issues.append(_unreadable_issue(path))
            if sources:
                groups.append(
                    ServiceGroup(group_id, cat_group.name, GroupKind.FILES, tuple(sources))
                )
        return DiscoveryResult(groups=tuple(groups), issues=tuple(issues))


def _unreadable_issue(path: Path) -> DiscoveryIssue:
    try:
        group = grp.getgrgid(path.stat().st_gid).gr_name
    except (OSError, KeyError):
        group = None
    if group and group != "root":
        hint = (
            f"Add your user to the '{group}' group (sudo usermod -aG {group} $USER), "
            "then log out and back in."
        )
    else:
        hint = f"Grant read access without running as root, e.g.: sudo setfacl -m u:$USER:r {path}"
    return DiscoveryIssue(
        FileDiscoverer.name,
        "file_not_readable",
        f"{path} exists but is not readable by your user.",
        Severity.WARNING,
        hint,
    )


def _load_catalog(path: Path) -> list[_CatalogGroup]:
    """Load and validate the YAML catalog.

    Raises:
        CatalogError: if the file is missing, not valid YAML, or has the wrong shape.
    """
    try:
        data: Any = yaml.safe_load(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise CatalogError(f"cannot read file catalog {path}: {exc.strerror}") from exc
    except yaml.YAMLError as exc:
        raise CatalogError(f"file catalog {path} is not valid YAML: {exc}") from exc

    if not isinstance(data, dict) or not isinstance(data.get("groups"), list):
        raise CatalogError(f"file catalog {path}: top level must be a mapping with a 'groups' list")
    groups = []
    for i, g in enumerate(data["groups"]):
        where = f"file catalog {path}: groups[{i}]"
        if not isinstance(g, dict) or not _is_str(g.get("id")) or not _is_str(g.get("name")):
            raise CatalogError(f"{where} needs string 'id' and 'name'")
        files = g.get("files")
        if not isinstance(files, list) or not files:
            raise CatalogError(f"{where} needs a non-empty 'files' list")
        entries = []
        for j, f in enumerate(files):
            paths = f.get("paths") if isinstance(f, dict) else None
            if (
                not isinstance(f, dict)
                or not _is_str(f.get("name"))
                or not isinstance(paths, list)
                or not paths
                or not all(_is_str(p) and p.startswith("/") for p in paths)
            ):
                raise CatalogError(
                    f"{where}.files[{j}] needs a 'name' and a non-empty list of absolute 'paths'"
                )
            entries.append(_CatalogFile(f["name"], tuple(Path(p) for p in paths)))
        groups.append(_CatalogGroup(g["id"], g["name"], tuple(entries)))
    return groups


def _is_str(value: object) -> bool:
    return isinstance(value, str) and bool(value.strip())
