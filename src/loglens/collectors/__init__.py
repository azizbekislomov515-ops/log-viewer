"""Collectors: everything that talks to systemd, Docker and the filesystem."""

from __future__ import annotations

from pathlib import PurePosixPath

from loglens.collectors.base import Collector
from loglens.core.models import LogSource, SourceKind

__all__ = ["Collector", "default_collectors", "source_from_id"]


def default_collectors() -> dict[SourceKind, Collector]:
    """One production collector per source kind."""
    from loglens.collectors.docker_logs import DockerCollector  # noqa: PLC0415
    from loglens.collectors.files import FileCollector  # noqa: PLC0415
    from loglens.collectors.journald import JournaldCollector  # noqa: PLC0415
    from loglens.helper.client import HelperFallback  # noqa: PLC0415

    # Journal and files go through loglens-helper when this user cannot read them and
    # the helper is installed; otherwise directly.
    return {
        SourceKind.SYSTEMD: HelperFallback(JournaldCollector()),
        SourceKind.DOCKER_CONTAINER: DockerCollector(),
        SourceKind.FILE: HelperFallback(FileCollector()),
    }


def source_from_id(source_id: str) -> LogSource:
    """Build a LogSource from its id alone (``systemd:x.service``, ``docker:name``,
    ``file:/abs/path``), so any unit/container/file can be tailed without discovery.

    Raises:
        ValueError: for an unknown prefix, an empty name or a relative file path.
    """
    prefix, _, name = source_id.partition(":")
    if not name:
        raise ValueError(f"invalid source id {source_id!r}: expected <kind>:<name>")
    match prefix:
        case "systemd":
            return LogSource(source_id, SourceKind.SYSTEMD, name, "", metadata={"unit": name})
        case "docker":
            return LogSource(
                source_id, SourceKind.DOCKER_CONTAINER, name, "", metadata={"container_name": name}
            )
        case "file" if PurePosixPath(name).is_absolute():
            return LogSource(source_id, SourceKind.FILE, name, "", metadata={"path": name})
        case "file":
            raise ValueError(f"file source needs an absolute path: {source_id!r}")
    raise ValueError(f"unknown source kind {prefix!r} in {source_id!r} (systemd|docker|file)")
