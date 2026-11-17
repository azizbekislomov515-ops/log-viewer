"""Log source discovery: systemd units, Docker containers, well-known log files."""

from loglens.collectors.discovery.base import Discoverer
from loglens.collectors.discovery.containers import DockerDiscoverer
from loglens.collectors.discovery.files import FileDiscoverer
from loglens.collectors.discovery.systemd import SystemdDiscoverer

__all__ = [
    "Discoverer",
    "DockerDiscoverer",
    "FileDiscoverer",
    "SystemdDiscoverer",
    "default_discoverers",
]


def default_discoverers() -> list[Discoverer]:
    """The discoverers the app runs out of the box, with production defaults."""
    return [SystemdDiscoverer(), DockerDiscoverer(), FileDiscoverer()]
