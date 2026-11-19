"""What the current (unprivileged) user may read, and the exact fix when it may not.

LogLens never needs root. Each check returns a ``DiscoveryIssue`` with a copy-pasteable
fix, or None when access is fine. Group membership is passed in so tests can simulate
any user.
"""

from __future__ import annotations

import grp
import os
from collections.abc import Iterable

from loglens.core.models import DiscoveryIssue, Severity

#: Groups whose members may read the whole system journal (distribution dependent).
JOURNAL_GROUPS = frozenset({"systemd-journal", "adm", "wheel"})

DOCKER_ROOT_WARNING = (
    "Warning: membership in the 'docker' group is equivalent to root (anyone in it can "
    "start a privileged container). Safer alternatives: rootless Docker "
    "(dockerd-rootless-setuptool.sh install, then "
    "export DOCKER_HOST=unix:///run/user/$UID/docker.sock), or the read-only "
    "loglens-helper (docs/SECURITY.md)."
)


def current_groups() -> frozenset[str]:
    """Names of the groups this process belongs to."""
    names = set()
    for gid in {*os.getgroups(), os.getegid()}:
        try:
            names.add(grp.getgrgid(gid).gr_name)
        except KeyError:
            continue
    return frozenset(names)


def journal_access_issue(
    groups: Iterable[str] | None = None, *, euid: int | None = None
) -> DiscoveryIssue | None:
    """An issue if this user can only see its own journal, not the system's."""
    euid = os.geteuid() if euid is None else euid
    groups = current_groups() if groups is None else frozenset(groups)
    if euid == 0 or JOURNAL_GROUPS & groups:
        return None
    return DiscoveryIssue(
        "systemd",
        "journal_access_limited",
        "You can see only your own user's journal; system service logs are hidden.",
        Severity.WARNING,
        "Add your user to the 'systemd-journal' group (read-only access to the journal): "
        "sudo usermod -aG systemd-journal $USER, then log out and back in. "
        "Or install the read-only loglens-helper (docs/SECURITY.md).",
    )
