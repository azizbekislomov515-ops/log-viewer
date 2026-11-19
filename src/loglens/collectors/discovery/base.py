"""Discoverer protocol and the injectable command runner used by discoverers."""

from __future__ import annotations

import logging
import os

# subprocess: argv lists built by our code only, never a shell.
import subprocess  # nosec B404
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Protocol

from loglens.core.models import DiscoveryResult

log = logging.getLogger(__name__)

DEFAULT_TIMEOUT = 10.0
EXIT_CANNOT_EXECUTE = 126
EXIT_NOT_FOUND = 127
EXIT_TIMEOUT = 124


class Discoverer(Protocol):
    """Finds log sources of one kind. Must never raise for expected environment problems;
    report them as ``DiscoveryIssue`` in the result instead."""

    name: str

    def discover(self) -> DiscoveryResult:
        """Run one discovery pass."""
        ...


@dataclass(frozen=True, slots=True)
class CommandResult:
    """Outcome of an external command. Missing binary -> 127, not executable -> 126,
    timeout -> 124."""

    returncode: int
    stdout: str
    stderr: str

    @property
    def ok(self) -> bool:
        """True when the command exited with status 0."""
        return self.returncode == 0


class CommandRunner(Protocol):
    """Runs an argv list (never a shell string) and returns its result without raising."""

    def __call__(self, args: Sequence[str], timeout: float = DEFAULT_TIMEOUT) -> CommandResult:
        """Execute ``args`` and return its result."""
        ...


def run_command(args: Sequence[str], timeout: float = DEFAULT_TIMEOUT) -> CommandResult:
    """Default ``CommandRunner``: list args, no shell, captured output, C locale, timeout.

    Missing binaries and timeouts are converted to a ``CommandResult`` (127 / 124)
    instead of raising, so callers have a single code path.
    """
    argv = list(args)
    env = {**os.environ, "LC_ALL": "C", "SYSTEMD_COLORS": "0"}
    try:
        proc = subprocess.run(  # noqa: S603  # nosec B603
            argv, capture_output=True, text=True, timeout=timeout, check=False, env=env
        )
    except FileNotFoundError:
        return CommandResult(EXIT_NOT_FOUND, "", f"command not found: {argv[0]}")
    except subprocess.TimeoutExpired:
        log.warning("command timed out", extra={"argv": argv, "timeout": timeout})
        return CommandResult(EXIT_TIMEOUT, "", f"timed out after {timeout:g}s: {argv[0]}")
    except PermissionError as exc:
        return CommandResult(EXIT_CANNOT_EXECUTE, "", f"cannot execute {argv[0]}: {exc}")
    return CommandResult(proc.returncode, proc.stdout, proc.stderr)
