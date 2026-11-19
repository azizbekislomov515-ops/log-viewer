"""Desktop notifications: which events deserve one (pure logic) and how to send it.

Conditions are rule tags plus severity, so new rule packs can raise notifications without
GUI code:

* ``critical``: a CRITICAL entry, or a rule that rates the entry critical.
* ``detection``: a rule tagged ``detection`` (malware, leaked secrets, forgery).
* ``restart_loop``: a rule tagged ``restart_loop``, or ``RESTART_LOOP_COUNT`` entries
  tagged ``restart`` from one source within ``RESTART_LOOP_WINDOW``.

Per-source mutes, at most one notification per source and condition per
``PER_KEY_INTERVAL``, and at most ``GLOBAL_PER_MINUTE`` in total; suppressed ones are
counted and mentioned in the next notification.
"""

from __future__ import annotations

import html
import logging
import shutil
import time
from collections import defaultdict, deque
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta

from loglens.core.models import Explanation, LogEntry, Severity

log = logging.getLogger(__name__)

CONDITIONS: Mapping[str, str] = {
    "critical": "A new critical entry",
    "detection": "Malware or another security detection",
    "restart_loop": "A service or container restarting in a loop",
}
RESTART_LOOP_COUNT = 3
RESTART_LOOP_WINDOW = timedelta(minutes=5)
PER_KEY_INTERVAL = 60.0
GLOBAL_PER_MINUTE = 5
MAX_SUMMARY = 120
MAX_BODY = 400

Pair = tuple[LogEntry, Explanation | None]


@dataclass(frozen=True, slots=True)
class Notification:
    """One desktop notification."""

    summary: str
    body: str
    source_id: str
    condition: str
    urgency: str = "normal"  # low | normal | critical (freedesktop)


class NotificationCenter:
    """Decides which (entry, explanation) pairs become notifications."""

    def __init__(
        self,
        conditions: Iterable[str],
        muted: Iterable[str] = (),
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.conditions = set(conditions)
        self.muted = set(muted)
        self._clock = clock
        self._last_sent: dict[tuple[str, str], float] = {}
        self._sent: deque[float] = deque()
        self._suppressed: dict[tuple[str, str], int] = defaultdict(int)
        self._restarts: dict[str, deque[datetime]] = defaultdict(deque)

    def consider(self, pairs: Sequence[Pair], names: Mapping[str, str]) -> list[Notification]:
        """Notifications to show for these pairs (already rate-limited)."""
        out: list[Notification] = []
        for entry, explanation in pairs:
            if entry.source_id in self.muted:
                continue
            for condition in self._conditions_met(entry, explanation):
                note = self._admit(entry, explanation, condition, names)
                if note is not None:
                    out.append(note)
        return out

    def _conditions_met(self, entry: LogEntry, exp: Explanation | None) -> list[str]:
        tags = set(exp.tags) if exp is not None else set()
        met = []
        severity = max(entry.severity, exp.severity_assessment) if exp else entry.severity
        if "critical" in self.conditions and severity >= Severity.CRITICAL:
            met.append("critical")
        if "detection" in self.conditions and "detection" in tags:
            met.append("detection")
        looping = "restart_loop" in tags or ("restart" in tags and self._looping(entry))
        if "restart_loop" in self.conditions and looping:
            met.append("restart_loop")
        return met

    def _looping(self, entry: LogEntry) -> bool:
        times = self._restarts[entry.source_id]
        times.append(entry.timestamp)
        while times and entry.timestamp - times[0] > RESTART_LOOP_WINDOW:
            times.popleft()
        return len(times) >= RESTART_LOOP_COUNT

    def _admit(
        self, entry: LogEntry, exp: Explanation | None, condition: str, names: Mapping[str, str]
    ) -> Notification | None:
        now = self._clock()
        key = (entry.source_id, condition)
        while self._sent and now - self._sent[0] > 60:
            self._sent.popleft()
        recent = now - self._last_sent.get(key, -1e9) < PER_KEY_INTERVAL
        if recent or len(self._sent) >= GLOBAL_PER_MINUTE:
            self._suppressed[key] += 1
            return None
        self._last_sent[key] = now
        self._sent.append(now)
        name = names.get(entry.source_id) or entry.source_id
        if condition == "restart_loop" and (exp is None or "restart_loop" not in exp.tags):
            summary = f"{name} keeps restarting"
            body = (
                f"{name} restarted {len(self._restarts[entry.source_id])} times in the last "
                f"{int(RESTART_LOOP_WINDOW.total_seconds() // 60)} minutes."
            )
        else:
            summary = f"{name}: {exp.title if exp else entry.severity.name.title() + ' entry'}"
            body = exp.plain_text if exp else entry.message.split("\n", 1)[0][:300]
        if more := self._suppressed.pop(key, 0):
            body += f" (+{more} more like this since the last notification)"
        urgency = "critical" if condition in ("critical", "detection") else "normal"
        return Notification(summary, body, entry.source_id, condition, urgency)


class DesktopNotifier:
    """Sends notifications with ``notify-send`` (libnotify, freedesktop), detached so the
    GUI thread never waits. Without it, notifications are logged and reported once."""

    def __init__(self, starter: Callable[[str, list[str]], bool] | None = None) -> None:
        self.program = shutil.which("notify-send")
        self._starter = starter or _start_detached
        self.available = self.program is not None

    def send(self, note: Notification) -> bool:
        """Show ``note``; False if no notification service could be reached."""
        if self.program is None:
            log.info("notification (notify-send not installed): %s", note.summary)
            return False
        args = [
            "--app-name=LogLens",
            f"--urgency={note.urgency}",
            "--icon=dialog-warning" if note.urgency == "critical" else "--icon=dialog-information",
            "--",  # log text can never be read as an option
            _clean(note.summary, MAX_SUMMARY),
            # The body may hold markup (<a>, <img>, <b>) per the freedesktop spec: escape it.
            html.escape(_clean(note.body, MAX_BODY), quote=False),
        ]
        return self._starter(self.program, args)


def _clean(text: str, limit: int) -> str:
    """One readable line: control characters dropped, length capped."""
    text = "".join(c if c.isprintable() else " " for c in text)
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _start_detached(program: str, args: list[str]) -> bool:
    from PySide6.QtCore import QProcess  # noqa: PLC0415

    ok, _pid = QProcess.startDetached(program, args)
    return bool(ok)
