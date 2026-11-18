"""Guess a severity from message text when neither the source nor a parser gave one."""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping, Sequence

from loglens.core.models import Severity

#: Keywords per severity. A single word matches a whole word (case-insensitive); an entry
#: with a space or ``-`` is a phrase and matches as a substring. Most severe wins.
DEFAULT_SEVERITY_KEYWORDS: Mapping[Severity, tuple[str, ...]] = {
    Severity.CRITICAL: (
        "panic", "fatal", "emerg", "emergency", "critical", "segfault",
        "out of memory", "oom-kill", "oom killer", "core dumped", "kernel bug",
    ),
    Severity.ERROR: (
        "error", "errors", "err", "fail", "failed", "failure", "fails", "exception",
        "traceback", "denied", "refused", "cannot", "can't", "timeout",
        "unable to", "could not", "timed out",
    ),
    Severity.WARNING: (
        "warn", "warning", "deprecated", "retry", "retrying", "degraded", "invalid",
    ),
    Severity.DEBUG: ("debug", "trace"),
}  # fmt: skip

#: Only the head of a message is scanned (a stack trace's first lines carry the signal).
_SCAN_CHARS = 2048
_WORD = re.compile(r"[a-z']+")


class SeverityInferrer:
    """Keyword/phrase/regex severity guesser; reconfigure via the constructor.

    ``patterns`` are extra ``(severity, regex)`` rules, matched against the lower-cased
    head of the message. Token lookup is ~3x faster than one big regex, which matters
    because this runs for most lines from sources without levels.

    ponytail: keyword heuristic ("0 errors" reads as ERROR); rule packs (Phase 4) refine it.
    """

    def __init__(
        self,
        keywords: Mapping[Severity, Iterable[str]] = DEFAULT_SEVERITY_KEYWORDS,
        patterns: Sequence[tuple[Severity, str]] = (),
    ) -> None:
        rules: dict[Severity, tuple[set[str], list[str], list[re.Pattern[str]]]] = {}
        for severity, entries in keywords.items():
            words, phrases, _ = rules.setdefault(severity, (set(), [], []))
            for entry in (e.lower() for e in entries):
                if _WORD.fullmatch(entry):
                    words.add(entry)
                else:
                    phrases.append(entry)
        for severity, regex in patterns:
            rules.setdefault(severity, (set(), [], []))[2].append(re.compile(regex))
        self._rules = sorted(rules.items(), key=lambda item: -item[0])

    def infer(self, text: str) -> Severity | None:
        """The most severe matching rule's severity, or None if nothing matches."""
        head = text[:_SCAN_CHARS].lower()
        tokens = set(_WORD.findall(head))
        for severity, (words, phrases, regexes) in self._rules:
            if (
                not tokens.isdisjoint(words)
                or any(p in head for p in phrases)
                or any(r.search(head) for r in regexes)
            ):
                return severity
        return None
