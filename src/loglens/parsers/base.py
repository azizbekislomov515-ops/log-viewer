"""Parser protocol, source matching and the registry that picks parsers per source.

A parser turns one ``RawRecord`` into ``ParsedFields``. Parsers never raise on bad input:
anything they do not recognize comes back as ``ParsedFields(parsed=False)`` and the
normalizer keeps the raw text untouched. The registry still wraps every call, so a parser
bug degrades to "unparsed", never to a crashed pipeline.
"""

from __future__ import annotations

import logging
import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime
from fnmatch import fnmatchcase
from typing import Any, Protocol

from loglens.core.models import LogSource, RawRecord, Severity

log = logging.getLogger(__name__)


@dataclass(slots=True)
class ParsedFields:
    """What a parser extracted. ``None`` means "not provided by this line".

    ``message`` is the human part of the line (header stripped); ``None`` keeps the raw
    text as the message. Field names are lower_snake_case.
    """

    parsed: bool
    message: str | None = None
    timestamp: datetime | None = None
    severity: Severity | None = None
    fields: dict[str, Any] = field(default_factory=dict)


def unparsed() -> ParsedFields:
    """The "not mine" result."""
    return ParsedFields(parsed=False)


class Parser(Protocol):
    """Recognizes one log format. ``name`` is stored in ``fields["parser"]``."""

    name: str

    def matches(self, source: LogSource) -> bool:
        """Whether this parser should be tried for ``source`` at all."""
        ...

    def parse(self, record: RawRecord) -> ParsedFields:
        """Parse one record. Must not raise; return ``unparsed()`` when not recognized."""
        ...


@dataclass(frozen=True, slots=True)
class SourceMatch:
    """Glob patterns (``fnmatch``, case-sensitive) on a source's identity.

    ``units`` match systemd unit names, ``paths`` file paths, ``images`` Docker image
    names, ``services`` the Compose service name *or* the container name (``tail
    docker:x`` knows only the name). An empty ``SourceMatch`` matches every source.
    """

    units: tuple[str, ...] = ()
    paths: tuple[str, ...] = ()
    images: tuple[str, ...] = ()
    services: tuple[str, ...] = ()

    def __call__(self, source: LogSource) -> bool:
        """True if any pattern matches the corresponding metadata of ``source``."""
        if not (self.units or self.paths or self.images or self.services):
            return True
        meta = source.metadata
        candidates = (
            (self.units, (meta.get("unit"),)),
            (self.paths, (meta.get("path"),)),
            (self.images, (meta.get("image"),)),
            (self.services, (meta.get("compose_service"), meta.get("container_name"))),
        )
        return any(
            isinstance(value, str) and value and fnmatchcase(value, pattern)
            for patterns, values in candidates
            for value in values
            for pattern in patterns
        )


class ParserRegistry:
    """Ordered set of parsers; higher ``priority`` is tried first.

    Service parsers register with a high priority and narrow ``matches``; generic parsers
    with low priorities and match everything, so they are the fallback chain.
    """

    def __init__(self, parsers: Iterable[tuple[Parser, int]] = ()) -> None:
        self._parsers: list[tuple[int, int, Parser]] = []
        self._cache: dict[str, tuple[Parser, ...]] = {}
        for parser, priority in parsers:
            self.register(parser, priority)

    def register(self, parser: Parser, priority: int) -> None:
        """Add a parser. Equal priorities keep registration order."""
        self._parsers.append((-priority, len(self._parsers), parser))
        self._parsers.sort(key=lambda t: (t[0], t[1]))
        self._cache.clear()

    def for_source(self, source: LogSource) -> tuple[Parser, ...]:
        """Parsers to try for ``source``, in order (cached per source id)."""
        chain = self._cache.get(source.id)
        if chain is None:
            chain = tuple(p for _, _, p in self._parsers if _safe_matches(p, source))
            self._cache[source.id] = chain
        return chain

    def parse(self, source: LogSource, record: RawRecord) -> tuple[str | None, ParsedFields]:
        """First successful parse in priority order: ``(parser name, result)``.

        Returns ``(None, unparsed())`` when nothing recognizes the record.
        """
        for parser in self.for_source(source):
            try:
                result = parser.parse(record)
            except Exception:  # a parser bug must not take the pipeline down
                log.exception("parser raised", extra={"parser": parser.name})
                continue
            if result.parsed:
                return parser.name, result
        return None, unparsed()


def _safe_matches(parser: Parser, source: LogSource) -> bool:
    try:
        return parser.matches(source)
    except Exception:
        log.exception("parser.matches raised", extra={"parser": parser.name})
        return False


@dataclass(frozen=True, slots=True)
class EventPattern:
    """A message shape inside a service's log: regex -> ``event`` name (+ severity).

    Named groups become fields; ``None`` groups are dropped.
    """

    event: str
    regex: re.Pattern[str]
    severity: Severity | None = None


def events(*specs: tuple[str, str, Severity | None]) -> tuple[EventPattern, ...]:
    """Compile ``(event, regex, severity)`` triples."""
    return tuple(EventPattern(e, re.compile(rx), sev) for e, rx, sev in specs)


def match_event(
    text: str, patterns: Iterable[EventPattern]
) -> tuple[EventPattern, dict[str, Any]] | None:
    """First pattern whose regex matches at the start of ``text``, with its groups."""
    for pattern in patterns:
        if m := pattern.regex.match(text):
            return pattern, {k: v for k, v in m.groupdict().items() if v is not None}
    return None
