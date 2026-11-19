"""ExplanationEngine: the first matching rule explains an entry; no match means None.

Rules are tried in pack-file order, then file order, so put specific rules before
general ones. The candidate rules are computed once per (source, parser, program) and
cached, so a line only walks rules that can apply to it.
"""

from __future__ import annotations

import logging
from collections.abc import Iterable
from pathlib import Path

from loglens.collectors import source_from_id
from loglens.core.models import Explanation, LogEntry, LogSource, SourceKind
from loglens.explain.rules import LoadIssue, Pack, Rule, RuleSet, load_rules

log = logging.getLogger(__name__)


class ExplanationEngine:
    """Deterministic, rule-based explainer. Thread-safe for concurrent ``explain`` calls."""

    def __init__(self, rules: RuleSet) -> None:
        self._ruleset = rules
        self._rules = rules.rules
        #: source id -> (the source they were computed for, {(parser, program): rules})
        self._candidates: dict[
            str, tuple[LogSource, dict[tuple[str | None, str | None], tuple[Rule, ...]]]
        ] = {}
        self._sources: dict[str, LogSource] = {}
        self._broken: set[str] = set()

    @classmethod
    def from_directory(
        cls, directory: Path | None = None, *, packs: Iterable[str] | None = None
    ) -> ExplanationEngine:
        """Load packs from ``directory`` (default: ``rules/``). Problems are logged and kept
        in ``issues``; the engine works with whatever loaded."""
        ruleset = load_rules(directory, packs=packs)
        for issue in ruleset.issues:
            log.warning("rule pack problem: %s", issue)
        return cls(ruleset)

    @property
    def packs(self) -> tuple[Pack, ...]:
        """Loaded packs."""
        return self._ruleset.packs

    @property
    def issues(self) -> tuple[LoadIssue, ...]:
        """Everything skipped while loading (file, line, reason)."""
        return self._ruleset.issues

    @property
    def rules(self) -> tuple[Rule, ...]:
        """All active rules in evaluation order."""
        return self._rules

    def explain(self, entry: LogEntry, source: LogSource | None = None) -> Explanation | None:
        """Explain ``entry`` with the first matching rule, or None if no rule matches.

        Pass the discovered ``source`` when you have it: its metadata (image, Compose
        service) selects rules more precisely than the bare source id.
        """
        if source is None:
            source = self._source(entry.source_id)
        fields = entry.fields
        parser = fields.get("parser")
        program = fields.get("program") or fields.get("SYSLOG_IDENTIFIER")
        key = (
            parser if isinstance(parser, str) else None,
            program if isinstance(program, str) else None,
        )
        cached = self._candidates.get(source.id)
        if cached is None or not (cached[0] is source or cached[0].metadata == source.metadata):
            # first time, or the source was re-discovered with different metadata
            cached = (source, {})
            self._candidates[source.id] = cached
        candidates = cached[1].get(key)
        if candidates is None:
            candidates = cached[1][key] = self._select(source, *key)
        for rule in candidates:
            try:
                explanation = rule.apply(entry, source.display_name)
            except Exception:  # a template bug must not cost the line its display
                if rule.id not in self._broken:
                    self._broken.add(rule.id)
                    log.exception("rule failed to render", extra={"rule": rule.id})
                continue
            if explanation is not None:
                return explanation
        return None

    def _select(
        self, source: LogSource, parser: str | None, program: str | None
    ) -> tuple[Rule, ...]:
        return tuple(
            rule
            for rule in self._rules
            if rule.selector.matches_source(source) or rule.selector.matches(parser, program)
        )

    def _source(self, source_id: str) -> LogSource:
        source = self._sources.get(source_id)
        if source is None:
            try:
                source = source_from_id(source_id)
            except ValueError:  # unknown id shape: only parser/program selectors apply
                source = LogSource(source_id, SourceKind.FILE, source_id, "")
            self._sources[source_id] = source
        return source
