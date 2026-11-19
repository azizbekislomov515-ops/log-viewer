"""Run the examples every rule carries (``loglens-cli rules test`` and the test suite).

A positive example must be explained by *that* rule (not merely by some rule: this also
catches a rule shadowed by an earlier one) with exactly the expected rendered fields. A
counter-example must not be explained by that rule.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime

from loglens.collectors import source_from_id
from loglens.core.models import Explanation, LogEntry, RawRecord
from loglens.explain.engine import ExplanationEngine
from loglens.explain.rules import Rule
from loglens.parsers import Normalizer

#: Collector time given to example lines: fixed, so year-less timestamps are deterministic.
EXAMPLE_TIME = datetime(2026, 11, 18, 12, 0, tzinfo=UTC)


@dataclass(frozen=True, slots=True)
class ExampleFailure:
    """One failed example, phrased for ``file:line: [rule] ...`` output."""

    rule: Rule
    line: str
    problem: str

    def __str__(self) -> str:
        where = f"{self.rule.path}:{self.rule.line}: [{self.rule.id}]"
        return f"{where} {self.problem}\n    line: {self.line!r}"


@dataclass(frozen=True, slots=True)
class ExampleReport:
    """Counts and failures of one run."""

    rules: int
    examples: int
    failures: tuple[ExampleFailure, ...]


def parse_line(line: str, source_id: str, normalizer: Normalizer | None = None) -> LogEntry:
    """Parse ``line`` as if collected from ``source_id`` (what examples and ``explain`` use)."""
    normalize = normalizer or Normalizer()
    return normalize(source_from_id(source_id), RawRecord(source_id, line, EXAMPLE_TIME))


def run_examples(engine: ExplanationEngine, packs: Iterable[str] | None = None) -> ExampleReport:
    """Check every example of every rule (of ``packs``, if given) against ``engine``."""
    wanted = None if packs is None else set(packs)
    normalizer = Normalizer()
    failures: list[ExampleFailure] = []
    rules = examples = 0
    for rule in engine.rules:
        if wanted is not None and rule.pack not in wanted:
            continue
        rules += 1
        for example in rule.examples:
            examples += 1
            got = engine.explain(parse_line(example.line, example.source_id, normalizer))
            problem = _positive_problem(rule, got, example.expect or {})
            if problem:
                failures.append(ExampleFailure(rule, example.line, problem))
        for example in rule.counter_examples:
            examples += 1
            got = engine.explain(parse_line(example.line, example.source_id, normalizer))
            if got is not None and got.rule_id == rule.id:
                failures.append(ExampleFailure(rule, example.line, "counter-example matched"))
    return ExampleReport(rules, examples, tuple(failures))


def _positive_problem(rule: Rule, got: Explanation | None, expect: Mapping[str, str]) -> str:
    if got is None:
        return "example not explained by any rule"
    if got.rule_id != rule.id:
        return f"example explained by {got.rule_id} instead"
    actual = {
        "title": got.title,
        "text": got.plain_text,
        "cause": got.probable_cause,
        "action": got.suggested_action,
        "severity": got.severity_assessment.name.lower(),
        "category": got.category.value,
    }
    wrong = [
        f"{key}:\n      expected {want!r}\n      got      {actual[key]!r}"
        for key, want in expect.items()
        if actual[key] != want
    ]
    return "\n    ".join(["output differs", *wrong]) if wrong else ""
