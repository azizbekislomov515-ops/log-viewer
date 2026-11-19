"""Rule editor logic: draft a rule from a log line, preview it live, save it to the user pack.

The preview uses the real machinery (JSON Schema, compile, sandboxed templates), so what
the editor shows is exactly what the engine will do. Saving rewrites
``~/.config/loglens/rules/user.yaml`` only after the whole pack, with the rule's own
example and counter-example, passes the same checks as ``loglens-cli rules test``.
"""

from __future__ import annotations

import os
import re
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import jsonschema
import regex
import yaml

from loglens.config import config_dir
from loglens.core.models import Category, Explanation, LogEntry, LogSource, Severity, SourceKind
from loglens.explain import schema
from loglens.explain.rules import (
    MAX_MATCH_CHARS,
    RULE_TIMEOUT_S,
    Selector,
    _compile,
    _RuleError,
    _schema_message,
    load_rules,
    make_environment,
)

USER_PACK = "user"
_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_HEX = re.compile(r"\b(?=[0-9a-f]*[a-f])[0-9a-f]{8,}\b")  # an id, not a plain number
_NUMBER = re.compile(r"\d+")


def user_rules_dir() -> Path:
    """``~/.config/loglens/rules``: rules the user writes (loaded after the built-in ones)."""
    return config_dir() / "rules"


class EditorError(ValueError):
    """The draft cannot be saved; ``problems`` say why, one per line."""

    def __init__(self, problems: list[str]) -> None:
        super().__init__("; ".join(problems))
        self.problems = problems


@dataclass
class RuleDraft:
    """What the editor's form holds."""

    rule_id: str
    title: str
    template: str
    regex: str
    example_line: str
    example_source: str
    counter_example: str = ""
    match_field: str = "message"
    category: str = "info"
    severity: str = ""
    cause: str = ""
    action: str = ""
    applies_to: dict[str, list[str]] = field(default_factory=dict)

    def to_rule(self, expected_text: str) -> dict[str, Any]:
        """The rule as it is stored in the pack YAML."""
        rule: dict[str, Any] = {"id": self.rule_id, "title": self.title}
        if self.applies_to:
            rule["applies_to"] = self.applies_to
        match: dict[str, Any] = {"regex": self.regex}
        if self.match_field != "message":
            match["field"] = self.match_field
        rule["match"] = match
        rule["template"] = self.template
        for key, value in (("cause", self.cause), ("action", self.action)):
            if value.strip():
                rule[key] = value
        rule["category"] = self.category
        if self.severity:
            rule["severity_override"] = self.severity
        rule["examples"] = [
            {
                "line": self.example_line,
                "source": self.example_source,
                "expect": {"text": expected_text},
            }
        ]
        if self.counter_example.strip():
            rule["counter_examples"] = [
                {"line": self.counter_example, "source": self.example_source}
            ]
        return rule


@dataclass(frozen=True, slots=True)
class Preview:
    """Live result for the editor: problems, regex groups, the rendered explanation."""

    problems: tuple[str, ...]
    groups: dict[str, str]
    explanation: Explanation | None

    @property
    def ok(self) -> bool:
        """True when the draft can be saved."""
        return not self.problems and self.explanation is not None


def suggest_regex(message: str) -> str:
    """A starting regex for ``message``: literal text, with IPv4 addresses captured as
    ``ip`` and numbers / hex ids generalized (so the rule matches the next such line)."""
    first_line = message.split("\n", 1)[0][:300]
    out, pos, ips = [], 0, 0
    tokens = sorted(
        [(m.start(), m.end(), "ip") for m in _IPV4.finditer(first_line)]
        + [(m.start(), m.end(), "hex") for m in _HEX.finditer(first_line)]
        + [(m.start(), m.end(), "num") for m in _NUMBER.finditer(first_line)],
        key=lambda t: (t[0], -t[1]),  # longest token first: an IP beats its first number
    )
    for start, end, kind in tokens:
        if start < pos:
            continue
        out.append(re.escape(first_line[pos:start]))
        if kind == "ip":
            ips += 1
            name = "ip" if ips == 1 else f"ip{ips}"
            out.append(rf"(?P<{name}>\d{{1,3}}(?:\.\d{{1,3}}){{3}})")
        elif kind == "hex":
            out.append("[0-9a-f]+")
        else:
            out.append(r"\d+")
        pos = end
    out.append(re.escape(first_line[pos:]))
    return "".join(out).replace("\\ ", " ")


def selector_for(source: LogSource) -> dict[str, list[str]]:
    """A rule-level ``applies_to`` that scopes a new rule to the line's own service."""
    meta = source.metadata
    if source.kind is SourceKind.SYSTEMD and meta.get("unit"):
        return {"units": [str(meta["unit"])]}
    if source.kind is SourceKind.DOCKER_CONTAINER:
        # The container name works for discovered sources and ones rebuilt from their id
        # (rules test); the Compose service name also survives a container re-creation.
        names = [str(n) for n in (meta.get("container_name"), meta.get("compose_service")) if n]
        return {"services": list(dict.fromkeys(names))} if names else {}
    if source.kind is SourceKind.FILE and meta.get("path"):
        return {"paths": [str(meta["path"])]}
    return {}


def suggest(entry: LogEntry, source: LogSource, counter_example: str = "") -> RuleDraft:
    """A draft for an unexplained line, ready to edit."""
    words = re.findall(r"[a-z]+", entry.message.lower())[:4] or ["rule"]
    has_ip = bool(_IPV4.search(entry.message.split("\n", 1)[0]))
    template = (
        "Describe what happened, e.g. which client ({{ ip }}) did what."
        if has_ip
        else "Describe in one or two plain sentences what this line means."
    )
    return RuleDraft(
        rule_id=f"{USER_PACK}.{'_'.join(words)}",
        title=entry.message.split("\n", 1)[0][:60],
        template=template,
        regex=suggest_regex(entry.message),
        example_line=entry.raw,
        example_source=source.id,
        counter_example=counter_example,
        severity=entry.severity.name.lower() if entry.severity >= Severity.WARNING else "",
        applies_to=selector_for(source),
    )


def preview(
    draft: RuleDraft, entry: LogEntry, source: LogSource, counter: LogEntry | None = None
) -> Preview:
    """Validate, compile and run the draft on ``entry`` (and ``counter``)."""
    problems: list[str] = []
    groups: dict[str, str] = {}
    try:  # typed by the user: the regex module, so a catastrophic pattern times out
        pattern = regex.compile(draft.regex)
    except regex.error as exc:
        return Preview((f"regex: {exc}",), {}, None)
    target = entry.raw if draft.match_field == "raw" else entry.message
    if draft.match_field not in ("message", "raw"):
        value = entry.fields.get(draft.match_field)
        target = "" if value is None else str(value)
    try:
        found = pattern.search(target, 0, MAX_MATCH_CHARS, timeout=RULE_TIMEOUT_S)
    except TimeoutError:
        return Preview(("regex: too slow on this line (catastrophic backtracking)",), {}, None)
    if found is None:
        problems.append("the regex does not match this line")
    else:
        groups = {k: v for k, v in found.groupdict().items() if v is not None}
    raw = draft.to_rule(expected_text="(preview)")
    if not draft.counter_example.strip():
        problems.append("add a counter-example: a similar line this rule must NOT explain")
        raw["counter_examples"] = ["(placeholder)"]
    if not draft.rule_id.startswith(f"{USER_PACK}."):
        problems.append(f"the rule id must start with '{USER_PACK}.'")
    error = jsonschema.exceptions.best_match(
        jsonschema.Draft202012Validator(schema.RULE).iter_errors(raw)
    )
    if error is not None:
        problems.append(_schema_message(error))
        return Preview(tuple(problems), groups, None)
    try:
        rule = _compile(
            raw,
            pack=USER_PACK,
            path=Path("<editor>"),
            line=0,
            pack_selector=Selector(),
            default_source=draft.example_source,
            env=make_environment(),
        )
    except _RuleError as exc:
        return Preview((*problems, str(exc)), groups, None)
    try:
        explanation = rule.apply(entry, source.display_name)
        if counter is not None and rule.apply(counter, source.display_name) is not None:
            problems.append("the counter-example matches too: make the regex more specific")
    except Exception as exc:  # template errors at render time (e.g. a filter on None)
        return Preview((*problems, f"template: {exc}"), groups, None)
    if found is not None and explanation is None:
        problems.append("a value the template needs (extract) is missing in this line")
    return Preview(tuple(problems), groups, explanation)


def save(draft: RuleDraft, explanation: Explanation, directory: Path | None = None) -> Path:
    """Add or replace the rule in the user pack, after checking the whole pack.

    Raises:
        EditorError: with the problems if the pack would not load or its examples fail.
    """
    from loglens.explain.engine import ExplanationEngine  # noqa: PLC0415
    from loglens.explain.examples import run_examples  # noqa: PLC0415

    directory = directory or user_rules_dir()
    path = directory / f"{USER_PACK}.yaml"
    data: dict[str, Any] = {
        "pack": USER_PACK,
        "version": 1,
        "description": "Rules written in the LogLens rule editor.",
        "example_source": draft.example_source,
        "rules": [],
    }
    if path.exists():
        loaded = yaml.safe_load(path.read_text(encoding="utf-8"))
        if isinstance(loaded, dict) and isinstance(loaded.get("rules"), list):
            data = loaded
    rule = draft.to_rule(explanation.plain_text)
    rules = [r for r in data["rules"] if not (isinstance(r, dict) and r.get("id") == draft.rule_id)]
    data["rules"] = [*rules, rule]
    text = yaml.safe_dump(data, sort_keys=False, allow_unicode=True, width=100)
    with tempfile.TemporaryDirectory() as tmp:
        check = Path(tmp) / path.name
        check.write_text(text, encoding="utf-8")
        ruleset = load_rules([Path(tmp)])
        problems = [f"line {i.line}: {i.message}" for i in ruleset.issues]
        if not problems:
            report = run_examples(ExplanationEngine(ruleset), [USER_PACK])
            problems = [f.problem.split("\n")[0] + f" ({f.rule.id})" for f in report.failures]
        if problems:
            raise EditorError(problems)
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    tmp_path = path.with_suffix(".tmp")
    fd = os.open(tmp_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write("# Rules written in the LogLens rule editor. Safe to edit by hand.\n")
        handle.write(text)
    tmp_path.replace(path)
    return path


CATEGORIES = tuple(c.value for c in Category)
SEVERITIES = ("", *(s.name.lower() for s in Severity))
