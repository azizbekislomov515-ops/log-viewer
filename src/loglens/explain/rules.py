"""Rule packs: load ``rules/*.yaml``, validate, compile, and match one entry against a rule.

Loading never raises for bad content. Every problem becomes a ``LoadIssue`` with file and
line; a bad rule is skipped, a bad pack header skips the pack, the rest still loads.

Matching a rule against an entry, in order (cheapest first):

1. ``match.fields``: every listed field must exist and equal (as text) one of the values.
2. ``match.regex``: ``re.search`` on the message (or on field ``match.field``; ``raw`` is
   the line as collected, before any parser stripped a prefix), first
   ``MAX_MATCH_CHARS`` characters only. Named groups become template variables.
3. ``extract`` / ``optional``: field (or group) names the templates use. A missing
   ``extract`` value means the rule does not fire (never "None" in text); a missing
   ``optional`` value is None in the template.

Templates run in a Jinja2 sandbox with ``StrictUndefined``; rendered text has its
whitespace collapsed so YAML block strings and ``{% if %}`` read cleanly. ``action``
templates suggest commands an admin may copy-paste, so every value printed there must go
through ``| shquote`` (enforced at load time): a file named ``x; rm -rf ~`` stays one word.
"""

from __future__ import annotations

import logging
import re
import shlex
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import jsonschema
import yaml
from jinja2 import StrictUndefined, Template, TemplateSyntaxError, meta, nodes
from jinja2.sandbox import SandboxedEnvironment

from loglens.core.models import Category, Explanation, LogEntry, LogSource, Severity
from loglens.explain import schema
from loglens.parsers.base import SourceMatch

log = logging.getLogger(__name__)

# ponytail: repo-relative default; ship rules/ as package data when packaging (Phase 9).
DEFAULT_RULES_DIR = Path(__file__).resolve().parents[3] / "rules"
#: Files in the rules directory that are not rule packs.
NOT_PACKS = frozenset({"file_sources.yaml"})
#: Regexes only look at this much of a message: bounds the cost of a crafted long line.
MAX_MATCH_CHARS = 4096
#: Longest value quoted into an explanation.
MAX_VALUE_CHARS = 200
#: Template variables every rule may use without listing them in ``extract``.
BUILTINS = frozenset({"source", "message"})


@dataclass(frozen=True, slots=True)
class LoadIssue:
    """A problem found while loading a pack, phrased for ``file:line: message`` output."""

    path: Path
    line: int
    message: str
    rule_id: str | None = None

    def __str__(self) -> str:
        rule = f" [{self.rule_id}]" if self.rule_id else ""
        return f"{self.path}:{self.line}:{rule} {self.message}"


@dataclass(frozen=True, slots=True)
class Example:
    """A sample line for ``rules test``; ``expect`` is None for counter-examples."""

    line: str
    source_id: str
    expect: Mapping[str, str] | None = None


@dataclass(frozen=True, slots=True)
class Selector:
    """``applies_to``: source globs (see ``SourceMatch``), parser names, program names.

    Criteria are ORed. An empty selector selects everything.
    """

    source: SourceMatch | None = None
    parsers: frozenset[str] = frozenset()
    programs: frozenset[str] = frozenset()

    @property
    def everything(self) -> bool:
        """True when there are no criteria at all."""
        return self.source is None and not self.parsers and not self.programs

    def matches_source(self, source: LogSource) -> bool:
        """Whether the source criteria alone select ``source``."""
        return self.everything or (self.source is not None and self.source(source))

    def matches(self, parser: str | None, program: str | None) -> bool:
        """Whether an entry's parser name or program (syslog tag / SYSLOG_IDENTIFIER) is
        selected."""
        return parser in self.parsers or program in self.programs


@dataclass(frozen=True, slots=True, eq=False)
class Rule:
    """One compiled rule. ``apply`` returns an Explanation or None; it never raises for
    entry content, only for template bugs (the engine catches those)."""

    id: str
    pack: str
    path: Path
    line: int
    selector: Selector
    conditions: tuple[tuple[str, frozenset[str]], ...]
    regex: re.Pattern[str] | None
    on: str
    extract: tuple[tuple[str, bool], ...]
    title: Template
    text: Template
    cause: Template | None
    action: Template | None
    category: Category
    severity: Severity | None
    confidence: float
    references: tuple[str, ...]
    tags: tuple[str, ...]
    examples: tuple[Example, ...] = ()
    counter_examples: tuple[Example, ...] = ()

    def apply(self, entry: LogEntry, source_name: str) -> Explanation | None:
        """Explain ``entry`` if this rule matches it (selector already checked)."""
        fields = entry.fields
        for name, allowed in self.conditions:
            value = fields.get(name)
            if value is None or _as_text(value) not in allowed:
                return None
        groups: dict[str, Any] = {}
        if self.regex is not None:
            target = self._target(entry)
            if target is None or (m := self.regex.search(target, 0, MAX_MATCH_CHARS)) is None:
                return None
            groups = m.groupdict()
        context: dict[str, Any] = {"source": source_name, "message": _clip(entry.message)}
        context.update((k, _clip(v)) for k, v in groups.items())
        for name, required in self.extract:
            value = groups.get(name)
            if value is None:
                value = fields.get(name)
            if value is None or value == "":
                if required:
                    return None
                value = None
            context[name] = _clip(value)
        text = _render(self.text, context)
        if not text:
            return None
        return Explanation(
            title=_render(self.title, context),
            plain_text=text,
            severity_assessment=entry.severity if self.severity is None else self.severity,
            category=self.category,
            rule_id=self.id,
            confidence=self.confidence,
            probable_cause=_render(self.cause, context) or None,
            suggested_action=_render(self.action, context) or None,
            references=self.references,
            tags=self.tags,
        )

    def _target(self, entry: LogEntry) -> str | None:
        """The text ``match.regex`` runs on: message, raw line, or a field (None if absent)."""
        if self.on == "message":
            return entry.message
        if self.on == "raw":
            return entry.raw
        value = entry.fields.get(self.on)
        return None if value is None else _as_text(value)


@dataclass(frozen=True, slots=True)
class Pack:
    """A loaded rule pack (only its valid rules)."""

    name: str
    path: Path
    example_source: str
    description: str = ""
    rules: tuple[Rule, ...] = ()


@dataclass(frozen=True, slots=True)
class RuleSet:
    """Everything ``load_rules`` found: valid packs plus every problem it skipped."""

    packs: tuple[Pack, ...] = ()
    issues: tuple[LoadIssue, ...] = ()

    @property
    def rules(self) -> tuple[Rule, ...]:
        """All rules in evaluation order (packs by file name, rules in file order)."""
        return tuple(r for p in self.packs for r in p.rules)


def load_rules(directory: Path | None = None, *, packs: Iterable[str] | None = None) -> RuleSet:
    """Load every ``*.yaml`` pack in ``directory`` (default: the repo's ``rules/``).

    ``packs`` limits loading to those pack names. Duplicate rule ids across packs: the
    first one wins, later ones are reported and skipped.
    """
    directory = directory or DEFAULT_RULES_DIR
    wanted = None if packs is None else set(packs)
    env = SandboxedEnvironment(undefined=StrictUndefined, autoescape=False)
    env.filters["shquote"] = _shquote
    loaded: list[Pack] = []
    issues: list[LoadIssue] = []
    seen: set[str] = set()
    if not directory.is_dir():
        issues.append(LoadIssue(directory, 0, "rules directory not found"))
    for path in sorted(directory.glob("*.yaml")) if directory.is_dir() else ():
        if path.name in NOT_PACKS:
            continue
        pack = _load_pack(path, env, issues, seen, wanted)
        if pack is not None:
            loaded.append(pack)
    return RuleSet(tuple(loaded), tuple(issues))


class _RuleError(Exception):
    def __init__(self, message: str, path: Sequence[str | int] = ()) -> None:
        super().__init__(message)
        self.path = path


def _load_pack(
    path: Path,
    env: SandboxedEnvironment,
    issues: list[LoadIssue],
    seen: set[str],
    wanted: set[str] | None,
) -> Pack | None:
    try:
        text = path.read_text(encoding="utf-8")
        root = yaml.compose(text, Loader=yaml.SafeLoader)
        data = yaml.safe_load(text)
    except (OSError, UnicodeDecodeError) as exc:
        issues.append(LoadIssue(path, 0, f"cannot read: {exc}"))
        return None
    except yaml.YAMLError as exc:
        mark = getattr(exc, "problem_mark", None)
        line = mark.line + 1 if mark is not None else 0
        issues.append(LoadIssue(path, line, f"invalid YAML: {getattr(exc, 'problem', exc)}"))
        return None
    if root is None or not isinstance(data, dict):
        issues.append(LoadIssue(path, 1, "a rule pack must be a mapping"))
        return None
    header_error = jsonschema.exceptions.best_match(
        jsonschema.Draft202012Validator(schema.PACK).iter_errors(data)
    )
    if header_error is not None:
        error_path = list(header_error.absolute_path)
        issues.append(LoadIssue(path, _line(root, error_path), _schema_message(header_error)))
        return None
    name = data["pack"]
    if wanted is not None and name not in wanted:
        return None
    pack_selector = _selector(data.get("applies_to"))
    rules: list[Rule] = []
    validator = jsonschema.Draft202012Validator(schema.RULE)
    for index, raw in enumerate(data["rules"]):
        where: list[str | int] = ["rules", index]
        rule_id = raw.get("id") if isinstance(raw, dict) else None
        rule_id = rule_id if isinstance(rule_id, str) else None
        error = jsonschema.exceptions.best_match(validator.iter_errors(raw))
        try:
            if error is not None:
                raise _RuleError(_schema_message(error), list(error.absolute_path))
            assert isinstance(rule_id, str)  # noqa: S101 (guaranteed by the schema)
            if not rule_id.startswith(f"{name}."):
                raise _RuleError(f"rule id must start with '{name}.'", ["id"])
            if rule_id in seen:
                raise _RuleError("duplicate rule id", ["id"])
            rule = _compile(
                raw,
                pack=name,
                path=path,
                line=_line(root, where),
                pack_selector=pack_selector,
                default_source=data["example_source"],
                env=env,
            )
        except _RuleError as exc:
            issues.append(LoadIssue(path, _line(root, [*where, *exc.path]), str(exc), rule_id))
            continue
        seen.add(rule_id)
        rules.append(rule)
    return Pack(name, path, data["example_source"], data.get("description", ""), tuple(rules))


def _compile(
    raw: dict[str, Any],
    *,
    pack: str,
    path: Path,
    line: int,
    pack_selector: Selector,
    default_source: str,
    env: SandboxedEnvironment,
) -> Rule:
    match = raw["match"]
    regex = None
    if "regex" in match:
        try:
            regex = re.compile(match["regex"])
        except re.error as exc:
            raise _RuleError(f"bad regex: {exc}", ["match", "regex"]) from None
    extract = tuple((name, True) for name in raw.get("extract", ())) + tuple(
        (name, False) for name in raw.get("optional", ())
    )
    known = BUILTINS | {n for n, _ in extract} | set(regex.groupindex if regex else ())
    templates: dict[str, Template | None] = {}
    for key in ("title", "template", "cause", "action"):
        templates[key] = _template(env, raw.get(key), key, known)
    title, text = templates["title"], templates["template"]
    assert title is not None and text is not None  # noqa: S101 (required by the schema)
    severity = raw.get("severity_override")
    return Rule(
        id=raw["id"],
        pack=pack,
        path=path,
        line=line,
        selector=_selector(raw["applies_to"]) if "applies_to" in raw else pack_selector,
        conditions=tuple(
            (key, frozenset(_as_text(v) for v in (value if isinstance(value, list) else [value])))
            for key, value in match.get("fields", {}).items()
        ),
        regex=regex,
        on=match.get("field", "message"),
        extract=extract,
        title=title,
        text=text,
        cause=templates["cause"],
        action=templates["action"],
        category=Category(raw["category"]),
        severity=None if severity is None else Severity[severity.upper()],
        confidence=float(raw.get("confidence", 0.9)),
        references=tuple(raw.get("references", ())),
        tags=tuple(raw.get("tags", ())),
        examples=tuple(
            Example(ex["line"], ex.get("source", default_source), ex["expect"])
            for ex in raw["examples"]
        ),
        counter_examples=tuple(
            Example(ex, default_source)
            if isinstance(ex, str)
            else Example(ex["line"], ex.get("source", default_source))
            for ex in raw["counter_examples"]
        ),
    )


def _template(
    env: SandboxedEnvironment, source: str | None, key: str, known: frozenset[str] | set[str]
) -> Template | None:
    if source is None:
        return None
    try:
        ast = env.parse(source)
        unknown = meta.find_undeclared_variables(ast) - known
        template = env.from_string(source)
    except TemplateSyntaxError as exc:
        raise _RuleError(f"bad template: {exc.message}", [key]) from None
    if key == "action" and not _all_shell_quoted(ast):
        raise _RuleError(
            "every value in 'action' must end with '| shquote': actions hold commands admins "
            "copy-paste, and log text is untrusted",
            [key],
        )
    if unknown:
        names = ", ".join(sorted(unknown))
        raise _RuleError(f"template uses {names}: add to 'extract' or the regex groups", [key])
    return template


def _shquote(value: Any) -> str:
    """Jinja filter: quote a log-derived value for a shell command (``shlex.quote``)."""
    return shlex.quote(str(value))


def _all_shell_quoted(ast: nodes.Template) -> bool:
    """True if every ``{{ ... }}`` prints a literal or ends with the ``shquote`` filter."""
    return all(
        isinstance(node, nodes.TemplateData | nodes.Const)
        or (isinstance(node, nodes.Filter) and node.name == "shquote")
        for output in ast.find_all(nodes.Output)
        for node in output.nodes
    )


def _selector(raw: Mapping[str, Any] | None) -> Selector:
    if not raw:
        return Selector()
    globs = {k: tuple(raw.get(k, ())) for k in ("units", "paths", "images", "services")}
    return Selector(
        source=SourceMatch(**globs) if any(globs.values()) else None,
        parsers=frozenset(raw.get("parsers", ())),
        programs=frozenset(raw.get("programs", ())),
    )


def _line(node: yaml.Node, path: Iterable[str | int]) -> int:
    """1-based line of the YAML node at ``path`` (or of the deepest ancestor found)."""
    for key in path:
        child: yaml.Node | None = None
        if isinstance(node, yaml.MappingNode):
            child = next((v for k, v in node.value if k.value == key), None)
        elif isinstance(node, yaml.SequenceNode) and isinstance(key, int):
            child = node.value[key] if key < len(node.value) else None
        if child is None:
            break
        node = child
    return int(node.start_mark.line) + 1


def _schema_message(error: jsonschema.ValidationError) -> str:
    where = ".".join(str(p) for p in error.absolute_path)
    return f"{where}: {error.message}" if where else error.message


def _as_text(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def _clip(value: Any) -> Any:
    if isinstance(value, str) and len(value) > MAX_VALUE_CHARS:
        return value[: MAX_VALUE_CHARS - 1] + "…"
    return value


def _render(template: Template | None, context: Mapping[str, Any]) -> str:
    if template is None:
        return ""
    return " ".join(template.render(context).split())
