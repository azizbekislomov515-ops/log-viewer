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
from types import MappingProxyType
from typing import Any

import jsonschema
import regex as regex_engine
import yaml
from jinja2 import StrictUndefined, Template, TemplateSyntaxError, meta, nodes
from jinja2.exceptions import SecurityError
from jinja2.sandbox import ImmutableSandboxedEnvironment, SandboxedEnvironment

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
    #: Collector fields the line arrives with (e.g. ``{"stream": "events"}``).
    fields: Mapping[str, Any] = MappingProxyType({})


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
    regex: Any  # a compiled ``regex`` pattern (re-compatible syntax, supports timeouts)
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
    #: Per-line regex timeout (None for trusted built-in packs, which use ``re``).
    timeout: float | None = None
    counter_examples: tuple[Example, ...] = ()

    def _search(self, target: str) -> Any:
        if self.timeout is None:  # trusted built-in pack, plain re
            return self.regex.search(target, 0, MAX_MATCH_CHARS)
        try:
            return self.regex.search(target, 0, MAX_MATCH_CHARS, timeout=self.timeout)
        except TimeoutError:
            raise RuleTimeoutError(self.id) from None

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
            if target is None:
                return None
            if (m := self._search(target)) is None:
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
        extracted = {k: v for k, v in context.items() if k not in BUILTINS and v is not None}
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
            extracted=extracted,
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
class CardSpec:
    """One overview card a pack declares (see ``schema._CARD``)."""

    title: str
    kind: str
    field: str | None = None
    columns: tuple[str, ...] = ()
    limit: int = 5
    warn_at: int | None = None
    empty: str = "Nothing in this period."
    rules: frozenset[str] = frozenset()
    tags: frozenset[str] = frozenset()
    min_severity: Severity | None = None

    def selects(self, rule_id: str | None, tags: Iterable[str], severity: Severity) -> bool:
        """Whether an entry (with its explanation's rule id and tags) feeds this card."""
        if self.min_severity is not None and severity < self.min_severity:
            return False
        if not (self.rules or self.tags):
            return True
        return rule_id in self.rules or not self.tags.isdisjoint(tags)


@dataclass(frozen=True, slots=True)
class Overview:
    """A pack's Service Overview metadata: cards, the fields its summary names, thresholds."""

    cards: tuple[CardSpec, ...] = ()
    #: Which sources show these cards (None: the pack's own ``applies_to``).
    selector: Selector | None = None
    key_fields: Mapping[str, str] = MappingProxyType({})
    error_rate: float | None = None
    spike_z: float | None = None
    spike_min_errors: int | None = None


@dataclass(frozen=True, slots=True)
class Pack:
    """A loaded rule pack (only its valid rules)."""

    name: str
    path: Path
    example_source: str
    description: str = ""
    rules: tuple[Rule, ...] = ()
    selector: Selector = Selector()
    overview: Overview | None = None


@dataclass(frozen=True, slots=True)
class RuleSet:
    """Everything ``load_rules`` found: valid packs plus every problem it skipped."""

    packs: tuple[Pack, ...] = ()
    issues: tuple[LoadIssue, ...] = ()

    @property
    def rules(self) -> tuple[Rule, ...]:
        """All rules in evaluation order (packs by file name, rules in file order)."""
        return tuple(r for p in self.packs for r in p.rules)


def load_rules(
    directory: Path | Sequence[Path] | None = None, *, packs: Iterable[str] | None = None
) -> RuleSet:
    """Load every ``*.yaml`` pack in ``directory`` (default: the repo's ``rules/``), or in
    several directories in order (built-in packs first, then user packs).

    ``packs`` limits loading to those pack names. Duplicate rule ids across packs: the
    first one wins, later ones are reported and skipped.
    """
    if directory is None:
        directories: Sequence[Path] = (DEFAULT_RULES_DIR,)
    elif isinstance(directory, Path):
        directories = (directory,)
    else:
        directories = directory
    wanted = None if packs is None else set(packs)
    env = make_environment()
    loaded: list[Pack] = []
    issues: list[LoadIssue] = []
    seen: set[str] = set()
    for folder in directories:
        if not folder.is_dir():
            issues.append(LoadIssue(folder, 0, "rules directory not found"))
            continue
        for path in sorted(folder.glob("*.yaml")):
            if path.name in NOT_PACKS:
                continue
            trusted = folder.resolve() == DEFAULT_RULES_DIR.resolve()
            pack = _load_pack(path, env, issues, seen, wanted, trusted=trusted)
            if pack is not None:
                loaded.append(pack)
    return RuleSet(tuple(loaded), tuple(issues))


class RuleSandbox(ImmutableSandboxedEnvironment):
    """Rule packs are untrusted input. On top of Jinja's immutable sandbox (no access to
    internals, no mutation), templates may only use ``ALLOWED_NODES`` and
    ``ALLOWED_FILTERS`` (checked at load time: no loops, macros, calls or attribute
    access), and ``*`` may not build huge strings or lists."""

    intercepted_binops = frozenset({"*"})

    def call_binop(self, context: Any, operator: str, left: Any, right: Any) -> Any:
        """Refuse repetition that would allocate more than ``MAX_REPEAT`` items."""
        if operator == "*":
            if any(isinstance(v, list | tuple | dict) for v in (left, right)):
                raise SecurityError("list repetition is not allowed in rule templates")
            if isinstance(left, str) or isinstance(right, str):
                seq, times = (left, right) if isinstance(left, str) else (right, left)
                if not isinstance(times, int) or len(seq) * max(times, 0) > MAX_REPEAT:
                    raise SecurityError("repetition too large in a rule template")
        return super().call_binop(context, operator, left, right)


def make_environment() -> SandboxedEnvironment:
    """The Jinja2 sandbox rule templates run in (shared by the loader and the editor)."""
    env = RuleSandbox(undefined=StrictUndefined, autoescape=False)
    env.filters["shquote"] = _shquote
    env.filters["thousands"] = _thousands
    return env


def _thousands(value: Any) -> str:
    """Jinja filter: ``8708530`` -> ``8,708,530`` (non-numbers unchanged)."""
    try:
        return f"{int(value):,}"
    except (TypeError, ValueError):
        return str(value)


#: Template constructs a rule may use. No For (a loop can hang the app even in a
#: sandbox), no Call/Getattr (no methods on objects), no Pow, no Macro/Include/Assign.
ALLOWED_NODES: tuple[type[nodes.Node], ...] = (
    nodes.Template, nodes.Output, nodes.TemplateData, nodes.Name, nodes.Const, nodes.Filter,
    nodes.Test, nodes.If, nodes.CondExpr, nodes.Compare, nodes.Operand, nodes.And, nodes.Or,
    nodes.Not, nodes.Getitem, nodes.Slice, nodes.Add, nodes.Sub, nodes.Mul, nodes.Div,
    nodes.FloorDiv, nodes.Mod, nodes.Neg, nodes.Pos, nodes.Concat, nodes.Tuple, nodes.List,
)  # fmt: skip
#: Only filters whose output is about as long as their input (no replace/center/
#: indent/join/wordwrap: those can multiply a value's size).
ALLOWED_FILTERS = frozenset({
    "shquote", "thousands", "int", "float", "round", "abs", "filesizeformat", "lower",
    "upper", "capitalize", "title", "trim", "default", "length",
})  # fmt: skip
#: Longest text a rule renders (anything after is cut).
MAX_OUTPUT_CHARS = 8_000
#: Longest string/list a template may build with ``*``.
MAX_REPEAT = 10_000
#: A rule's regex gives up on a line after this long (and the engine disables the rule
#: after ``engine.MAX_RULE_TIMEOUTS`` such timeouts).
RULE_TIMEOUT_S = 0.02


class RuleTimeoutError(RuntimeError):
    """A rule's regex took longer than ``RULE_TIMEOUT_S`` on a line."""


def _template_violation(ast: nodes.Template) -> str | None:
    """Why a template is not allowed, or None if it only uses safe constructs."""
    for node in ast.find_all(nodes.Node):
        if not isinstance(node, ALLOWED_NODES):
            return f"'{type(node).__name__}' is not allowed in rule templates"
        if isinstance(node, nodes.Filter) and node.name not in ALLOWED_FILTERS:
            return f"filter '{node.name}' is not allowed in rule templates"
        if isinstance(node, nodes.Filter) and (too_big := _small_constants(node.args)):
            return too_big
    return None


def _small_constants(args: list[nodes.Expr]) -> str | None:
    for arg in args:
        if isinstance(arg, nodes.Const) and isinstance(arg.value, int) and arg.value > MAX_REPEAT:
            return "filter argument too large"
    return None


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
    *,
    trusted: bool = False,
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
                trusted=trusted,
            )
        except _RuleError as exc:
            issues.append(LoadIssue(path, _line(root, [*where, *exc.path]), str(exc), rule_id))
            continue
        seen.add(rule_id)
        rules.append(rule)
    overview = _overview(data.get("overview"), {r.id for r in rules}, root, path, issues)
    return Pack(
        name,
        path,
        data["example_source"],
        data.get("description", ""),
        tuple(rules),
        pack_selector,
        overview,
    )


def _overview(
    raw: Any, rule_ids: set[str], root: yaml.Node, path: Path, issues: list[LoadIssue]
) -> Overview | None:
    """Parse a pack's ``overview`` block; a bad block is reported and dropped (the pack's
    rules still load)."""
    if raw is None:
        return None
    error = jsonschema.exceptions.best_match(
        jsonschema.Draft202012Validator(schema.OVERVIEW).iter_errors(raw)
    )
    if error is not None:
        where = ["overview", *error.absolute_path]
        issues.append(LoadIssue(path, _line(root, where), f"overview: {_schema_message(error)}"))
        return None
    cards = []
    for index, card in enumerate(raw.get("cards", ())):
        when = card.get("when", {})
        unknown = set(when.get("rules", ())) - rule_ids
        if unknown:
            where = ["overview", "cards", index, "when", "rules"]
            issues.append(
                LoadIssue(path, _line(root, where), f"card uses unknown rules: {sorted(unknown)}")
            )
            continue
        severity = when.get("min_severity")
        cards.append(
            CardSpec(
                title=card["title"],
                kind=card["kind"],
                field=card.get("field"),
                columns=tuple(card.get("columns", ())),
                limit=card.get("limit", 5),
                warn_at=card.get("warn_at"),
                empty=card.get("empty", "Nothing in this period."),
                rules=frozenset(when.get("rules", ())),
                tags=frozenset(when.get("tags", ())),
                min_severity=None if severity is None else Severity[severity.upper()],
            )
        )
    thresholds = raw.get("thresholds", {})
    return Overview(
        cards=tuple(cards),
        selector=_selector(raw["applies_to"]) if "applies_to" in raw else None,
        key_fields=MappingProxyType(dict(raw.get("key_fields", {}))),
        error_rate=thresholds.get("error_rate"),
        spike_z=thresholds.get("spike_z"),
        spike_min_errors=thresholds.get("spike_min_errors"),
    )


def _compile(
    raw: dict[str, Any],
    *,
    pack: str,
    path: Path,
    line: int,
    pack_selector: Selector,
    default_source: str,
    env: SandboxedEnvironment,
    trusted: bool = False,
) -> Rule:
    match = raw["match"]
    regex = None
    if "regex" in match:
        # Built-in packs use the fast re engine (their regexes are checked against ReDoS
        # payloads in CI); packs from users or other folders are untrusted and use the
        # regex module, whose matches time out.
        try:
            regex = (re if trusted else regex_engine).compile(match["regex"])
        except (regex_engine.error, re.error) as exc:
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
            Example(
                ex["line"],
                ex.get("source", default_source),
                ex["expect"],
                MappingProxyType(dict(ex.get("fields", {}))),
            )
            for ex in raw["examples"]
        ),
        counter_examples=tuple(
            Example(ex, default_source)
            if isinstance(ex, str)
            else Example(
                ex["line"],
                ex.get("source", default_source),
                None,
                MappingProxyType(dict(ex.get("fields", {}))),
            )
            for ex in raw["counter_examples"]
        ),
        timeout=None if trusted else RULE_TIMEOUT_S,
    )


def _template(
    env: SandboxedEnvironment, source: str | None, key: str, known: frozenset[str] | set[str]
) -> Template | None:
    if source is None:
        return None
    try:
        ast = env.parse(source)
    except TemplateSyntaxError as exc:
        raise _RuleError(f"bad template: {exc.message}", [key]) from None
    # Checked before compiling: Jinja folds constants at compile time (``2 ** 999999``).
    if (violation := _template_violation(ast)) is not None:
        raise _RuleError(violation, [key])
    unknown = meta.find_undeclared_variables(ast) - known
    try:
        template = env.from_string(source)
    except (TemplateSyntaxError, ValueError, OverflowError, MemoryError) as exc:
        raise _RuleError(f"bad template: {exc}", [key]) from None
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
    return " ".join(template.render(context)[:MAX_OUTPUT_CHARS].split())
