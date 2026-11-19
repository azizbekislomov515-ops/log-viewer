"""Explainer speed: a line no rule matches must cost < 50 us on average, per fixture source.

Prints a table (us/line for non-matching and matching lines) for every fixture corpus.
"""

import time

import pytest

from loglens.explain import ExplanationEngine, load_rules
from loglens.explain.examples import parse_line
from tests.test_parsers import CORPUS, FIXTURES

TARGET_US = 50.0
REPEAT = 200  # passes over each fixture's lines


def _us_per_line(engine: ExplanationEngine, entries: list) -> float:  # type: ignore[type-arg]
    if not entries:
        return 0.0
    best = float("inf")
    for _ in range(3):  # best of 3: the machine's noise, not the engine's
        start = time.perf_counter()
        for _ in range(REPEAT):
            for e in entries:
                engine.explain(e)
        best = min(best, (time.perf_counter() - start) / (REPEAT * len(entries)))
    return best * 1e6


def test_explain_speed(capsys: pytest.CaptureFixture[str], local_tz: None) -> None:
    engine = ExplanationEngine(load_rules())
    rows = []
    for name, (source_id, *_) in sorted(CORPUS.items()):
        lines = (FIXTURES / name).read_text(encoding="utf-8").splitlines()
        entries = [parse_line(line, source_id) for line in lines]
        miss = [e for e in entries if engine.explain(e) is None]
        hit = [e for e in entries if engine.explain(e) is not None]
        rows.append(
            (name, len(hit), len(miss), _us_per_line(engine, miss), _us_per_line(engine, hit))
        )

    with capsys.disabled():
        print(f"\n[bench] explain(), {len(engine.rules)} rules, best of 3")
        print(f"  {'fixture':<22} {'hit':>4} {'miss':>5} {'miss us/line':>13} {'hit us/line':>12}")
        for name, hits, misses, miss_us, hit_us in rows:
            print(f"  {name:<22} {hits:>4} {misses:>5} {miss_us:>13.1f} {hit_us:>12.1f}")

    slow = [(n, round(us, 1)) for n, _, _, us, _ in rows if us > TARGET_US]
    assert not slow, f"non-matching lines above {TARGET_US} us: {slow}"


#: Crafted 4 KB lines that make backtracking regexes quadratic (log text is attacker input).
_ADVERSARIAL = [
    "a" * 4096, "a " * 2048, "/" * 4096, "a:" * 2048, "(" * 4096, "x=" * 2048, "1" * 4096,
    ", " * 2048, "in /a:1 " * 512, '"' * 4096, "container die " * 292, "ip " * 1365,
]  # fmt: skip
MAX_REGEX_MS = 5.0  # linear scans of 4 KB take well under 1 ms


def test_no_rule_regex_backtracks_quadratically() -> None:
    slow = []
    for rule in load_rules().rules:
        if rule.regex is None:
            continue
        for text in _ADVERSARIAL:
            start = time.perf_counter()
            rule.regex.search(text, 0, 4096)
            ms = (time.perf_counter() - start) * 1e3
            if ms > MAX_REGEX_MS:
                slow.append((rule.id, text[:12], round(ms, 1)))
    assert not slow, f"regexes too slow on crafted input (anchor them with a look-behind): {slow}"
