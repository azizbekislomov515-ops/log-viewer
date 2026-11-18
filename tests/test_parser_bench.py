"""Throughput benchmark: every generic parser must exceed 100k lines/s on its own corpus.

Prints a table (parser alone, and the full normalizer chain) for all built-in parsers.
"""

import time
from datetime import UTC, datetime

import pytest

from loglens.collectors import source_from_id
from loglens.core.models import RawRecord
from loglens.parsers import Normalizer, default_registry
from tests.test_parsers import CORPUS, FIXTURES

LINES = 30_000
TARGET = 100_000  # lines/s, generic parsers
GENERIC = {"json", "syslog", "logfmt", "iso_text"}
REF = datetime(2026, 11, 18, tzinfo=UTC)


def _rate(fn, records: list[RawRecord]) -> float:  # type: ignore[no-untyped-def]
    best = 0.0
    for _ in range(3):  # best of 3: the machine's noise, not the parser's
        start = time.perf_counter()
        for r in records:
            fn(r)
        best = max(best, len(records) / (time.perf_counter() - start))
    return best


def test_parser_throughput(capsys: pytest.CaptureFixture[str], local_tz: None) -> None:
    registry, normalize = default_registry(), Normalizer()
    rows: list[tuple[str, str, float, float]] = []
    for name, (source_id, parser_name, _, _) in sorted(CORPUS.items()):
        source = source_from_id(source_id)
        parser = next(p for p in registry.for_source(source) if p.name == parser_name)
        lines = (FIXTURES / name).read_text(encoding="utf-8").splitlines()
        mine = [ln for ln in lines if parser.parse(RawRecord(source_id, ln, REF)).parsed]
        records = [RawRecord(source_id, mine[i % len(mine)], REF) for i in range(LINES)]
        alone = _rate(parser.parse, records)
        chain = _rate(lambda r, s=source: normalize(s, r), records)  # type: ignore[misc]
        rows.append((name, parser_name, alone, chain))

    with capsys.disabled():
        print(f"\n[bench] {LINES:,} lines each, best of 3")
        print(f"  {'fixture':<22} {'parser':<9} {'parser alone':>14} {'normalizer':>14}")
        for name, parser_name, alone, chain in rows:
            print(f"  {name:<22} {parser_name:<9} {alone:>12,.0f}/s {chain:>12,.0f}/s")

    slow = [(n, p, r) for n, p, r, _ in rows if p in GENERIC and r < TARGET]
    assert not slow, f"generic parsers below {TARGET:,} lines/s: {slow}"
