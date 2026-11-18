"""Property-based tests: no parser, the normalizer or the assembler may crash on any input,
and the raw text always survives."""

from datetime import UTC, datetime

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from loglens.collectors import source_from_id
from loglens.collectors.base import decode
from loglens.core.models import LogSource, RawRecord
from loglens.parsers import MAX_MESSAGE_CHARS, MultilineAssembler, Normalizer, default_registry
from loglens.parsers.base import ParsedFields

SOURCES = [
    source_from_id(s)
    for s in (
        "file:/var/log/squid/access.log",
        "file:/var/log/clamav/clamav.log",
        "file:/var/log/nginx/access.log",
        "file:/var/log/auth.log",
        "systemd:docker.service",
        "docker:anything-1",
    )
]
PARSERS = {p.name: p for s in SOURCES for p in default_registry().for_source(s)}

# Random text plus near-misses built from the characters log formats care about.
LOGGY = st.text(
    alphabet='0123456789 :-/.[]<>{}"=\\,|TZ+_aAbBNovWedERROR\t\n\x00\ufeff', max_size=200
)
TEXT = st.one_of(st.text(max_size=300), LOGGY)
PREFIXES = st.sampled_from(
    [
        "",
        "<34>1 2026-11-17T22:50:01Z h a 1 - ",
        "Nov 17 22:50:01 kali sshd[1]: ",
        "2026-11-17T22:50:01.1+05:00 kali sshd[1]: ",
        "Tue Nov 17 22:50:01 2026 -> ",
        '10.0.0.1 - - [17/Nov/2026:22:50:01 +0000] "',
        "1794955801.123    245 10.0.0.5 TCP_MISS/200 5 GET ",
        "2026/11/17 22:50:01 [error] 1#1: ",
        'time="2026-11-17T22:50:01Z" level=info msg="',
        '{"level":"info","ts":',
        "Failed password for ",
        "Accepted publickey for root from ",
    ]
)
SETTINGS = settings(max_examples=300, deadline=None, suppress_health_check=[HealthCheck.too_slow])
REF = datetime(2026, 11, 18, tzinfo=UTC)


@pytest.mark.parametrize("name", sorted(PARSERS))
@SETTINGS
@given(prefix=PREFIXES, text=TEXT)
def test_parser_never_raises(name: str, prefix: str, text: str) -> None:
    result = PARSERS[name].parse(RawRecord("s", prefix + text, timestamp=REF))
    assert isinstance(result, ParsedFields)
    if result.timestamp is not None:
        assert result.timestamp.tzinfo is not None


@pytest.mark.parametrize("source", SOURCES, ids=lambda s: s.id)
@SETTINGS
@given(prefix=PREFIXES, text=TEXT, with_ts=st.booleans())
def test_normalizer_never_raises_and_keeps_raw(
    source: LogSource, prefix: str, text: str, with_ts: bool
) -> None:
    line = prefix + text
    entry = Normalizer()(source, RawRecord(source.id, line, timestamp=REF if with_ts else None))
    assert entry.raw == line[:MAX_MESSAGE_CHARS]
    assert entry.timestamp.tzinfo is UTC
    if not entry.parsed:
        assert entry.message == entry.raw


@SETTINGS
@given(data=st.binary(max_size=400))
def test_arbitrary_bytes_through_decode(data: bytes) -> None:
    normalize = Normalizer()
    for line in data.split(b"\n"):
        for source in SOURCES:
            entry = normalize(source, RawRecord(source.id, decode(line)))
            assert entry.raw == decode(line)


@SETTINGS
@given(
    lines=st.lists(
        st.one_of(
            TEXT, st.sampled_from(["  at x", "Traceback (most recent call last):", "", "E: x"])
        ),
        max_size=40,
    )
)
def test_assembler_never_loses_or_reorders_text(lines: list[str]) -> None:
    a = MultilineAssembler(max_lines=5, max_chars=120)
    records = [
        RawRecord("s", line.replace("\n", " "), cursor=str(i)) for i, line in enumerate(lines)
    ]
    out = [e for r in records for e in a.feed(r, 0.0)] + a.flush()
    assert "\n".join(e.message for e in out) == "\n".join(r.message for r in records)
    assert [e.cursor for e in out] == sorted({e.cursor for e in out}, key=lambda c: int(c or 0))
    if out:
        assert out[-1].cursor == records[-1].cursor
