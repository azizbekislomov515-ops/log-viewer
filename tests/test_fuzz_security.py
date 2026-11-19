"""Fuzz tests (hypothesis) for everything that handles hostile text: the redactor, the
display sanitizer, the helper protocol, and parsing plus explaining with all built-in
rule packs. Each must never raise (beyond its documented error), never hang, and keep
its guarantee for any input."""

from __future__ import annotations

import contextlib
import re
import time
from datetime import UTC, datetime

import pytest
from hypothesis import HealthCheck, assume, given, settings
from hypothesis import strategies as st

from loglens.collectors import source_from_id
from loglens.core.models import RawRecord, Severity
from loglens.explain import DEFAULT_RULES_DIR, ExplanationEngine
from loglens.helper import protocol
from loglens.parsers import Normalizer
from loglens.security.redact import Redactor, luhn_ok
from loglens.security.text import printable

SETTINGS = settings(max_examples=300, deadline=None, suppress_health_check=[HealthCheck.too_slow])
HOSTILE_CHARS = "\x1b[]0;8m\x07\x9b\x00\x7f\u202e\u2066\u200f\r\n\t{}%#'\"\\$`|&;<>()aA0:=@/+-_."
HOSTILE = st.one_of(
    st.text(max_size=400),
    st.text(alphabet=HOSTILE_CHARS, max_size=400),
    st.builds(
        lambda a, b, c: a + b + c,
        st.text(max_size=50),
        st.sampled_from(
            ["password=", "Authorization: Bearer ", "https://u:", "Cookie: ", "AKIA", "ghp_",
             "sk_live_", "eyJ", "-----BEGIN PRIVATE KEY-----", "{{ ", "{% for ", "\x1b]8;;",
             "a" * 40 + "!", "4111 1111 1111 "]
        ),
        st.text(max_size=80),
    ),
)  # fmt: skip
SECRET_FORMS = st.sampled_from(
    [
        "password={s}",
        "passwd: {s}",
        "https://admin:{s}@db.example/x",
        "Authorization: Bearer {s}",
        "Authorization: Basic {s}",
        "Cookie: session={s}",
        "api_key={s}",
        "client_secret={s}",
    ]
)
SECRET = st.text(
    alphabet="ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!$%*",
    min_size=8,
    max_size=40,
)


@SETTINGS
@given(text=HOSTILE)
def test_redactor_never_raises_and_is_stable(text: str) -> None:
    redactor = Redactor()
    once, _ = redactor.redact(text)
    twice, again = redactor.redact(once)
    assert twice == once and again == 0  # redacting again changes nothing


@SETTINGS
@given(form=SECRET_FORMS, secret=SECRET, before=HOSTILE, after=st.text(max_size=40))
def test_planted_secrets_never_survive(form: str, secret: str, before: str, after: str) -> None:
    # Only the planted copy counts (not one in the noise, the form or a marker's name).
    assume(secret not in before + after + form + "[REDACTED:password authorization cookie]")
    line = f"{before} {form.format(s=secret)}"
    if after:
        line += f" {after}"
    redacted, count = Redactor().redact(line)
    assert count >= 1
    assert secret not in redacted


@SETTINGS
@given(digits=st.lists(st.integers(0, 9), min_size=11, max_size=17))  # 13..19 digits
def test_luhn_valid_card_numbers_are_redacted(digits: list[int]) -> None:
    body = "4" + "".join(map(str, digits))
    check = next(str(d) for d in range(10) if luhn_ok(body + str(d)))
    card = body + check
    if len(set(card)) == 1:
        return
    redacted, _ = Redactor().redact(f"paid with {card} today")
    assert card not in redacted


@SETTINGS
@given(text=HOSTILE)
def test_custom_patterns_cannot_hang(text: str) -> None:
    redactor = Redactor(["(a|aa)+$", "(x+x+)+y"])
    started = time.perf_counter()
    redactor.redact(text + "a" * 30 + "!")
    assert time.perf_counter() - started < 1.0


@SETTINGS
@given(text=HOSTILE, keep=st.booleans())
def test_printable_output_has_no_controls_escapes_or_bidi(text: str, keep: bool) -> None:
    out = printable(text, keep_newlines=keep)
    allowed_newline = "\n" if keep else ""
    bad = [c for c in out if (ord(c) < 32 and c not in allowed_newline) or 127 <= ord(c) < 160]
    assert not bad
    assert not re.search("[\u202a-\u202e\u2066-\u2069\u200e\u200f\u061c]", out)


@SETTINGS
@given(data=st.one_of(st.binary(max_size=600), HOSTILE.map(lambda t: t.encode())))
def test_protocol_decoders_raise_only_protocol_errors(data: bytes) -> None:
    for decoder in (protocol.decode_request, protocol.decode_reply):
        with contextlib.suppress(protocol.ProtocolError):
            decoder(data)


@SETTINGS
@given(
    op=st.sampled_from(["hello", "stream", "exec", None, 1]),
    extra=st.dictionaries(st.text(max_size=8), st.one_of(st.none(), st.integers(),
                                                         st.text(max_size=20)), max_size=4),
)  # fmt: skip
def test_protocol_requests_are_strict(op: object, extra: dict[str, object]) -> None:
    import json  # noqa: PLC0415

    line = json.dumps({"v": 1, "op": op, **extra}).encode()
    try:
        request = protocol.decode_request(line)
    except protocol.ProtocolError:
        return
    assert isinstance(request, protocol.Hello | protocol.StreamRequest)


@SETTINGS
@given(text=HOSTILE, fields=st.dictionaries(st.text(max_size=70), HOSTILE, max_size=5))
def test_any_record_round_trips_within_limits(text: str, fields: dict[str, str]) -> None:
    record = RawRecord("file:/x", text * 50, datetime(2026, 1, 1, tzinfo=UTC), Severity.ERROR,
                       fields)  # fmt: skip
    line = protocol.encode_record(record)
    assert len(line) <= protocol.MAX_MESSAGE
    back = protocol.record_from_reply(protocol.decode_reply(line), "file:/x")
    assert back.severity is Severity.ERROR


ENGINE = ExplanationEngine.from_directory([DEFAULT_RULES_DIR])
NORMALIZE = Normalizer()
SOURCES = [
    source_from_id(s)
    for s in (
        "file:/var/log/squid/access.log",
        "file:/var/log/clamav/clamav.log",
        "file:/var/log/nginx/error.log",
        "file:/var/log/auth.log",
        "systemd:ssh.service",
        "systemd:docker.service",
        "docker:web-1",
    )
]
PREFIXES = st.sampled_from(
    ["", "Nov 17 22:50:01 kali sshd[1]: ", "1794955801.123    245 10.0.0.5 TCP_DENIED/403 5 ",
     "Tue Nov 17 22:50:01 2026 -> ", "2026/11/17 22:50:01 [error] 1#1: ", "ERROR: ",
     "Failed password for ", "container die ", '{"level":"error","msg":"']
)  # fmt: skip


@pytest.mark.parametrize("source", SOURCES, ids=lambda s: s.id)
@SETTINGS
@given(prefix=PREFIXES, text=HOSTILE)
def test_parse_and_explain_never_raise_or_stall(source: object, prefix: str, text: str) -> None:
    entry = NORMALIZE(source, RawRecord(source.id, prefix + text))  # type: ignore[attr-defined]
    started = time.perf_counter()
    explanation = ENGINE.explain(entry, source)  # type: ignore[arg-type]
    assert time.perf_counter() - started < 0.5
    if explanation is not None:
        assert explanation.title
