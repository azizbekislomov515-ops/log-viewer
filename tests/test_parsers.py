"""Phase 3 parsers: fixture corpus (golden files), table-driven field checks, timestamps,
registry selection, severity inference, multi-line assembly and the normalizer.

Regenerate golden files after an intended parser change, then review the diff:

    LOGLENS_UPDATE_GOLDEN=1 uv run pytest tests/test_parsers.py
"""

import json
import logging
import os
from dataclasses import replace
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest

from loglens.collectors import source_from_id
from loglens.core.models import LogEntry, LogSource, RawRecord, Severity, SourceKind
from loglens.parsers import (
    MultilineAssembler,
    Normalizer,
    ParsedFields,
    ParserRegistry,
    SeverityInferrer,
    SourceMatch,
    default_registry,
    timestamps,
)
from loglens.parsers.multiline import exception_fields
from loglens.parsers.timestamps import (
    parse_clf,
    parse_ctime,
    parse_epoch,
    parse_iso,
    parse_rfc3164,
)

FIXTURES = Path(__file__).parent / "fixtures" / "logs"
#: Collector time for fixture records: the year reference for year-less syslog stamps.
REF = datetime(2026, 11, 18, 12, 0, tzinfo=UTC)

#: fixture -> (source id it is read as, parser expected for its well-formed lines,
#:             minimum lines that parser must claim, minimum lines it must reject)
CORPUS: dict[str, tuple[str, str, int, int]] = {
    "squid_access.log": ("file:/var/log/squid/access.log", "squid", 28, 5),
    "squid_cache.log": ("file:/var/log/squid/cache.log", "squid", 30, 2),
    "clamav.log": ("file:/var/log/clamav/clamav.log", "clamav", 31, 1),
    "freshclam.log": ("file:/var/log/clamav/freshclam.log", "clamav", 31, 2),
    "nginx_access.log": ("file:/var/log/nginx/access.log", "nginx", 29, 4),
    "nginx_error.log": ("file:/var/log/nginx/error.log", "nginx", 32, 2),
    "auth.log": ("file:/var/log/auth.log", "sshd", 28, 2),
    "dockerd.log": ("systemd:docker.service", "dockerd", 31, 3),
    "syslog_rfc3164.log": ("file:/var/log/syslog", "syslog", 31, 3),
    "syslog_rfc5424.log": ("file:/var/log/messages", "syslog", 30, 2),
    "jsonlines.log": ("docker:api-1", "json", 30, 3),
    "logfmt.log": ("docker:loki-1", "logfmt", 28, 4),
    "iso_text.log": ("systemd:myapp.service", "iso_text", 28, 4),
    "python_traceback.log": ("systemd:worker.service", "iso_text", 6, 0),
    "java_stacktrace.log": ("docker:orders-1", "iso_text", 8, 0),
}


@pytest.fixture(autouse=True)
def _utc(local_tz: None) -> None:
    """Naive fixture timestamps are read as UTC so goldens don't depend on the host."""


def read_corpus(name: str) -> tuple[str, list[LogEntry]]:
    source_id = CORPUS[name][0]
    text = (FIXTURES / name).read_text(encoding="utf-8")
    assembler, normalize = MultilineAssembler(), Normalizer()
    records = [RawRecord(source_id, line, timestamp=REF) for line in text.split("\n")[:-1]]
    events = [e for r in records for e in assembler.feed(r, 0.0)] + assembler.flush()
    # Goldens check what the parser read. For containers Docker's write time would win
    # over the line's time (tested separately), so read them as plain sources.
    source = replace(source_from_id(source_id), kind=SourceKind.FILE)
    return text, [normalize(source, e) for e in events]


def snapshot(entry: LogEntry) -> dict[str, Any]:
    return {
        "parsed": entry.parsed,
        "parser": entry.fields.get("parser"),
        "ts": entry.timestamp.isoformat(),
        "severity": entry.severity.name,
        "message": entry.message,
        "fields": {k: v for k, v in sorted(entry.fields.items()) if k != "parser"},
    }


@pytest.mark.parametrize("name", sorted(CORPUS))
def test_corpus_matches_golden(name: str) -> None:
    _, entries = read_corpus(name)
    got = [json.dumps(snapshot(e), ensure_ascii=False, sort_keys=True) for e in entries]
    golden = FIXTURES / f"{name}.expected.jsonl"
    if os.environ.get("LOGLENS_UPDATE_GOLDEN"):
        golden.write_text("\n".join(got) + "\n", encoding="utf-8")
        pytest.skip("golden updated")
    expected = golden.read_text(encoding="utf-8").splitlines()
    for i, (g, e) in enumerate(zip(got, expected, strict=False)):
        assert json.loads(g) == json.loads(e), f"{name} entry {i}"
    assert len(got) == len(expected)


@pytest.mark.parametrize("name", sorted(CORPUS))
def test_corpus_preserves_raw_and_rejects_garbage(name: str) -> None:
    text, entries = read_corpus(name)
    _, parser, min_claimed, min_rejected = CORPUS[name]
    # Every byte of input survives in some entry's raw text, in order.
    assert "\n".join(e.raw for e in entries) == text[:-1]
    for e in entries:
        if not e.parsed:
            assert e.message == e.raw  # untouched
            assert "parser" not in e.fields
        assert e.timestamp.tzinfo is UTC
    claimed = sum(e.fields.get("parser") == parser for e in entries)
    assert claimed >= min_claimed
    assert len(entries) - claimed >= min_rejected
    assert sum(len(e.raw.split("\n")) for e in entries) >= 30  # corpus size


def find(entries: list[LogEntry], needle: str) -> LogEntry:
    return next(e for e in entries if needle in e.raw)


# (fixture, substring identifying the line, expected severity, expected field subset)
TABLE: list[tuple[str, str, Severity, dict[str, Any]]] = [
    (
        "squid_access.log",
        "CONNECT facebook.com:443",
        Severity.WARNING,
        {
            "client_ip": "10.0.0.5",
            "cache_result": "TCP_DENIED",
            "status": 403,
            "method": "CONNECT",
            "domain": "facebook.com",
            "hierarchy": "HIER_NONE",
            "elapsed_ms": 0,
            "bytes": 3922,
        },
    ),
    (
        "squid_access.log",
        "neverssl.com/ alice",
        Severity.INFO,
        {
            "user": "alice",
            "peer": "34.223.124.45",
            "domain": "neverssl.com",
            "content_type": "text/html",
        },
    ),
    ("squid_access.log", "TCP_MISS/502", Severity.ERROR, {"status": 502}),
    ("squid_access.log", "[2001:db8::10]", Severity.INFO, {"domain": "2001:db8::10"}),
    (
        "squid_access.log",
        '"curl/8.5.0" TCP_MISS',
        Severity.INFO,
        {"user_agent": "curl/8.5.0", "extra": "TCP_MISS:HIER_DIRECT"},
    ),
    ("squid_cache.log", "SECURITY ALERT", Severity.WARNING, {"level": "SECURITY ALERT"}),
    ("squid_cache.log", "FATAL: Unable", Severity.CRITICAL, {"kid": "kid1"}),
    ("squid_cache.log", "ERROR: Connection to 10.0.5.20", Severity.ERROR, {"lines": 2}),
    (
        "clamav.log",
        "eicar.com",
        Severity.ERROR,
        {
            "event": "virus_found",
            "file": "/home/azik/Downloads/eicar.com",
            "signature": "Win.Test.EICAR_HDB-1",
        },
    ),
    (
        "clamav.log",
        "file with spaces.exe",
        Severity.ERROR,
        {"file": "/tmp/x y z/file with spaces.exe", "signature": "Win.Trojan.Generic-9999"},
    ),
    (
        "clamav.log",
        "Access denied. ERROR",
        Severity.ERROR,
        {"event": "scan_error", "file": "/root/secret", "error": "Access denied."},
    ),
    (
        "clamav.log",
        "correctly reloaded",
        Severity.INFO,
        {"event": "db_reloaded", "signatures": 8710423},
    ),
    ("clamav.log", "macro.docm", Severity.ERROR, {"event": "virus_found"}),
    (
        "freshclam.log",
        "daily.cld updated (version: 28187",
        Severity.NOTICE,
        {"event": "db_updated", "database": "daily.cld", "version": 28187, "signatures": 2074152},
    ),
    ("freshclam.log", "!Can't download", Severity.ERROR, {"event": "error"}),
    ("freshclam.log", "^Can't query", Severity.WARNING, {"event": "warning"}),
    ("freshclam.log", "OUTDATED", Severity.WARNING, {"event": "warning"}),
    (
        "nginx_access.log",
        '/favicon.ico HTTP/1.1" 404',
        Severity.WARNING,
        {
            "client_ip": "10.0.0.5",
            "method": "GET",
            "path": "/favicon.ico",
            "protocol": "HTTP/1.1",
            "status": 404,
            "bytes": 153,
            "referer": "http://example.com/",
        },
    ),
    (
        "nginx_access.log",
        "\\x16\\x03",
        Severity.WARNING,
        {"request": "\\x16\\x03\\x01\\x02\\x00\\x01\\x00\\x01\\xFC\\x03\\x03", "status": 400},
    ),
    ("nginx_access.log", "- admin [", Severity.INFO, {"user": "admin"}),
    (
        "nginx_access.log",
        '"weird\\" agent',
        Severity.INFO,
        {"user_agent": 'Mozilla/5.0 \\"weird\\" agent'},
    ),
    ("nginx_access.log", '/api/v1/report HTTP/1.1" 502', Severity.ERROR, {"status": 502}),
    (
        "nginx_error.log",
        "connect() failed (111",
        Severity.ERROR,
        {
            "level": "error",
            "pid": 29,
            "connection": 3,
            "client_ip": "10.0.0.10",
            "server": "api.example.com",
            "request": "GET /api/v1/report HTTP/1.1",
            "upstream": "http://127.0.0.1:8080/api/v1/report",
            "host": "api.example.com",
        },
    ),
    ("nginx_error.log", "[emerg] 1#1: bind()", Severity.CRITICAL, {"level": "emerg"}),
    ("nginx_error.log", "[warn]", Severity.WARNING, {"level": "warn"}),
    ("nginx_error.log", "unknown directive", Severity.CRITICAL, {"level": "emerg"}),
    (
        "auth.log",
        "Failed password for invalid user admin",
        Severity.WARNING,
        {
            "event": "failed",
            "user": "admin",
            "invalid_user": True,
            "auth_method": "password",
            "src_ip": "203.0.113.9",
            "src_port": 51234,
            "program": "sshd",
            "pid": "1301",
            "host": "kali",
        },
    ),
    (
        "auth.log",
        "Accepted publickey for azik from 192.168.1.10 port 40000",
        Severity.NOTICE,
        {
            "event": "accepted",
            "user": "azik",
            "auth_method": "publickey",
            "key": "ED25519 SHA256:Zx3r9Kq2mW8vN1bT4yH6uJ0pL5sD7fG9hA2cE4iO6k",
        },
    ),
    (
        "auth.log",
        "Invalid user admin from",
        Severity.WARNING,
        {"event": "invalid_user", "user": "admin", "src_ip": "203.0.113.9"},
    ),
    (
        "auth.log",
        "Disconnected from user azik",
        Severity.INFO,
        {"event": "disconnected", "user": "azik", "src_ip": "192.168.1.10"},
    ),
    (
        "auth.log",
        "Connection closed by invalid user admin",
        Severity.INFO,
        {"event": "connection_closed", "invalid_user": True, "preauth": True},
    ),
    (
        "auth.log",
        "maximum authentication attempts",
        Severity.WARNING,
        {"event": "max_auth_exceeded", "user": "root"},
    ),
    (
        "auth.log",
        "sshd-session[1701]",
        Severity.WARNING,
        {"event": "invalid_user", "user": "oracle", "program": "sshd-session"},
    ),
    (
        "auth.log",
        "2001:db8::77",
        Severity.WARNING,
        {"event": "failed", "src_ip": "2001:db8::77", "user": "git"},
    ),
    ("auth.log", "sudo:     azik", Severity.INFO, {"program": "sudo", "parser": "syslog"}),
    (
        "auth.log",
        "Disconnecting authenticating",
        Severity.WARNING,
        {"event": "disconnecting", "user": "root", "reason": "Too many authentication failures"},
    ),
    ("freshclam.log", "DON'T PANIC", Severity.INFO, {"event": "outdated_help"}),
    (
        "squid_access.log",
        "error:invalid-request",
        Severity.WARNING,
        {"domain": None, "cache_result": "NONE_NONE", "status": 400},
    ),
    (
        "dockerd.log",
        "topic=/tasks/delete",
        Severity.INFO,
        {"event": "container_exited", "container_id": "4f1e2d3c4b5a", "level": "info"},
    ),
    ("dockerd.log", "topic=/tasks/oom", Severity.ERROR, {"event": "container_oom"}),
    (
        "dockerd.log",
        "using the force",
        Severity.WARNING,
        {
            "event": "container_kill_forced",
            "timeout_s": "10",
            "signal": "15",
            "container_id": "9a8b7c6d5e4f",
        },
    ),
    ("dockerd.log", "Daemon has completed", Severity.NOTICE, {"event": "daemon_ready"}),
    ("dockerd.log", "pid file found", Severity.CRITICAL, {"event": "daemon_start_failed"}),
    (
        "dockerd.log",
        "syslog wrapped error",
        Severity.ERROR,
        {"host": "kali", "program": "dockerd", "container_id": "ffee"},
    ),
    (
        "syslog_rfc3164.log",
        "<0>Nov 17",
        Severity.CRITICAL,
        {"facility": 0, "program": "kernel", "host": "kali"},
    ),
    ("syslog_rfc3164.log", "Out of memory: Killed", Severity.CRITICAL, {"program": "kernel"}),
    ("syslog_rfc3164.log", "CRON[1600]", Severity.INFO, {"program": "CRON", "pid": "1600"}),
    (
        "syslog_rfc5424.log",
        "ID47 - BOM",
        Severity.CRITICAL,
        {"facility": 4, "host": "mymachine.example.com", "program": "su", "msgid": "ID47"},
    ),
    (
        "syslog_rfc5424.log",
        "escaped bracket",
        Severity.INFO,
        {"structured_data": '[escaped@1 v="a \\] b"]'},
    ),
    (
        "jsonlines.log",
        "slow query",
        Severity.WARNING,
        {"level": "warn", "duration": 2.31, "caller": "db/pool.go:88"},
    ),
    ("jsonlines.log", '"level":60', Severity.CRITICAL, {"name": "api", "pid": 123}),
    ("jsonlines.log", "ECS formatted", Severity.WARNING, {"service.name": "orders"}),
    ("jsonlines.log", "unparseable time", Severity.INFO, {"bad_timestamp": "yesterday at noon"}),
    ("logfmt.log", "connection refused", Severity.ERROR, {"component": "db", "level": "error"}),
    ("logfmt.log", 'escaped \\"quotes\\"', Severity.INFO, {"user": "o'brien"}),
    ("logfmt.log", "Failed to look up user", Severity.ERROR, {"error": "user not found"}),
    ("iso_text.log", "Request failed", Severity.ERROR, {"level": "ERROR"}),
    ("iso_text.log", "[WARN] disk usage", Severity.WARNING, {"level": "WARN"}),
    ("iso_text.log", "Ban 203.0.113.9", Severity.NOTICE, {"level": "NOTICE"}),
]


@pytest.mark.parametrize(("name", "needle", "severity", "expected"), TABLE)
def test_table(name: str, needle: str, severity: Severity, expected: dict[str, Any]) -> None:
    entry = find(read_corpus(name)[1], needle)
    assert entry.parsed
    assert entry.severity is severity
    assert {k: entry.fields.get(k) for k in expected} == expected


def test_messages_and_timestamps_from_fixtures() -> None:
    entries = read_corpus("auth.log")[1]
    e = find(entries, "Failed password for root")
    assert e.message == "Failed password for root from 203.0.113.9 port 51300 ssh2"
    assert e.timestamp == datetime(2026, 11, 17, 22, 50, 20, tzinfo=UTC)
    iso = find(entries, "sshd-session[1700]")
    assert iso.timestamp == datetime(2026, 11, 17, 17, 56, 0, 123456, tzinfo=UTC)

    squid = find(read_corpus("squid_access.log")[1], "facebook.com:443")
    assert squid.timestamp == datetime(2026, 11, 17, 22, 50, 1, 456000, tzinfo=UTC)
    clam = find(read_corpus("clamav.log")[1], "Wed Nov  4")
    assert clam.timestamp == datetime(2026, 11, 4, 1, 2, 10, tzinfo=UTC)
    dockerd = find(read_corpus("dockerd.log")[1], "Loading containers: start")
    assert dockerd.timestamp == datetime(2026, 11, 18, 15, 7, 5, 313363, tzinfo=UTC)
    assert dockerd.message == "Loading containers: start."
    year = find(read_corpus("syslog_rfc3164.log")[1], "Year boundary")
    assert year.timestamp.year == 2025  # Dec 31 seen on Nov 18 2026 -> last year


def test_unparseable_timestamp_warns_and_falls_back(caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.WARNING, logger="loglens.parsers.timestamps")
    timestamps._bad.clear()  # the warning is rate-limited per process
    entries = read_corpus("iso_text.log")[1]
    e = find(entries, "2026-13-45")
    assert e.parsed
    assert e.fields["bad_timestamp"] == "2026-13-45 25:61:00"
    assert e.timestamp == REF  # collector time, not garbage, not "now"
    assert any("unparseable timestamp" in r.message for r in caplog.records)


def test_stack_traces_are_merged_into_one_entry() -> None:
    entries = read_corpus("python_traceback.log")[1]
    chained = find(entries, "chained failure")
    assert chained.fields["lines"] == 14
    assert chained.fields["exception_type"] == "app.errors.DatabaseError"
    assert chained.fields["exception_message"] == "cannot reach database"
    assert chained.fields["stack_frames"] == 3
    assert chained.severity is Severity.ERROR
    bare = find(entries, "KeyboardInterrupt")  # bare Traceback after a WARNING line
    assert bare.fields["exception_type"] == "KeyboardInterrupt"
    orphan = find(entries, "orphan indented")
    assert orphan.raw.startswith("2026-11-17 22:50:06,000 INFO")  # joined to the previous line

    java = read_corpus("java_stacktrace.log")[1]
    npe = find(java, "NullPointerException")
    assert npe.fields["exception_type"] == "java.lang.NullPointerException"
    assert npe.fields["stack_frames"] == 4
    root = find(java, "Unable to acquire JDBC")
    assert root.fields["exception_type"] == "java.net.ConnectException"  # root cause
    assert root.fields["lines"] == 12
    uncaught = find(java, 'Exception in thread "main"')
    assert uncaught.raw.startswith("Exception in thread")
    assert uncaught.fields["exception_type"] == "java.lang.IllegalStateException"
    assert sum("\n" in e.raw for e in java) == 5


# --- timestamps -------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("2026-11-17T22:50:01Z", datetime(2026, 11, 17, 22, 50, 1, tzinfo=UTC)),
        ("2026-11-17T22:50:01.123456789Z", datetime(2026, 11, 17, 22, 50, 1, 123456, tzinfo=UTC)),
        ("2026-11-17 22:50:01,5", datetime(2026, 11, 17, 22, 50, 1, 500000, tzinfo=UTC)),
        ("2026-11-17T22:50:01+05:00", datetime(2026, 11, 17, 17, 50, 1, tzinfo=UTC)),
        ("2026-11-17T22:50:01+0500", datetime(2026, 11, 17, 17, 50, 1, tzinfo=UTC)),
        ("2026/11/17 22:50:01", datetime(2026, 11, 17, 22, 50, 1, tzinfo=UTC)),
        ("2026-02-30T00:00:00Z", None),
        ("not a date", None),
    ],
)
def test_parse_iso(text: str, expected: datetime | None) -> None:
    assert parse_iso(text) == expected


def test_other_formats() -> None:
    assert parse_ctime("Wed Nov  4 01:02:10 2026") == datetime(2026, 11, 4, 1, 2, 10, tzinfo=UTC)
    assert parse_ctime("Xyz Foo 4 01:02:10 2026") is None
    assert parse_clf("17/Nov/2026:22:50:12 -0500") == datetime(2026, 11, 18, 3, 50, 12, tzinfo=UTC)
    assert parse_clf("32/Nov/2026:22:50:12 +0000") is None
    for value in (1794955801, 1794955801000, 1794955801000000, 1794955801000000000, "1794955801"):
        assert parse_epoch(value) == datetime(2026, 11, 17, 22, 50, 1, tzinfo=UTC)
    assert parse_epoch("nan") is None
    assert parse_epoch(float("inf")) is None


def test_rfc3164_year_inference() -> None:
    ref = datetime(2027, 1, 1, 0, 0, 30, tzinfo=UTC)
    assert parse_rfc3164("Dec 31 23:59:59", ref) == datetime(2026, 12, 31, 23, 59, 59, tzinfo=UTC)
    assert parse_rfc3164("Jan  1 00:00:10", ref) == datetime(2027, 1, 1, 0, 0, 10, tzinfo=UTC)
    # A little in the future (clock skew) stays in the reference year.
    assert parse_rfc3164("Jan  2 00:00:00", ref) == datetime(2027, 1, 2, tzinfo=UTC)
    assert parse_rfc3164("Feb 29 00:00:00", ref) is None  # 2027 is not a leap year
    assert parse_rfc3164("Foo 1 00:00:00", ref) is None


def test_naive_timestamps_are_local_time(tashkent_tz: None) -> None:
    assert parse_iso("2026-11-17 22:50:01") == datetime(2026, 11, 17, 17, 50, 1, tzinfo=UTC)
    tashkent = timezone(timedelta(hours=5))
    ref = datetime(2026, 11, 18, tzinfo=tashkent)
    assert parse_rfc3164("Nov 17 22:50:01", ref) == datetime(2026, 11, 17, 17, 50, 1, tzinfo=UTC)
    assert parse_ctime("Tue Nov 17 22:50:01 2026") == datetime(2026, 11, 17, 17, 50, 1, tzinfo=UTC)


# --- registry ---------------------------------------------------------------------------


class Stub:
    def __init__(self, name: str, *, claims: bool = True, raises: bool = False,
                 match: SourceMatch | None = None) -> None:  # fmt: skip
        self.name, self.claims, self.raises = name, claims, raises
        self.match = match or SourceMatch()

    def matches(self, source: LogSource) -> bool:
        if self.raises and self.name == "bad-match":
            raise RuntimeError("matches broke")
        return self.match(source)

    def parse(self, record: RawRecord) -> ParsedFields:
        if self.raises:
            raise RuntimeError("parse broke")
        return ParsedFields(self.claims, message=self.name)


def test_registry_priority_and_fallback() -> None:
    reg = ParserRegistry([(Stub("low"), 1), (Stub("high", claims=False), 9), (Stub("mid"), 5)])
    src = source_from_id("systemd:x.service")
    assert [p.name for p in reg.for_source(src)] == ["high", "mid", "low"]
    name, result = reg.parse(src, RawRecord(src.id, "x"))
    assert (name, result.message) == ("mid", "mid")


def test_registry_survives_broken_parsers(caplog: pytest.LogCaptureFixture) -> None:
    reg = ParserRegistry([(Stub("boom", raises=True), 9), (Stub("bad-match", raises=True), 8),
                          (Stub("ok"), 1)])  # fmt: skip
    src = source_from_id("systemd:x.service")
    assert [p.name for p in reg.for_source(src)] == ["boom", "ok"]
    assert reg.parse(src, RawRecord(src.id, "x"))[0] == "ok"
    assert "parser raised" in caplog.text


@pytest.mark.parametrize(
    ("source", "matched"),
    [
        (source_from_id("systemd:nginx.service"), True),
        (source_from_id("file:/var/log/nginx/error.log"), True),
        (source_from_id("docker:proxy-nginx-1"), True),  # container name, as `tail` knows it
        (LogSource("docker:web-1", SourceKind.DOCKER_CONTAINER, "web", "g",
                   metadata={"image": "nginx:1.27-alpine", "container_name": "web-1"}), True),
        (LogSource("docker:p-edge-1", SourceKind.DOCKER_CONTAINER, "edge", "g",
                   metadata={"image": "acme/edge:2", "compose_service": "nginx-edge"}), True),
        (source_from_id("file:/var/log/nginxish.log"), False),
        (source_from_id("systemd:apache2.service"), False),
    ],
)  # fmt: skip
def test_source_match(source: LogSource, matched: bool) -> None:
    names = [p.name for p in default_registry().for_source(source)]
    assert ("nginx" in names) is matched
    assert names[-4:] == ["json", "syslog", "logfmt", "iso_text"]  # generic fallback chain


def test_service_parser_falls_back_to_generic() -> None:
    src = source_from_id("file:/var/log/nginx/access.log")
    line = '{"level":"error","msg":"json access log","status":500}'
    entry = Normalizer()(src, RawRecord(src.id, line, timestamp=REF))
    assert (entry.fields["parser"], entry.severity, entry.message) == (
        "json", Severity.ERROR, "json access log")  # fmt: skip


# --- severity inference -----------------------------------------------------------------


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("Kernel panic - not syncing", Severity.CRITICAL),
        ("worker 3 was OOM-killed", Severity.CRITICAL),  # phrase "oom-kill", substring
        ("myapp.service: Failed with result 'oom-kill'.", Severity.CRITICAL),
        ("connection refused by peer", Severity.ERROR),
        ("Could not resolve host", Severity.ERROR),
        ("this API is Deprecated", Severity.WARNING),
        ("debug: x=1", Severity.DEBUG),
        ("all good", None),
        ("errorless operation", None),  # whole words only
    ],
)
def test_severity_inference(text: str, expected: Severity | None) -> None:
    assert SeverityInferrer().infer(text) is expected


def test_severity_inference_is_configurable() -> None:
    inferrer = SeverityInferrer(
        {Severity.NOTICE: ("ban", "unban now")}, patterns=[(Severity.ERROR, r"code=5\d\d")]
    )
    assert inferrer.infer("Ban 1.2.3.4") is Severity.NOTICE
    assert inferrer.infer("please UNBAN NOW") is Severity.NOTICE
    assert inferrer.infer("status code=503") is Severity.ERROR
    assert inferrer.infer("error") is None
    entry = Normalizer(inferrer=inferrer)(
        source_from_id("systemd:x.service"), RawRecord("systemd:x.service", "Ban 1.2.3.4")
    )
    assert entry.severity is Severity.NOTICE


# --- normalizer precedence --------------------------------------------------------------


def test_normalizer_timestamp_precedence() -> None:
    normalize, src = Normalizer(), source_from_id("systemd:x.service")
    collector_ts = datetime(2026, 11, 18, 1, 0, tzinfo=UTC)
    stamped = normalize(src, RawRecord(src.id, "2026-11-17T22:50:01Z INFO hi", collector_ts))
    assert stamped.timestamp == datetime(2026, 11, 17, 22, 50, 1, tzinfo=UTC)  # line wins
    plain = normalize(src, RawRecord(src.id, "hello", collector_ts))
    assert plain.timestamp == collector_ts and "timestamp_source" not in plain.fields
    before = datetime.now(UTC)
    bare = normalize(src, RawRecord(src.id, "hello"))
    assert bare.timestamp >= before and bare.fields["timestamp_source"] == "ingest"


def test_docker_write_time_beats_the_time_written_in_the_line() -> None:
    """Times inside containers are often naive UTC while the host is not: trust Docker."""
    normalize, src = Normalizer(), source_from_id("docker:web-1")
    line = "2026-11-17T22:50:01 INFO started"
    docker_time = datetime(2026, 11, 17, 22, 50, 1, 500_000, tzinfo=UTC)
    assert normalize(src, RawRecord(src.id, line, docker_time)).timestamp == docker_time
    assert normalize(src, RawRecord(src.id, line)).timestamp.minute == 50  # no Docker time


def test_normalizer_severity_precedence() -> None:
    normalize, src = Normalizer(), source_from_id("systemd:x.service")
    journal = RawRecord(src.id, "level=debug msg=x a=b", severity=Severity.ERROR)
    assert normalize(src, journal).severity is Severity.DEBUG  # line's own level wins
    assert normalize(src, RawRecord(src.id, "failed", severity=Severity.NOTICE)).severity is (
        Severity.NOTICE
    )
    assert normalize(src, RawRecord(src.id, "it failed")).severity is Severity.ERROR  # inferred
    assert normalize(src, RawRecord(src.id, "hello")).severity is Severity.INFO
    trace = "boom\nTraceback (most recent call last):\n  File \"x\", line 1\nKeyError: 'k'"
    assert normalize(src, RawRecord(src.id, trace)).fields["exception_type"] == "KeyError"


# --- multi-line assembler ---------------------------------------------------------------


def rec(msg: str, cursor: str | None = None, ts: datetime | None = None,
        source: str = "s") -> RawRecord:  # fmt: skip
    return RawRecord(source, msg, timestamp=ts, cursor=cursor)


def test_assembler_merges_and_keeps_last_cursor() -> None:
    a = MultilineAssembler()
    assert a.feed(rec("ERROR boom", "c1"), 0) == []
    assert a.feed(rec("  at frame", "c2"), 0) == []
    assert a.pending
    [event] = a.feed(rec("next", "c3"), 0)
    assert (event.message, event.cursor, event.fields["lines"]) == (
        "ERROR boom\n  at frame",
        "c2",
        2,
    )
    assert [r.message for r in a.flush()] == ["next"]
    assert not a.pending


def test_assembler_keeps_sources_apart_and_flushes_idle() -> None:
    a = MultilineAssembler(idle=5)
    a.feed(rec("a1", source="a"), 0)
    a.feed(rec("b1", source="b"), 1)
    assert a.feed(rec("  a2", source="a"), 2) == []  # continuation of a, not b
    assert a.flush_idle(5) == []
    assert [r.message for r in a.flush_idle(6)] == ["b1"]
    assert [r.message for r in a.flush_idle(7)] == ["a1\n  a2"]


def test_assembler_time_gap_and_caps() -> None:
    t0 = datetime(2026, 1, 1, tzinfo=UTC)
    a = MultilineAssembler(max_gap=2.0)
    a.feed(rec("x", ts=t0), 0)
    assert len(a.feed(rec("  late", ts=t0 + timedelta(seconds=3)), 0)) == 1  # too late
    small = MultilineAssembler(max_lines=3, max_chars=1000)
    out = [e for i in range(7) for e in small.feed(rec(f"  {i}" if i else "head"), 0)]
    out += small.flush()
    assert [len(e.message.split("\n")) for e in out] == [3, 3, 1]
    huge = MultilineAssembler(max_chars=100)
    out = huge.feed(rec("h" * 60), 0) + huge.feed(rec(" " + "c" * 60), 0) + huge.flush()
    assert len(out) == 2


def test_exception_fields_needs_a_trace() -> None:
    assert exception_fields("one line") == {}
    assert exception_fields("two\nplain lines") == {}
    assert exception_fields('Traceback (most recent call last):\n  File "x"') == {}


def test_log_text_cannot_forge_collector_or_normalizer_fields() -> None:
    src = source_from_id("systemd:web.service")
    line = (
        '{"msg":"hi","_PID":"1","_SYSTEMD_UNIT":"sshd.service","stream":"stdout",'
        '"truncated":true,"parser":"fake","lines":99,"timestamp_source":"ingest","ts":1794955801}'
    )
    trusted = {"_PID": "4242", "_SYSTEMD_UNIT": "web.service", "stream": "stderr"}
    entry = Normalizer()(src, RawRecord(src.id, line, fields=trusted))
    assert {k: entry.fields[k] for k in trusted} == trusted
    assert entry.fields["parser"] == "json"
    for reserved in ("truncated", "lines", "timestamp_source"):
        assert reserved not in entry.fields
