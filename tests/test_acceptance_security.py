"""Phase 7 acceptance: hostile input end to end, and startup without privileges.

1. One crafted log line (terminal escapes, 10 MB of text, a ReDoS payload, Jinja
   injection, fake secrets) goes through the real file collector, pipeline, redactor,
   storage, explanation engine (built-in packs plus a hostile user pack), GUI model and
   every export. Nothing crashes or hangs, nothing is evaluated, and no secret reaches the
   database file, its WAL or any export.
2. The GUI starts as a user without journal, Docker or file access and lists exact fixes.
"""

from __future__ import annotations

import asyncio
import io
import json
import time
from pathlib import Path

import pytest
from pytestqt.qtbot import QtBot

from loglens.collectors import source_from_id
from loglens.collectors.discovery.base import CommandResult
from loglens.collectors.discovery.containers import DockerDiscoverer
from loglens.collectors.discovery.files import FileDiscoverer
from loglens.collectors.discovery.systemd import SystemdDiscoverer
from loglens.collectors.files import FileCollector
from loglens.config import Settings
from loglens.core.models import SourceKind
from loglens.core.pipeline import IngestPipeline, PipelineLimits
from loglens.explain import DEFAULT_RULES_DIR, ExplanationEngine
from loglens.export import incident_report, write_entries
from loglens.gui.app import launch
from loglens.gui.log_model import Column, LogTableModel
from loglens.gui.workers import SyncWorker
from loglens.security.privileges import journal_access_issue
from loglens.security.redact import Redactor
from loglens.storage import EntryQuery, Storage

SECRETS = (
    "Hunter2Secret!",
    "AKIAIOSFODNN7EXAMPLE",
    "abcdef1234567890abcdef",
    "4111 1111 1111 1111",
    "ghp_1234567890abcdefghijklmnopqrstuvwxyzAB",
)
HOSTILE = (
    "\x1b[2J\x1b[H\x1b[31mERROR\x1b[0m \x1b]0;pwned\x07\x1b]8;;http://evil.example\x07click"
    "\x1b]8;;\x07 \u202egnp.exe\u202c "
    "{{ 7*191 }} {{ ''.__class__.__mro__[1].__subclasses__() }} "
    "{% for x in range(99999999) %}x{% endfor %} "
    f"login password={SECRETS[0]} Authorization: Bearer {SECRETS[2]} key {SECRETS[1]} "
    f"card {SECRETS[3]} token {SECRETS[4]} "
    + "a" * 40
    + "! "  # (a|aa)+$ backtracks exponentially on this
    + "x" * (10 * 1024 * 1024)
)
USER_PACK = """\
pack: hostile
version: 1
example_source: file:/var/log/app.log
rules:
  - id: hostile.redos
    title: slow
    match: {regex: '(a|aa)+$'}
    template: slow rule matched
    category: security
    examples: [{line: aaa, expect: {text: slow}}]
    counter_examples: [b]
  - id: hostile.echo
    title: "Saw {{ word }}"
    match: {regex: 'login (?P<word>\\S+)'}
    template: "The line said {{ message }}"
    category: security
    examples: [{line: login x, expect: {text: said}}]
    counter_examples: [b]
"""


def _all_bytes(db: Path) -> bytes:
    return b"".join(p.read_bytes() for p in db.parent.iterdir() if p.name.startswith(db.name))


async def _ingest(log: Path, db: Path) -> int:
    with Storage(db) as storage:
        limits = PipelineLimits(queue_size=64, batch_size=16, flush_interval=0.01)
        collectors = {SourceKind.FILE: FileCollector(use_inotify=False)}
        async with IngestPipeline(
            storage, collectors, limits=limits, redactor=Redactor()
        ) as pipeline:
            pipeline.add_source(source_from_id(f"file:{log}"), lines=100)
            async with asyncio.timeout(20):
                while pipeline.stats.stored < 3:
                    await asyncio.sleep(0.05)
            return pipeline.stats.redacted


def test_hostile_line_end_to_end(tmp_path: Path, qtbot: QtBot) -> None:
    log, db = tmp_path / "app.log", tmp_path / "data" / "loglens.db"
    log.write_text(f"normal start\n{HOSTILE}\nnormal end\n", encoding="utf-8")
    started = time.perf_counter()

    assert asyncio.run(_ingest(log, db)) >= 1
    raw = _all_bytes(db)
    for secret in SECRETS:  # not in the database file, the WAL or the shared memory
        assert secret.encode() not in raw, secret

    with Storage(db) as storage:
        entries = storage.tail(f"file:{log}", limit=10)
        assert [e.message for e in entries][0::2] == ["normal start", "normal end"]
        hostile = entries[1]
        assert hostile.fields.get("truncated") is True  # 10 MB capped at the collector
        assert len(hostile.raw) <= 64 * 1024
        assert "[REDACTED:password]" in hostile.message

        packs = tmp_path / "packs"
        packs.mkdir()
        (packs / "hostile.yaml").write_text(USER_PACK)
        engine = ExplanationEngine.from_directory([DEFAULT_RULES_DIR, packs])
        assert not engine.issues, engine.issues
        t0 = time.perf_counter()
        explanations = [engine.explain(e) for e in entries for _ in range(5)]
        assert time.perf_counter() - t0 < 2.0  # the ReDoS rule times out, nothing hangs
        rendered = " ".join(f"{x.title} {x.plain_text}" for x in explanations if x is not None)
        assert "{{ 7*191 }}" in rendered  # the echo rule shows the line as text...
        assert "1337" not in rendered and "<class" not in rendered  # ...never evaluated

        model = LogTableModel(SyncWorker(storage), EntryQuery(source_ids=(f"file:{log}",)))
        model.reload()
        assert model.rowCount() == 3
        shown = model.data(model.index(1, Column.MESSAGE))
        assert isinstance(shown, str)
        assert "\x1b" not in shown and "\x07" not in shown and "\u202e" not in shown

        outputs = {}
        for fmt in ("txt", "csv", "json"):
            out = io.StringIO()
            assert write_entries(entries, fmt, out) == 3
            outputs[fmt] = out.getvalue()
        outputs["report"] = incident_report(
            [(e, engine.explain(e)) for e in entries], {}, "Incident"
        )
    json.loads(outputs["json"])
    for name, text in outputs.items():
        for secret in SECRETS:
            assert secret not in text, (name, secret)
        assert "\x1b" not in text and "\x07" not in text, name
        if name != "json":
            assert "\u202e" not in text, name
    assert time.perf_counter() - started < 60


def test_starts_unprivileged_and_shows_exact_fixes(
    qtbot: QtBot, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("DOCKER_HOST", "unix:///nonexistent/docker.sock")
    secret_log = tmp_path / "squid" / "access.log"
    secret_log.parent.mkdir()
    secret_log.write_text("x\n")
    secret_log.chmod(0o000)
    catalog = tmp_path / "catalog.yaml"
    catalog.write_text(
        "version: 1\ngroups:\n  - id: squid\n    name: Squid\n    files:\n"
        f"      - name: access\n        paths: [{secret_log}]\n"
    )
    systemd = SystemdDiscoverer(
        lambda cmd: CommandResult(0, "[]", ""),
        journal_check=lambda: journal_access_issue({"users"}, euid=1000),
    )
    launched = launch(
        settings=Settings(theme="dark", discovery_interval_s=3600),
        db_path=tmp_path / "db.sqlite",
        discoverers=[systemd, DockerDiscoverer(), FileDiscoverer(catalog)],
    )
    try:
        window = launched.window
        window.show()
        qtbot.waitUntil(lambda: window.issues_panel.count >= 3, timeout=20_000)
        text = "\n".join(
            window.issues_panel.list.item(i).text() for i in range(window.issues_panel.list.count())
        )
        assert "sudo usermod -aG systemd-journal $USER" in text
        assert "Cannot connect to the Docker daemon" in text
        assert "setfacl -m u:$USER:r" in text
        assert window.isVisible()
    finally:
        secret_log.chmod(0o600)
        launched.close()
