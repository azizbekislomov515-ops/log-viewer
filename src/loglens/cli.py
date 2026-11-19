"""``loglens-cli``: discover, tail, collect and search logs from the command line."""

from __future__ import annotations

import argparse
import asyncio
import dataclasses
import json
import logging
import math
import re
import signal
import sys
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime, timedelta
from enum import Enum, StrEnum
from pathlib import Path
from typing import Any, TextIO

from loglens.collectors import Collector, default_collectors, source_from_id
from loglens.collectors.discovery import Discoverer, default_discoverers
from loglens.core.models import Explanation, LogEntry, LogSource, RawRecord, SourceKind
from loglens.core.pipeline import IngestPipeline
from loglens.core.registry import SourceRegistry
from loglens.explain import ExplanationEngine, load_rules
from loglens.explain.examples import run_examples
from loglens.explain.insights import analyze
from loglens.parsers import MultilineAssembler, Normalizer
from loglens.parsers.multiline import assemble_stream
from loglens.storage import Storage, StorageError, default_db_path

_MAX_NAME_WIDTH = 40
# C0 controls, DEL and C1 controls -> "?" so log-derived text can't drive the terminal.
_CONTROL_CHARS = dict.fromkeys([*range(0x20), *range(0x7F, 0xA0)], "?")


def main(argv: Sequence[str] | None = None) -> int:  # noqa: PLR0911 (command dispatch)
    """Entry point for the ``loglens-cli`` script."""
    parser = argparse.ArgumentParser(prog="loglens-cli", description=__doc__)
    parser.add_argument("-v", "--verbose", action="store_true", help="log diagnostics to stderr")
    sub = parser.add_subparsers(dest="command", required=True)

    sources = sub.add_parser("sources", help="list discovered log sources grouped by service")
    sources.add_argument("--json", action="store_true", help="print JSON instead of a table")

    tail = sub.add_parser("tail", help="print a source's lines (does not store them)")
    tail.add_argument("source_id", help="e.g. systemd:nginx.service, docker:web-1, file:/var/log/x")
    tail.add_argument("--since", type=_since_arg, help="10m, 2h, 1d, or an ISO date/time")
    tail.add_argument("-n", "--lines", type=int, default=10, help="backlog lines (default 10)")
    tail.add_argument("-f", "--follow", action="store_true", help="keep printing new lines")
    tail.add_argument("--fields", action="store_true", help="also print parsed fields")

    collect = sub.add_parser("collect", help="collect sources into the database until Ctrl-C")
    collect.add_argument("source_ids", nargs="+", metavar="source_id")
    collect.add_argument("--db", type=Path, help="database path (default: XDG data dir)")

    search = sub.add_parser("search", help="full-text search collected entries")
    search.add_argument("text")
    search.add_argument("--source", action="append", default=[], help="limit to a source id")
    search.add_argument("--limit", type=int, default=50)
    search.add_argument("--db", type=Path, help="database path (default: XDG data dir)")

    explain = sub.add_parser("explain", help="explain each line of a log file in plain language")
    explain.add_argument("--file", type=Path, required=True, help="log file to read")
    explain.add_argument(
        "--source",
        help="rule pack name (squid, clamav, ...) or a source id the lines come from "
        "(default: file:<path>)",
    )
    explain.add_argument("--rules", type=Path, help="rules directory (default: rules/)")

    rules = sub.add_parser("rules", help="check rule packs")
    rules_sub = rules.add_subparsers(dest="rules_command", required=True)
    lint = rules_sub.add_parser("lint", help="validate packs; report problems with file:line")
    lint.add_argument("--rules", type=Path, help="rules directory (default: rules/)")
    test = rules_sub.add_parser("test", help="run every rule's examples")
    test.add_argument("--rules", type=Path, help="rules directory (default: rules/)")
    test.add_argument("--pack", action="append", help="only this pack (repeatable)")

    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO if args.verbose else logging.WARNING)
    try:
        match args.command:
            case "sources":
                return cmd_sources(default_discoverers(), as_json=args.json, out=sys.stdout)
            case "tail":
                return asyncio.run(
                    cmd_tail(
                        args.source_id,
                        default_collectors(),
                        since=args.since,
                        lines=args.lines,
                        follow=args.follow,
                        fields=args.fields,
                        out=sys.stdout,
                    )
                )
            case "collect":
                return asyncio.run(
                    cmd_collect(args.source_ids, args.db or default_db_path(), out=sys.stdout)
                )
            case "explain":
                return cmd_explain(args.file, args.source, args.rules, out=sys.stdout)
            case "rules" if args.rules_command == "lint":
                return cmd_rules_lint(args.rules, out=sys.stdout)
            case "rules":
                return cmd_rules_test(args.rules, args.pack, out=sys.stdout)
            case _:
                return cmd_search(
                    args.text,
                    args.db or default_db_path(),
                    source_ids=args.source,
                    limit=args.limit,
                    out=sys.stdout,
                )
    except KeyboardInterrupt:
        return 130
    except (ValueError, StorageError) as exc:
        print(f"loglens-cli: error: {exc}", file=sys.stderr)
        return 2


async def cmd_tail(
    source_id: str,
    collectors: Mapping[SourceKind, Collector],
    *,
    since: datetime | None,
    lines: int,
    follow: bool,
    out: TextIO,
    fields: bool = False,
) -> int:
    """Stream a source straight from its collector, parsed (nothing is stored)."""
    source = source_from_id(source_id)
    if since is not None and source.kind is SourceKind.FILE:
        print("note: files can't be read from a point in time; --since is ignored, "
              f"showing the last {lines} lines", file=sys.stderr)  # fmt: skip

    def warn(_: str, exc: BaseException) -> None:
        print(f"warning: {exc} (retrying)", file=sys.stderr)

    stream = collectors[source.kind].stream(
        source, since=since, lines=lines, follow=follow, on_error=warn
    )
    normalize = Normalizer()
    try:
        async for record in assemble_stream(stream, MultilineAssembler()):
            out.write(format_entry(normalize(source, record), with_fields=fields))
            out.flush()
    except Exception as exc:  # non-follow mode raises instead of retrying
        print(f"loglens-cli: error: {exc}", file=sys.stderr)
        return 1
    return 0


async def cmd_collect(source_ids: Sequence[str], db_path: Path, *, out: TextIO) -> int:
    """Collect sources into the database, printing entries as they are stored."""
    sources = [source_from_id(s) for s in source_ids]
    with Storage(db_path) as storage:
        async with IngestPipeline(storage, default_collectors()) as pipeline:

            def show(entries: Sequence[LogEntry]) -> None:
                out.writelines(format_entry(e, with_source=True) for e in entries)
                out.flush()

            pipeline.subscribe(show)
            for source in sources:
                pipeline.add_source(source)
            stop = asyncio.Event()
            loop = asyncio.get_running_loop()
            for sig in (signal.SIGINT, signal.SIGTERM):  # flush and exit cleanly on both
                loop.add_signal_handler(sig, stop.set)
            print(f"collecting {len(sources)} source(s) into {db_path}; Ctrl-C to stop",
                  file=sys.stderr)  # fmt: skip
            await stop.wait()
    print(f"stopped; {pipeline.stats.stored} entries stored", file=sys.stderr)
    return 0


def cmd_search(
    text: str, db_path: Path, *, source_ids: Sequence[str], limit: int, out: TextIO
) -> int:
    """Print stored entries matching ``text``, newest first."""
    if not db_path.exists():
        print(f"no database at {db_path}; run 'loglens-cli collect' first", file=sys.stderr)
        return 1
    with Storage(db_path) as storage:
        results = storage.search(text, source_ids=source_ids, limit=limit)
    out.writelines(format_entry(e, with_source=True) for e in results)
    if not results:
        print("no matches", file=sys.stderr)
    return 0


def cmd_explain(path: Path, source: str | None, rules_dir: Path | None, *, out: TextIO) -> int:
    """Parse and explain every line of ``path``, then print a summary of the whole file.

    ``source`` is a pack name (use only that pack, parse lines as its example source) or a
    source id (all packs); by default the file is its own source (``file:<abs path>``).
    """
    if source is not None and ":" not in source:
        engine = ExplanationEngine.from_directory(rules_dir, packs=[source])
        if not engine.packs:
            raise ValueError(f"no rule pack named {source!r}; see 'loglens-cli rules lint'")
        source_id = engine.packs[0].example_source
    else:
        engine = ExplanationEngine.from_directory(rules_dir)
        source_id = source or f"file:{path.resolve()}"
    log_source = source_from_id(source_id)
    if source is not None and ":" not in source:  # parse like the pack's source, label as the file
        log_source = dataclasses.replace(log_source, id=f"file:{path.resolve()}")
        source_id = log_source.id
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        print(f"loglens-cli: error: {exc}", file=sys.stderr)
        return 1
    assembler, normalize = MultilineAssembler(), Normalizer()
    records = [RawRecord(source_id, line) for line in text.splitlines()]
    events = [e for r in records for e in assembler.feed(r, 0.0)] + assembler.flush()
    entries: list[LogEntry] = []
    explained = 0
    for record in events:
        # A line without its own timestamp happened "at" the previous line, not at ingest.
        stamp = entries[-1].timestamp if entries else None
        entry = normalize(log_source, dataclasses.replace(record, timestamp=stamp))
        entries.append(entry)
        explanation = engine.explain(entry, log_source)
        explained += explanation is not None
        out.write(format_entry(entry) + format_explanation(explanation))
    out.write(f"\n{explained} of {len(entries)} entries explained.\n")
    if entries:
        span = max(e.timestamp for e in entries) - min(e.timestamp for e in entries)
        window = timedelta(minutes=max(1, math.ceil(span / timedelta(minutes=1))))
        insights = analyze(entries, window=window, explain=lambda e: engine.explain(e, log_source))
        out.writelines(_safe(i.summary) + "\n" for i in insights.values())
    return 0


def format_explanation(explanation: Explanation | None) -> str:
    """The indented explanation block printed under an entry."""
    if explanation is None:
        return "    (no explanation available)\n\n"
    e = explanation
    lines = [
        f"    => {e.title}  [{e.severity_assessment.name.lower()}, {e.category.value}]",
        f"       {e.plain_text}",
    ]
    if e.probable_cause:
        lines.append(f"       Probable cause: {e.probable_cause}")
    if e.suggested_action:
        lines.append(f"       Next step: {e.suggested_action}")
    if e.references:
        lines.append(f"       See: {', '.join(e.references)}")
    return "".join(_safe(line) + "\n" for line in lines) + "\n"


def cmd_rules_lint(rules_dir: Path | None, *, out: TextIO) -> int:
    """Load every pack and print each problem as ``file:line: message``. 1 if any."""
    ruleset = load_rules(rules_dir)
    for issue in ruleset.issues:
        out.write(_safe(str(issue)) + "\n")
    rules = len(ruleset.rules)
    out.write(f"{len(ruleset.packs)} packs, {rules} rules, {len(ruleset.issues)} problems\n")
    return 1 if ruleset.issues else 0


def cmd_rules_test(rules_dir: Path | None, packs: Sequence[str] | None, *, out: TextIO) -> int:
    """Run every rule's examples (all packs loaded, so shadowing shows up). 1 on failure."""
    engine = ExplanationEngine(load_rules(rules_dir))
    for issue in engine.issues:
        out.write(_safe(f"load: {issue}") + "\n")
    report = run_examples(engine, packs)
    for failure in report.failures:
        out.writelines(_safe(line) + "\n" for line in str(failure).split("\n"))
    out.write(
        f"{report.rules} rules, {report.examples} examples, {len(report.failures)} failures\n"
    )
    return 1 if report.failures or engine.issues or not report.rules else 0


def format_entry(entry: LogEntry, *, with_source: bool = False, with_fields: bool = False) -> str:
    """One terminal line per entry (continuation lines of a multi-line event indented,
    parsed fields on an extra line if asked); control characters neutralized."""
    stamp = entry.timestamp.astimezone().strftime("%Y-%m-%d %H:%M:%S")
    source = f" [{entry.source_id}]" if with_source else ""
    stream = " (stderr)" if entry.fields.get("stream") == "stderr" else ""
    head = _safe(f"{stamp} {entry.severity.name:<8}{source}{stream} ")
    lines = [_safe(line) for line in entry.message.split("\n")]
    text = head + "\n    ".join(lines) + "\n"
    if with_fields:
        shown = " ".join(
            f"{key}={_field_text(value)}"
            for key, value in sorted(entry.fields.items())
            if not _is_journal_field(key)
        )
        if shown:
            text += _safe(f"    {{{shown}}}") + "\n"
    return text


def _is_journal_field(key: str) -> bool:
    """journald's own fields (``_PID``, ``SYSLOG_IDENTIFIER``): always upper case."""
    return key.startswith("_") or key.isupper()


def _field_text(value: Any) -> str:
    text = value if isinstance(value, str) else json.dumps(value, default=str)
    return json.dumps(text) if not text or any(c in text for c in ' "=') else text


_SINCE_RE = re.compile(r"^(\d+)\s*([smhdw])$")
_UNITS = {"s": "seconds", "m": "minutes", "h": "hours", "d": "days", "w": "weeks"}


def parse_since(text: str, now: datetime | None = None) -> datetime:
    """``10m``/``2h``/``1d``/``1w``/``30s`` ago, or an ISO date/time (local if naive).

    Raises:
        ValueError: if ``text`` is neither.
    """
    if match := _SINCE_RE.match(text.strip()):
        delta = timedelta(**{_UNITS[match[2]]: int(match[1])})
        return (now or datetime.now(UTC)) - delta
    try:
        moment = datetime.fromisoformat(text.strip())
    except ValueError:
        raise ValueError(f"invalid time {text!r}: use 10m, 2h, 1d or an ISO date/time") from None
    return moment if moment.tzinfo else moment.astimezone()


def _since_arg(text: str) -> datetime:
    try:
        return parse_since(text)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from None


def cmd_sources(discoverers: Sequence[Discoverer], *, as_json: bool, out: TextIO) -> int:
    """Run discovery once and print the result."""
    registry = SourceRegistry(discoverers)
    registry.refresh()
    if as_json:
        payload = {"groups": registry.groups, "issues": registry.issues}
        json.dump(payload, out, default=_to_json, indent=2)
        out.write("\n")
    else:
        out.write(render_table(registry))
    return 0


def render_table(registry: SourceRegistry) -> str:
    """Human-readable listing: one block per group, then issues with hints."""
    names = [s.display_name for g in registry.groups for s in g.sources]
    width = min(max(map(len, names), default=10), _MAX_NAME_WIDTH)
    lines: list[str] = []
    for group in registry.groups:
        n = len(group.sources)
        lines.append(f"{group.name}  [{group.kind.value}, {n} source{'s' * (n != 1)}]")
        for s in group.sources:
            name = s.display_name[:width].ljust(width)
            lines.append(f"  {name}  {s.status.value:<8}  {_detail(s)}".rstrip())
        lines.append("")
    if not registry.groups:
        lines += ["No log sources found.", ""]
    if registry.issues:
        lines.append("Issues:")
        for issue in registry.issues:
            lines.append(f"  [{issue.severity.name.lower()}] {issue.discoverer}: {issue.message}")
            if issue.hint:
                lines.append(f"      -> {issue.hint}")
    return "\n".join(_safe(line) for line in lines).rstrip() + "\n"


def _safe(text: str) -> str:
    """Neutralize terminal escape sequences in untrusted text (labels, stderr, descriptions)."""
    return text.translate(_CONTROL_CHARS)


def _detail(source: LogSource) -> str:
    meta = source.metadata
    match source.kind:
        case SourceKind.SYSTEMD:
            return str(meta.get("description", ""))
        case SourceKind.DOCKER_CONTAINER:
            return f"{meta.get('image', '')}  ({meta.get('state', '')})"
        case SourceKind.FILE:
            return str(meta.get("path", "")) + ("" if meta.get("readable") else "  [not readable]")


def _to_json(obj: Any) -> Any:
    if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
        return {f.name: _plain(getattr(obj, f.name)) for f in dataclasses.fields(obj)}
    if isinstance(obj, datetime):
        return obj.isoformat()
    if hasattr(obj, "items"):  # MappingProxyType
        return dict(obj)
    raise TypeError(f"not JSON serializable: {type(obj).__name__}")


def _plain(value: Any) -> Any:
    if isinstance(value, StrEnum):
        return value.value
    if isinstance(value, Enum):
        return value.name.lower()
    return value


if __name__ == "__main__":
    sys.exit(main())
