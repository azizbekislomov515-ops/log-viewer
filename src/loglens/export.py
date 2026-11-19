"""Export entries as text / JSON / CSV, and incident reports as Markdown.

Writers stream to an open text handle, so a million-entry export never holds the whole
file in memory (the GUI runs them on a worker thread).
"""

from __future__ import annotations

import csv
import json
from collections.abc import Iterable, Mapping, Sequence
from typing import Any, TextIO

from loglens.core.models import Explanation, LogEntry
from loglens.security.redact import Redactor
from loglens.security.text import printable

FORMATS: Mapping[str, str] = {"txt": "Text", "json": "JSON", "csv": "CSV"}
CSV_COLUMNS = ("time", "source", "severity", "message", "raw", "fields")


def entry_dict(entry: LogEntry) -> dict[str, Any]:
    """The JSON shape of one entry."""
    return {
        "id": entry.id,
        "time": entry.timestamp.isoformat(),
        "source": entry.source_id,
        "severity": entry.severity.name.lower(),
        "message": entry.message,
        "raw": entry.raw,
        "fields": dict(entry.fields),
    }


def write_entries(
    entries: Iterable[LogEntry], fmt: str, handle: TextIO, redactor: Redactor | None = None
) -> int:
    """Write ``entries`` in ``fmt`` (txt, json or csv); returns how many were written.

    Entries are redacted again (defence in depth: stored entries already are), and text
    formats get terminal escapes and control characters neutralized, so ``cat``-ing an
    export cannot drive a terminal. JSON escapes control characters itself.
    """
    if fmt not in FORMATS:
        raise ValueError(f"unknown export format {fmt!r} (txt, json, csv)")
    redactor = redactor or Redactor()
    entries = (redactor.redact_entry(e) for e in entries)
    count = 0
    if fmt == "csv":
        writer = csv.writer(handle)
        writer.writerow(CSV_COLUMNS)
        for entry in entries:
            data = entry_dict(entry)
            fields = json.dumps(data["fields"], ensure_ascii=False, default=str)
            writer.writerow(
                [
                    data["time"],
                    data["source"],
                    data["severity"],
                    _csv_safe(printable(data["message"])),
                    _csv_safe(printable(data["raw"])),
                    printable(fields),
                ]
            )
            count += 1
    elif fmt == "json":
        handle.write("[")
        for entry in entries:
            handle.write(",\n  " if count else "\n  ")
            handle.write(json.dumps(entry_dict(entry), ensure_ascii=False, default=str))
            count += 1
        handle.write("\n]\n" if count else "]\n")
    else:
        for entry in entries:
            stamp = entry.timestamp.astimezone().isoformat(timespec="milliseconds")
            text = printable(entry.message).replace("\n", "\n    ")
            handle.write(f"{stamp} {entry.severity.name:<8} {printable(entry.source_id)} {text}\n")
            count += 1
    return count


def _csv_safe(text: str) -> str:
    """Neutralize spreadsheet formulas: log text starting with = + - @ is data, not code."""
    return "'" + text if text[:1] in ("=", "+", "-", "@", "\t", "\r") else text


def incident_report(
    pairs: Sequence[tuple[LogEntry, Explanation | None]],
    names: Mapping[str, str],
    title: str = "Incident report",
    redactor: Redactor | None = None,
) -> str:
    """Markdown bundling entries with their explanations (for tickets and chat).

    Entries are redacted again and control characters neutralized (a report is pasted
    into chats and terminals)."""
    redactor = redactor or Redactor()
    pairs = [(redactor.redact_entry(e), x) for e, x in pairs]
    if not pairs:
        return f"# {title}\n\nNo entries selected.\n"
    entries = [e for e, _ in pairs]
    first, last = min(e.timestamp for e in entries), max(e.timestamp for e in entries)
    sources = sorted({names.get(e.source_id, e.source_id) for e in entries})
    lines = [
        f"# {title}",
        "",
        f"- **When:** {first.astimezone():%Y-%m-%d %H:%M:%S} to {last.astimezone():%H:%M:%S %Z}",
        f"- **Sources:** {', '.join(sources)}",
        f"- **Entries:** {len(pairs)} ({sum(1 for _, x in pairs if x)} explained)",
        "",
    ]
    for entry, exp in pairs:
        name = names.get(entry.source_id, entry.source_id)
        stamp = entry.timestamp.astimezone().strftime("%H:%M:%S")
        heading = exp.title if exp else "No explanation available"
        lines += [f"## {stamp} · {entry.severity.name} · {name}: {_md(heading)}", ""]
        if exp is not None:
            lines.append(_md(exp.plain_text))
            if exp.probable_cause:
                lines.append(f"\n- **Probable cause:** {_md(exp.probable_cause)}")
            if exp.suggested_action:
                lines.append(f"- **Next step:** {_md(exp.suggested_action)}")
            lines.append("")
        raw = printable(entry.raw)
        fence = "`" * max(3, _longest_run(raw, "`") + 1)  # the line cannot close it
        lines += [fence, raw, fence, ""]
    return "\n".join(lines)


def _longest_run(text: str, char: str) -> int:
    longest = current = 0
    for c in text:
        current = current + 1 if c == char else 0
        longest = max(longest, current)
    return longest


def _md(text: str) -> str:
    """Log-derived text in Markdown prose: keep it from turning into markup or links."""
    text = printable(text, keep_newlines=False)
    return text.replace("\\", "\\\\").replace("<", "&lt;").replace("[", "\\[").replace("`", "\\`")
