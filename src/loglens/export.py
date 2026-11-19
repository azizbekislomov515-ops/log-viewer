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


def write_entries(entries: Iterable[LogEntry], fmt: str, handle: TextIO) -> int:
    """Write ``entries`` in ``fmt`` (txt, json or csv); returns how many were written."""
    if fmt not in FORMATS:
        raise ValueError(f"unknown export format {fmt!r} (txt, json, csv)")
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
                    _csv_safe(data["message"]),
                    _csv_safe(data["raw"]),
                    fields,
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
            handle.write(f"{stamp} {entry.severity.name:<8} {entry.source_id} {entry.message}\n")
            count += 1
    return count


def _csv_safe(text: str) -> str:
    """Neutralize spreadsheet formulas: log text starting with = + - @ is data, not code."""
    return "'" + text if text[:1] in ("=", "+", "-", "@", "\t", "\r") else text


def incident_report(
    pairs: Sequence[tuple[LogEntry, Explanation | None]],
    names: Mapping[str, str],
    title: str = "Incident report",
) -> str:
    """Markdown bundling entries with their explanations (for tickets and chat)."""
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
        fence = "````" if "```" in entry.raw else "```"
        lines += [fence, entry.raw, fence, ""]
    return "\n".join(lines)


def _md(text: str) -> str:
    """Log-derived text in Markdown prose: keep it from turning into markup or links."""
    return text.replace("\\", "\\\\").replace("<", "&lt;").replace("[", "\\[").replace("`", "\\`")
