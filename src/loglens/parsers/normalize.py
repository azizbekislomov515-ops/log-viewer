"""Normalizer: RawRecord + its LogSource -> LogEntry, via the parser registry.

Precedence rules:

* **timestamp**: the time written in the line (parser) > the collector's source time
  (journald ``__REALTIME_TIMESTAMP``, Docker's receive time) > the host clock at ingest,
  which is flagged ``timestamp_source="ingest"`` so ordering by it is known to be weak.
* **severity**: the line's own level (parser) > the source's (journald ``PRIORITY``) >
  ERROR for an assembled stack trace > keyword inference > INFO.
* **message/raw**: ``raw`` is always the collected text (capped); ``message`` is the
  parser's cleaned message, or the raw text when nothing parsed it.
"""

from __future__ import annotations

from dataclasses import replace

from loglens.core.models import LogEntry, LogSource, RawRecord, Severity, utc_now
from loglens.parsers.base import ParserRegistry
from loglens.parsers.multiline import exception_fields
from loglens.parsers.severity import SeverityInferrer

#: Longest message kept; anything longer is cut and flagged ``truncated``.
MAX_MESSAGE_CHARS = 64 * 1024


class Normalizer:
    """Callable used by the pipeline and the CLI. Never raises for any record text."""

    def __init__(
        self,
        registry: ParserRegistry | None = None,
        inferrer: SeverityInferrer | None = None,
    ) -> None:
        if registry is None:
            from loglens.parsers import default_registry  # noqa: PLC0415 (import cycle)

            registry = default_registry()
        self._registry = registry
        self._inferrer = inferrer or SeverityInferrer()

    def __call__(self, source: LogSource, record: RawRecord) -> LogEntry:
        """Parse and normalize one record (see the module docstring for precedence)."""
        fields = dict(record.fields)
        if len(record.message) > MAX_MESSAGE_CHARS:
            record = replace(record, message=record.message[:MAX_MESSAGE_CHARS])
            fields["truncated"] = True
        text = record.message
        name, parsed = self._registry.parse(source, record)
        fields.update(parsed.fields)
        if name is not None:
            fields["parser"] = name
        trace = exception_fields(text) if "\n" in text else {}
        fields.update(trace)

        timestamp = parsed.timestamp or record.timestamp
        if timestamp is None:
            timestamp = utc_now()
            fields["timestamp_source"] = "ingest"
        message = text if parsed.message is None else parsed.message
        severity = parsed.severity if parsed.severity is not None else record.severity
        if severity is None and trace:
            severity = Severity.ERROR
        if severity is None:
            severity = self._inferrer.infer(message)
        return LogEntry(
            id=0,
            source_id=record.source_id,
            timestamp=timestamp,
            severity=Severity.INFO if severity is None else severity,
            message=message,
            raw=text,
            fields=fields,
            parsed=parsed.parsed,
        )
