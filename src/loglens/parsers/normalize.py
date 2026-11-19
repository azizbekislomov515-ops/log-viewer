"""Normalizer: RawRecord + its LogSource -> LogEntry, via the parser registry.

Precedence rules:

* **timestamp**: the time written in the line (parser) > the collector's source time
  (journald ``__REALTIME_TIMESTAMP``) > the host clock at ingest, which is flagged
  ``timestamp_source="ingest"`` so ordering by it is known to be weak. Exception: for
  Docker containers Docker's own per-line timestamp wins, because times written inside a
  container are usually naive and in the container's time zone, not the host's.
* **severity**: the line's own level (parser) > the source's (journald ``PRIORITY``) >
  ERROR for an assembled stack trace > keyword inference > INFO.
* **fields**: normalizer-computed (``parser``, ``truncated``, ``timestamp_source``) >
  collector fields (journald trusted ``_*`` fields, Docker ``stream``, assembler ``lines``)
  > exception fields > parser fields. Log text can't overwrite source metadata.
* **message/raw**: ``raw`` is always the collected text (capped); ``message`` is the
  parser's cleaned message, or the raw text when nothing parsed it.
"""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime

from loglens.core.models import LogEntry, LogSource, RawRecord, Severity, SourceKind, utc_now
from loglens.parsers.base import ParserRegistry
from loglens.parsers.multiline import exception_fields
from loglens.parsers.severity import SeverityInferrer

#: Field names only the normalizer, assembler or a collector may set: rules trust them
#: (``stream: events`` marks Docker's own lifecycle events), so log text must not claim them.
_RESERVED = frozenset({"parser", "truncated", "timestamp_source", "lines", "stream"})
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
        truncated = len(record.message) > MAX_MESSAGE_CHARS
        if truncated:
            record = replace(record, message=record.message[:MAX_MESSAGE_CHARS])
        text = record.message
        name, parsed = self._registry.parse(source, record)
        trace = exception_fields(text) if "\n" in text else {}
        # Precedence: what we computed > what the collector reported (journald's trusted
        # _PID/_SYSTEMD_UNIT, Docker's stream) > what the log line claims about itself.
        # A line must never be able to forge source metadata.
        claimed = {k: v for k, v in parsed.fields.items() if k not in _RESERVED}
        fields = {**claimed, **trace, **record.fields}
        if name is not None:
            fields["parser"] = name
        if truncated:
            fields["truncated"] = True

        # Docker stamps every line with its exact write time; the time written in the line
        # is often naive and in the container's time zone (usually UTC, not the host's).
        if source.kind is SourceKind.DOCKER_CONTAINER and record.timestamp is not None:
            timestamp: datetime | None = record.timestamp
        else:
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
