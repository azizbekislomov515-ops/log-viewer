"""The loglens-helper wire protocol, version 1.

Newline-delimited JSON over a Unix stream socket. Every message is one UTF-8 JSON object
on one line, at most ``MAX_MESSAGE`` bytes including the newline, carrying ``"v": 1``.
Both sides validate strictly: unknown keys, wrong types or another version are rejected,
and the connection is closed. One request per connection.

Requests (client -> helper)::

    {"v": 1, "op": "hello"}
    {"v": 1, "op": "stream", "source": "systemd:ssh.service",
     "cursor": null, "lines": 100, "follow": true}

Replies (helper -> client)::

    {"v": 1, "type": "hello", "server": "loglens-helper", "sources": ["systemd:..."]}
    {"v": 1, "type": "record", "message": "...", "cursor": "...", "ts": "<iso>",
     "severity": "ERROR", "fields": {"KEY": "value"}}
    {"v": 1, "type": "status", "message": "journalctl exited; reconnecting"}
    {"v": 1, "type": "end"}
    {"v": 1, "type": "error", "code": "not_allowed", "message": "..."}

The helper serves only sources its administrator listed (``/etc/loglens/helper.toml``),
and only read access exists: there is no operation that writes, deletes or runs
anything chosen by the client.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from loglens.core.models import RawRecord, Severity

VERSION = 1
MAX_MESSAGE = 64 * 1024
#: Most history lines a stream request may ask for.
MAX_LINES = 10_000
MAX_FIELDS = 128
MAX_FIELD_KEY = 64
MAX_SOURCE_ID = 4096
#: Longest message text in a record (keeps every record under ``MAX_MESSAGE``).
MAX_RECORD_TEXT = 48 * 1024
SERVER_NAME = "loglens-helper"
ERROR_CODES = frozenset(
    {"bad_request", "too_large", "unsupported_version", "not_allowed", "unauthorized", "busy",
     "failed"}
)  # fmt: skip


class ProtocolError(ValueError):
    """A message that does not follow the protocol. ``code`` is sent to the peer."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True, slots=True)
class Hello:
    """Ask which sources this client may stream."""


@dataclass(frozen=True, slots=True)
class StreamRequest:
    """Stream one allowed source (see ``Collector.stream`` for the start position)."""

    source: str
    cursor: str | None = None
    lines: int = 0
    follow: bool = True


Request = Hello | StreamRequest


def encode(message: dict[str, Any]) -> bytes:
    """One protocol line (adds ``v``); raises ProtocolError if it is too large."""
    data = json.dumps({"v": VERSION, **message}, ensure_ascii=False, separators=(",", ":"))
    line = data.encode("utf-8") + b"\n"
    if len(line) > MAX_MESSAGE:
        raise ProtocolError("too_large", f"message of {len(line)} bytes exceeds {MAX_MESSAGE}")
    return line


def _object(line: bytes) -> dict[str, Any]:
    if len(line) > MAX_MESSAGE:
        raise ProtocolError("too_large", f"message exceeds {MAX_MESSAGE} bytes")
    try:
        obj = json.loads(line.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise ProtocolError("bad_request", "not a UTF-8 JSON line") from None
    if not isinstance(obj, dict):
        raise ProtocolError("bad_request", "a message must be a JSON object")
    if obj.get("v") != VERSION or type(obj.get("v")) is not int:
        raise ProtocolError("unsupported_version", f"protocol version {VERSION} expected")
    return obj


def _keys(obj: dict[str, Any], required: set[str], optional: set[str] = frozenset()) -> None:  # type: ignore[assignment]
    keys = set(obj) - {"v"}
    if missing := required - keys:
        raise ProtocolError("bad_request", f"missing {sorted(missing)}")
    if extra := keys - required - optional:
        raise ProtocolError("bad_request", f"unknown {sorted(extra)}")


def _text(obj: dict[str, Any], key: str, limit: int, *, nullable: bool = False) -> str | None:
    value = obj.get(key)
    if value is None and nullable:
        return None
    if not isinstance(value, str) or len(value) > limit:
        raise ProtocolError("bad_request", f"'{key}' must be a string of at most {limit} chars")
    return value


def decode_request(line: bytes) -> Request:
    """Parse and validate one request line."""
    obj = _object(line)
    op = obj.get("op")
    if op == "hello":
        _keys(obj, {"op"})
        return Hello()
    if op == "stream":
        _keys(obj, {"op", "source"}, {"cursor", "lines", "follow"})
        lines, follow = obj.get("lines", 0), obj.get("follow", True)
        if type(lines) is not int or not 0 <= lines <= MAX_LINES:
            raise ProtocolError("bad_request", f"'lines' must be an integer 0..{MAX_LINES}")
        if type(follow) is not bool:
            raise ProtocolError("bad_request", "'follow' must be true or false")
        source = _text(obj, "source", MAX_SOURCE_ID) or ""
        return StreamRequest(source, _text(obj, "cursor", 1024, nullable=True), lines, follow)
    raise ProtocolError("bad_request", "'op' must be 'hello' or 'stream'")


def encode_request(request: Request) -> bytes:
    """The line a client sends."""
    if isinstance(request, Hello):
        return encode({"op": "hello"})
    return encode(
        {"op": "stream", "source": request.source, "cursor": request.cursor,
         "lines": request.lines, "follow": request.follow}
    )  # fmt: skip


def record_message(record: RawRecord) -> dict[str, Any]:
    """A record reply; long text is cut so the line always fits."""
    fields = {
        k[:MAX_FIELD_KEY]: v[:1024] if isinstance(v, str) else v
        for k, v in list(record.fields.items())[:MAX_FIELDS]
        if isinstance(v, str | int | float | bool) or v is None
    }
    return {
        "type": "record",
        "message": record.message[:MAX_RECORD_TEXT],
        "cursor": record.cursor,
        "ts": record.timestamp.isoformat() if record.timestamp else None,
        "severity": record.severity.name if record.severity is not None else None,
        "fields": fields,
    }


def decode_reply(line: bytes) -> dict[str, Any]:
    """Parse and validate one reply line (the client trusts the helper no more than
    any other input)."""
    obj = _object(line)
    kind = obj.get("type")
    if kind == "hello":
        _keys(obj, {"type", "server", "sources"})
        sources = obj["sources"]
        if not isinstance(sources, list) or not all(
            isinstance(s, str) and len(s) <= MAX_SOURCE_ID for s in sources
        ):
            raise ProtocolError("bad_request", "'sources' must be a list of source ids")
    elif kind == "record":
        _keys(obj, {"type", "message", "cursor", "ts", "severity", "fields"})
        _text(obj, "message", MAX_RECORD_TEXT)
        _text(obj, "cursor", 1024, nullable=True)
        _text(obj, "ts", 64, nullable=True)
        severity = _text(obj, "severity", 16, nullable=True)
        if severity is not None and severity not in Severity.__members__:
            raise ProtocolError("bad_request", "unknown severity")
        fields = obj["fields"]
        if not isinstance(fields, dict) or len(fields) > MAX_FIELDS or not all(
            isinstance(k, str) and len(k) <= MAX_FIELD_KEY
            and (isinstance(v, str | int | float | bool) or v is None)
            for k, v in fields.items()
        ):  # fmt: skip
            raise ProtocolError("bad_request", "'fields' must map short names to scalars")
    elif kind == "status":
        _keys(obj, {"type", "message"})
        _text(obj, "message", 1024)
    elif kind == "end":
        _keys(obj, {"type"})
    elif kind == "error":
        _keys(obj, {"type", "code", "message"})
        if obj["code"] not in ERROR_CODES:
            raise ProtocolError("bad_request", "unknown error code")
        _text(obj, "message", 1024)
    else:
        raise ProtocolError("bad_request", "unknown reply type")
    return obj


def record_from_reply(reply: dict[str, Any], source_id: str) -> RawRecord:
    """The RawRecord a validated ``record`` reply describes (for ``source_id``: the
    client's own idea of the source, never the helper's)."""
    try:
        ts = datetime.fromisoformat(reply["ts"]) if reply["ts"] else None
    except ValueError:
        ts = None
    if ts is not None and ts.tzinfo is None:
        ts = None
    severity = Severity[reply["severity"]] if reply["severity"] else None
    return RawRecord(source_id, reply["message"], ts, severity, reply["fields"], reply["cursor"])
