"""Client side of loglens-helper, and the collector wrapper that uses it.

``HelperFallback`` wraps LogLens's own journald/file collectors: if this user cannot
read a source (not in ``systemd-journal``; file not readable) and the helper's socket
exists, the source is streamed through the helper instead. Otherwise nothing changes.
"""

from __future__ import annotations

import asyncio
import os
import stat
from collections.abc import AsyncIterator, Callable
from datetime import datetime
from functools import cache
from pathlib import Path

from loglens.collectors.base import Collector, CollectorError, ErrorCallback
from loglens.core.models import LogSource, RawRecord, SourceKind
from loglens.helper.protocol import (
    MAX_MESSAGE,
    Hello,
    ProtocolError,
    StreamRequest,
    decode_reply,
    encode_request,
    record_from_reply,
)
from loglens.helper.server import DEFAULT_SOCKET
from loglens.security.privileges import journal_access_issue

CONNECT_TIMEOUT_S = 5.0


class HelperClient:
    """Talks to the helper's Unix socket."""

    def __init__(self, socket_path: Path = DEFAULT_SOCKET) -> None:
        self.socket_path = socket_path

    def available(self) -> bool:
        """Whether the helper's socket exists."""
        try:
            return stat.S_ISSOCK(self.socket_path.stat().st_mode)
        except OSError:
            return False

    async def _open(
        self, request: Hello | StreamRequest
    ) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        reader, writer = await asyncio.wait_for(
            asyncio.open_unix_connection(str(self.socket_path), limit=MAX_MESSAGE),
            CONNECT_TIMEOUT_S,
        )
        writer.write(encode_request(request))
        await writer.drain()
        return reader, writer

    async def hello(self) -> list[str]:
        """Sources the helper will serve to this user."""
        reader, writer = await self._open(Hello())
        try:
            # Authorization may wait for a polkit password prompt.
            reply = await _read(reader, timeout=180)
        finally:
            writer.close()
        if reply is None or reply["type"] != "hello":
            raise CollectorError(_why(reply))
        return list(reply["sources"])

    async def stream(
        self,
        source: LogSource,
        *,
        cursor: str | None = None,
        lines: int = 0,
        follow: bool = True,
        on_error: ErrorCallback | None = None,
    ) -> AsyncIterator[RawRecord]:
        """Records of ``source`` through the helper."""
        request = StreamRequest(source.id, cursor, min(lines, 10_000), follow)
        reader, writer = await self._open(request)
        try:
            while True:
                reply = await _read(reader, timeout=None)
                if reply is None or reply["type"] == "end":
                    return
                if reply["type"] == "record":
                    yield record_from_reply(reply, source.id)
                elif reply["type"] == "status":
                    if on_error is not None:
                        on_error(source.id, CollectorError(f"helper: {reply['message']}"))
                else:
                    raise CollectorError(_why(reply))
        finally:
            writer.close()


async def _read(reader: asyncio.StreamReader, timeout: float | None) -> dict | None:  # type: ignore[type-arg]
    try:
        line = await asyncio.wait_for(reader.readline(), timeout)
    except (ValueError, asyncio.LimitOverrunError):
        raise CollectorError("helper sent an oversized message") from None
    if not line:
        return None
    try:
        return decode_reply(line)
    except ProtocolError as exc:
        raise CollectorError(f"helper protocol error: {exc}") from None


def _why(reply: dict | None) -> str:  # type: ignore[type-arg]
    if reply is None:
        return "helper closed the connection"
    if reply["type"] == "error":
        return f"helper refused ({reply['code']}): {reply['message']}"
    return f"unexpected helper reply {reply['type']!r}"


@cache
def _journal_limited() -> bool:
    return journal_access_issue() is not None


def needs_helper(source: LogSource) -> bool:
    """Whether this user lacks direct read access to ``source``."""
    if source.kind is SourceKind.SYSTEMD:
        return _journal_limited()
    if source.kind is SourceKind.FILE:
        return not os.access(source.metadata.get("path", source.display_name), os.R_OK)
    return False


class HelperFallback:
    """A collector that uses ``primary`` unless the helper is needed and present."""

    def __init__(
        self,
        primary: Collector,
        client: HelperClient | None = None,
        needs: Callable[[LogSource], bool] = needs_helper,
    ) -> None:
        self.primary = primary
        self.client = client or HelperClient()
        self._needs = needs

    def stream(
        self,
        source: LogSource,
        *,
        cursor: str | None = None,
        since: datetime | None = None,
        lines: int = 0,
        follow: bool = True,
        on_error: ErrorCallback | None = None,
    ) -> AsyncIterator[RawRecord]:
        """Stream directly, or through the helper when this user cannot read ``source``."""
        if self.client.available() and self._needs(source):
            # ponytail: 'since' is not in protocol v1; the helper starts from cursor/lines.
            return self.client.stream(
                source, cursor=cursor, lines=lines, follow=follow, on_error=on_error
            )
        return self.primary.stream(
            source, cursor=cursor, since=since, lines=lines, follow=follow, on_error=on_error
        )
