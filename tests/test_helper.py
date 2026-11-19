"""loglens-helper over a real Unix socket: protocol, allowlist, authorization, fallback."""

from __future__ import annotations

import asyncio
import json
import os
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from loglens.collectors import source_from_id
from loglens.collectors.base import CollectorError
from loglens.core.models import LogSource, RawRecord, Severity, SourceKind
from loglens.helper import protocol
from loglens.helper.client import HelperClient, HelperFallback
from loglens.helper.server import (
    ConfigError,
    HelperConfig,
    HelperServer,
    PeerCredentials,
    load_config,
)


class FakeCollector:
    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []

    async def stream(self, source: LogSource, **kw: Any) -> AsyncIterator[RawRecord]:
        self.calls.append({"source": source.id, **kw})
        ts = datetime(2026, 11, 19, 10, 0, tzinfo=UTC)
        for i in range(3):
            yield RawRecord(source.id, f"line {i}", ts, Severity.ERROR, {"UNIT": "x"}, f"c{i}")


async def _allow(_: PeerCredentials) -> bool:
    return True


async def _deny(_: PeerCredentials) -> bool:
    return False


@pytest.fixture
def log_file(tmp_path: Path) -> Path:
    path = tmp_path / "logs" / "squid.log"
    path.parent.mkdir()
    path.write_text("x\n")
    return path


async def _serve(server: HelperServer, path: Path) -> asyncio.Server:
    return await asyncio.start_unix_server(
        server.handle, path=str(path), limit=protocol.MAX_MESSAGE
    )


def _server(log_file: Path, authorize: Any = _allow) -> tuple[HelperServer, FakeCollector]:
    fake = FakeCollector()
    config = HelperConfig(units=("ssh.service",), files=(str(log_file.parent / "*.log"),))
    collectors = {SourceKind.SYSTEMD: fake, SourceKind.FILE: fake}
    return HelperServer(config, collectors, authorize), fake  # type: ignore[arg-type]


async def test_hello_and_stream(tmp_path: Path, log_file: Path) -> None:
    server, fake = _server(log_file)
    sock = tmp_path / "h.sock"
    async with await _serve(server, sock):
        client = HelperClient(sock)
        assert client.available()
        assert await client.hello() == ["systemd:ssh.service", f"file:{log_file}"]
        src = source_from_id("systemd:ssh.service")
        records = [r async for r in client.stream(src, cursor="c", lines=5, follow=False)]
    assert [r.message for r in records] == ["line 0", "line 1", "line 2"]
    assert records[0].severity is Severity.ERROR and records[0].cursor == "c0"
    assert records[0].timestamp == datetime(2026, 11, 19, 10, 0, tzinfo=UTC)
    assert fake.calls[0]["cursor"] == "c" and fake.calls[0]["lines"] == 5


@pytest.mark.parametrize(
    "source",
    ["systemd:sshd-other.service", "file:/etc/shadow", "docker:web", "file:relative.log"],
)
async def test_unlisted_sources_are_refused(tmp_path: Path, log_file: Path, source: str) -> None:
    server, fake = _server(log_file)
    sock = tmp_path / "h.sock"
    async with await _serve(server, sock):
        reader, writer = await asyncio.open_unix_connection(str(sock))
        writer.write(protocol.encode_request(protocol.StreamRequest(source)))
        reply = protocol.decode_reply(await reader.readline())
        writer.close()
    assert reply["type"] == "error" and reply["code"] == "not_allowed"
    assert not fake.calls


def test_symlinks_and_dotdot_cannot_escape_the_allowlist(log_file: Path) -> None:
    server, _ = _server(log_file)
    link = log_file.parent / "evil.log"
    link.symlink_to("/etc/passwd")
    assert server.is_allowed(f"file:{log_file}")
    assert not server.is_allowed(f"file:{link}")  # matches *.log but is a symlink
    assert not server.is_allowed(f"file:{log_file.parent}/../logs/squid.log")
    assert f"file:{link}" not in server.allowed_sources()


@pytest.mark.parametrize(
    ("line", "code"),
    [
        (b"not json\n", "bad_request"),
        (b'{"v": 2, "op": "hello"}\n', "unsupported_version"),
        (b'{"v": 1, "op": "hello", "extra": 1}\n', "bad_request"),
        (
            b'{"v": 1, "op": "stream", "source": "systemd:ssh.service", "lines": 99999999}\n',
            "bad_request",
        ),
        (b'{"v": 1, "op": "exec", "cmd": "id"}\n', "bad_request"),
        (b'{"v": 1, "op": "stream", "source": "x", "follow": "yes"}\n', "bad_request"),
        (b'{"v": true, "op": "hello"}\n', "unsupported_version"),
        (b"[" * 70_000 + b"\n", "too_large"),
    ],
)
async def test_malformed_requests_get_an_error(
    tmp_path: Path, log_file: Path, line: bytes, code: str
) -> None:
    server, fake = _server(log_file)
    sock = tmp_path / "h.sock"
    async with await _serve(server, sock):
        reader, writer = await asyncio.open_unix_connection(str(sock), limit=2**20)
        writer.write(line)
        await writer.drain()
        reply = json.loads(await reader.readline())
        writer.close()
    assert reply == {"v": 1, "type": "error", "code": code, "message": reply["message"]}
    assert not fake.calls


async def test_unauthorized_peer_is_refused(tmp_path: Path, log_file: Path) -> None:
    server, fake = _server(log_file, authorize=_deny)
    sock = tmp_path / "h.sock"
    async with await _serve(server, sock):
        with pytest.raises(CollectorError, match="unauthorized"):
            await HelperClient(sock).hello()
    assert not fake.calls


async def test_peer_credentials_come_from_the_kernel(tmp_path: Path, log_file: Path) -> None:
    seen: list[PeerCredentials] = []

    async def record(peer: PeerCredentials) -> bool:
        seen.append(peer)
        return True

    server, _ = _server(log_file, authorize=record)
    sock = tmp_path / "h.sock"
    async with await _serve(server, sock):
        await HelperClient(sock).hello()
    assert seen == [PeerCredentials(os.getpid(), os.getuid(), os.getgid())]


def test_client_rejects_hostile_replies() -> None:
    for line in (
        b'{"v":1,"type":"record","message":"x","cursor":null,"ts":null,"severity":"EVIL",'
        b'"fields":{}}\n',
        b'{"v":1,"type":"record","message":"x","cursor":null,"ts":null,"severity":null,'
        b'"fields":{"k":{"nested":1}}}\n',
        b'{"v":1,"type":"run","cmd":"rm -rf /"}\n',
    ):
        with pytest.raises(protocol.ProtocolError):
            protocol.decode_reply(line)


def test_records_are_cut_to_fit_one_message() -> None:
    record = RawRecord("file:/x", "A" * 200_000, fields={"k": "v" * 5000, "obj": object()})
    line = protocol.encode(protocol.record_message(record))
    assert len(line) <= protocol.MAX_MESSAGE
    reply = protocol.decode_reply(line)
    assert "obj" not in reply["fields"]


async def test_fallback_uses_helper_only_when_needed(tmp_path: Path, log_file: Path) -> None:
    server, fake = _server(log_file)
    primary = FakeCollector()
    sock = tmp_path / "h.sock"
    src = source_from_id(f"file:{log_file}")
    async with await _serve(server, sock):
        direct = HelperFallback(primary, HelperClient(sock), needs=lambda s: False)  # type: ignore[arg-type]
        [r async for r in direct.stream(src, follow=False)]
        via = HelperFallback(primary, HelperClient(sock), needs=lambda s: True)  # type: ignore[arg-type]
        [r async for r in via.stream(src, follow=False)]
        missing = HelperFallback(
            primary, HelperClient(tmp_path / "none.sock"), needs=lambda s: True
        )  # type: ignore[arg-type]
        [r async for r in missing.stream(src, follow=False)]
    assert len(primary.calls) == 2 and len(fake.calls) == 1


def _config(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "helper.toml"
    path.write_text(text)
    path.chmod(0o644)
    return path


def test_config_is_strict(tmp_path: Path) -> None:
    ok = _config(tmp_path, 'units = ["ssh.service"]\nfiles = ["/var/log/*.log"]\n')
    assert load_config(ok, require_root_owned=False).units == ("ssh.service",)
    with pytest.raises(ConfigError, match="owned by root"):
        load_config(ok)  # owned by the test user
    for bad in ('files = ["relative/*.log"]', "unknown = 1", 'units = "ssh"', "max_clients = 0"):
        with pytest.raises(ConfigError):
            load_config(_config(tmp_path, bad), require_root_owned=False)
