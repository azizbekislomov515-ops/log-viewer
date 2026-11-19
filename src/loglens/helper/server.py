"""loglens-helper: a small read-only daemon that streams selected logs to LogLens.

Run by systemd (socket activation) as the unprivileged ``loglens-helper`` user, which is
in the groups that may read the journal and /var/log. It never runs as root and never
needs to. Per connection it:

1. reads the peer's uid/pid from the kernel (``SO_PEERCRED``, cannot be forged);
2. authorizes it: root, a member of ``allow_groups``, or polkit
   (``org.loglens.helper.read-logs``, checked with ``pkcheck``);
3. reads one request (protocol.py) and serves only sources listed in the config, reusing
   LogLens's own journald and file collectors.

Config (``/etc/loglens/helper.toml``, must be owned by root and not writable by others)::

    units = ["ssh.service", "squid.service"]
    files = ["/var/log/squid/*.log", "/var/log/auth.log"]
    allow_groups = ["loglens"]
    polkit = true
    max_clients = 16
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import glob
import grp
import logging
import os
import pwd
import socket
import stat
import struct
import sys
import tomllib
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

from loglens.collectors import source_from_id
from loglens.collectors.base import Collector
from loglens.core.models import SourceKind
from loglens.helper.protocol import (
    MAX_MESSAGE,
    SERVER_NAME,
    Hello,
    StreamRequest,
    decode_request,
    encode,
    record_message,
)

log = logging.getLogger(__name__)

DEFAULT_CONFIG = Path("/etc/loglens/helper.toml")
DEFAULT_SOCKET = Path("/run/loglens-helper.sock")
POLKIT_ACTION = "org.loglens.helper.read-logs"
REQUEST_TIMEOUT_S = 10.0
SD_LISTEN_FDS_START = 3

Authorizer = Callable[["PeerCredentials"], Awaitable[bool]]


@dataclass(frozen=True, slots=True)
class HelperConfig:
    """What the helper may serve, and to whom."""

    units: tuple[str, ...] = ()
    files: tuple[str, ...] = ()
    allow_groups: tuple[str, ...] = ()
    polkit: bool = True
    max_clients: int = 16


@dataclass(frozen=True, slots=True)
class PeerCredentials:
    """The connecting process, as the kernel reports it."""

    pid: int
    uid: int
    gid: int


class ConfigError(ValueError):
    """The helper config is missing, malformed or unsafe."""


def load_config(path: Path = DEFAULT_CONFIG, *, require_root_owned: bool = True) -> HelperConfig:
    """Read and validate the config. An unsafe file (writable by someone other than root)
    is refused: whoever can edit it decides what the helper reveals."""
    try:
        info = path.stat()
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError, UnicodeDecodeError) as exc:
        raise ConfigError(f"{path}: {exc}") from None
    if require_root_owned and (info.st_uid != 0 or info.st_mode & (stat.S_IWGRP | stat.S_IWOTH)):
        raise ConfigError(f"{path} must be owned by root and not group/world-writable")
    allowed = {"units", "files", "allow_groups", "polkit", "max_clients"}
    if extra := set(data) - allowed:
        raise ConfigError(f"{path}: unknown keys {sorted(extra)}")
    lists = {}
    for key in ("units", "files", "allow_groups"):
        value = data.get(key, [])
        if not isinstance(value, list) or not all(isinstance(v, str) and v for v in value):
            raise ConfigError(f"{path}: '{key}' must be a list of strings")
        lists[key] = tuple(value)
    if any(not Path(p).is_absolute() for p in lists["files"]):
        raise ConfigError(f"{path}: 'files' patterns must be absolute paths")
    polkit, max_clients = data.get("polkit", True), data.get("max_clients", 16)
    if type(polkit) is not bool or type(max_clients) is not int or not 1 <= max_clients <= 1024:
        raise ConfigError(f"{path}: 'polkit' must be a boolean, 'max_clients' 1..1024")
    return HelperConfig(lists["units"], lists["files"], lists["allow_groups"], polkit, max_clients)


def peer_credentials(sock: socket.socket) -> PeerCredentials:
    """``SO_PEERCRED`` of a connected Unix socket."""
    raw = sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
    pid, uid, gid = struct.unpack("3i", raw)
    return PeerCredentials(pid, uid, gid)


def user_groups(uid: int) -> frozenset[str]:
    """Group names of ``uid`` (primary and supplementary)."""
    try:
        user = pwd.getpwuid(uid)
        gids = os.getgrouplist(user.pw_name, user.pw_gid)
    except (KeyError, OSError):
        return frozenset()
    names = set()
    for gid in gids:
        with contextlib.suppress(KeyError):
            names.add(grp.getgrgid(gid).gr_name)
    return frozenset(names)


def process_start_time(pid: int) -> int | None:
    """Field 22 of ``/proc/<pid>/stat``: identifies the process even if the pid is reused."""
    try:
        text = Path(f"/proc/{pid}/stat").read_text()
        return int(text[text.rindex(")") + 2 :].split()[19])
    except (OSError, ValueError, IndexError):
        return None


async def polkit_authorized(peer: PeerCredentials, *, pkcheck: str = "pkcheck") -> bool:
    """Ask polkit whether ``peer`` may read logs (may show the user a password prompt).

    The subject is ``pid,start-time,uid`` so a recycled pid cannot borrow a grant.
    """
    start = process_start_time(peer.pid)
    if start is None:
        return False
    try:
        proc = await asyncio.create_subprocess_exec(
            pkcheck, "--action-id", POLKIT_ACTION,
            "--process", f"{peer.pid},{start},{peer.uid}", "--allow-user-interaction",
            stdin=asyncio.subprocess.DEVNULL, stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )  # fmt: skip
    except OSError:
        log.warning("pkcheck is not available; polkit authorization impossible")
        return False
    try:
        return await asyncio.wait_for(proc.wait(), 120) == 0
    except TimeoutError:
        proc.kill()
        return False


class HelperServer:
    """Serves allowed sources to authorized peers. Tests inject collectors and authorizer."""

    def __init__(
        self,
        config: HelperConfig,
        collectors: Mapping[SourceKind, Collector] | None = None,
        authorize: Authorizer | None = None,
    ) -> None:
        self.config = config
        if collectors is None:
            from loglens.collectors.files import FileCollector  # noqa: PLC0415
            from loglens.collectors.journald import JournaldCollector  # noqa: PLC0415

            collectors = {SourceKind.SYSTEMD: JournaldCollector(), SourceKind.FILE: FileCollector()}
        self._collectors = collectors
        self._authorize = authorize or self._default_authorize
        self._slots = asyncio.Semaphore(config.max_clients)

    async def _default_authorize(self, peer: PeerCredentials) -> bool:
        if peer.uid == 0 or user_groups(peer.uid) & set(self.config.allow_groups):
            return True
        return self.config.polkit and await polkit_authorized(peer)

    def allowed_sources(self) -> list[str]:
        """Every source id this helper serves right now (file patterns expanded)."""
        files = sorted(
            {p for pattern in self.config.files for p in _expand(pattern) if _plain_file(p)}
        )
        return [f"systemd:{u}" for u in self.config.units] + [f"file:{p}" for p in files]

    def is_allowed(self, source_id: str) -> bool:
        """Whether ``source_id`` is listed. Files must be regular files reached without
        symlinks or ``..`` and match a configured pattern."""
        kind, _, name = source_id.partition(":")
        if kind == "systemd":
            return name in self.config.units
        if kind == "file":
            if not name.startswith("/") or os.path.realpath(name) != name or not _plain_file(name):
                return False
            return any(name in _expand(pattern) for pattern in self.config.files)
        return False

    async def handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        """Serve one connection (one request)."""
        try:
            await self._handle(reader, writer)
        except (ConnectionError, BrokenPipeError):
            pass
        except Exception:
            log.exception("helper connection failed")
            with contextlib.suppress(Exception):
                writer.write(encode({"type": "error", "code": "failed", "message": "internal"}))
        finally:
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        sock = writer.get_extra_info("socket")
        peer = peer_credentials(sock)
        if self._slots.locked():
            await _error(writer, "busy", "too many clients")
            return
        async with self._slots:
            if not await self._authorize(peer):
                log.warning("unauthorized helper client", extra={"uid": peer.uid, "pid": peer.pid})
                await _error(writer, "unauthorized", f"uid {peer.uid} may not read logs")
                return
            try:
                line = await asyncio.wait_for(reader.readline(), REQUEST_TIMEOUT_S)
                request = decode_request(line)
            except (ValueError, asyncio.LimitOverrunError) as exc:  # incl. ProtocolError
                await _error(writer, getattr(exc, "code", "too_large"), str(exc)[:200])
                return
            except TimeoutError:
                await _error(writer, "bad_request", "no request received")
                return
            if isinstance(request, Hello):
                writer.write(
                    encode({"type": "hello", "server": SERVER_NAME,
                            "sources": self.allowed_sources()})
                )  # fmt: skip
                await writer.drain()
                return
            await self._stream(request, writer, peer)

    async def _stream(
        self, request: StreamRequest, writer: asyncio.StreamWriter, peer: PeerCredentials
    ) -> None:
        if not self.is_allowed(request.source):
            await _error(writer, "not_allowed", "this source is not in the helper's allowlist")
            return
        source = source_from_id(request.source)
        collector = self._collectors.get(source.kind)
        if collector is None:
            await _error(writer, "not_allowed", "unsupported source kind")
            return
        log.info("streaming", extra={"source": source.id, "uid": peer.uid})

        def on_error(_source: str, exc: BaseException) -> None:
            with contextlib.suppress(Exception):
                writer.write(encode({"type": "status", "message": str(exc)[:1000]}))

        records = collector.stream(
            source, cursor=request.cursor, lines=request.lines, follow=request.follow,
            on_error=on_error,
        )  # fmt: skip
        try:
            async for record in records:
                writer.write(encode(record_message(record)))
                await writer.drain()  # backpressure: a slow client slows only its stream
        finally:
            closer = getattr(records, "aclose", None)
            if closer is not None:
                await closer()
        writer.write(encode({"type": "end"}))
        await writer.drain()


def _expand(pattern: str) -> list[str]:
    """Files matching an absolute pattern (``Path.glob`` takes only relative ones)."""
    return glob.glob(pattern)  # noqa: PTH207


def _plain_file(path: str) -> bool:
    try:
        return stat.S_ISREG(os.lstat(path).st_mode)
    except OSError:
        return False


async def _error(writer: asyncio.StreamWriter, code: str, message: str) -> None:
    writer.write(encode({"type": "error", "code": code, "message": message}))
    with contextlib.suppress(Exception):
        await writer.drain()


def _activated_socket() -> socket.socket | None:
    """The socket systemd passed (socket activation), if any."""
    if os.environ.get("LISTEN_PID") != str(os.getpid()) or os.environ.get("LISTEN_FDS") != "1":
        return None
    return socket.socket(fileno=SD_LISTEN_FDS_START)


async def serve(server: HelperServer, socket_path: Path) -> None:
    """Accept connections forever (systemd's socket, or bind ``socket_path``)."""
    sock = _activated_socket()
    if sock is not None:
        listener = await asyncio.start_unix_server(server.handle, sock=sock, limit=MAX_MESSAGE)
    else:
        socket_path.unlink(missing_ok=True)
        listener = await asyncio.start_unix_server(
            server.handle, path=str(socket_path), limit=MAX_MESSAGE
        )
        socket_path.chmod(0o666)  # anyone may connect; each peer is authorized in handle()
    async with listener:
        await listener.serve_forever()


def main(argv: Sequence[str] | None = None) -> int:
    """Entry point of ``loglens-helper``."""
    parser = argparse.ArgumentParser(prog="loglens-helper", description=__doc__.split("\n")[0])
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    parser.add_argument("--socket", type=Path, default=DEFAULT_SOCKET)
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    if os.geteuid() == 0:
        print("loglens-helper: refusing to run as root; use the packaged service, which "
              "runs as the loglens-helper user", file=sys.stderr)  # fmt: skip
        return 2
    try:
        config = load_config(args.config)
    except ConfigError as exc:
        print(f"loglens-helper: {exc}", file=sys.stderr)
        return 2
    with contextlib.suppress(KeyboardInterrupt):
        asyncio.run(serve(HelperServer(config), args.socket))
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
