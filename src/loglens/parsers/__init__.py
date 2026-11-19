"""Parsers: turn raw log lines into structured fields, per source."""

from __future__ import annotations

from loglens.parsers.base import ParsedFields, Parser, ParserRegistry, SourceMatch
from loglens.parsers.clamav import ClamavParser
from loglens.parsers.docker import DockerDaemonParser
from loglens.parsers.generic import IsoTextParser, JsonParser, LogfmtParser, SyslogParser
from loglens.parsers.multiline import MultilineAssembler
from loglens.parsers.nginx import NginxParser
from loglens.parsers.normalize import MAX_MESSAGE_CHARS, Normalizer
from loglens.parsers.severity import SeverityInferrer
from loglens.parsers.squid import SquidParser
from loglens.parsers.sshd import SshdParser

__all__ = [
    "MAX_MESSAGE_CHARS",
    "MultilineAssembler",
    "Normalizer",
    "ParsedFields",
    "Parser",
    "ParserRegistry",
    "SeverityInferrer",
    "SourceMatch",
    "default_registry",
]

#: Service parsers are tried first; generic ones are the fallback chain, in this order.
SERVICE_PRIORITY = 100


def default_registry() -> ParserRegistry:
    """All built-in parsers with their default priorities."""
    return ParserRegistry(
        [
            (SquidParser(), SERVICE_PRIORITY),
            (ClamavParser(), SERVICE_PRIORITY),
            (NginxParser(), SERVICE_PRIORITY),
            (SshdParser(), SERVICE_PRIORITY),
            (DockerDaemonParser(), SERVICE_PRIORITY),
            (JsonParser(), 40),
            (SyslogParser(), 30),
            (LogfmtParser(), 20),
            (IsoTextParser(), 10),
        ]
    )
