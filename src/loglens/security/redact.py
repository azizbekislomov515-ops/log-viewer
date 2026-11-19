"""Secret redaction, applied to every entry before it is stored (and again on export).

Default: irreversible. A secret becomes ``[REDACTED:kind]`` and is gone. Optional,
local-only: with a ``SecretVault`` it becomes ``[REDACTED:kind:token]`` and the original is
kept in an owner-only file on this machine, so the user can reveal it explicitly in the app.
Exports, reports and the AI feature never call ``reveal``.

Detected: passwords in URLs, Authorization / Bearer / Basic credentials, AWS keys, GitHub,
Stripe and Slack tokens, JWTs, private key blocks, cookies and session ids,
``password=``/``token=``/``api_key=`` style parameters, credit card numbers (Luhn
checked), generic high-entropy tokens, and user-configured regexes (run with a timeout).
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import math
import os
import re
import secrets as _secrets
import threading
from collections import Counter
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

import regex

from loglens.core.models import LogEntry

log = logging.getLogger(__name__)

#: A user-configured pattern gives up on a line after this long (ReDoS protection).
CUSTOM_TIMEOUT_S = 0.005
#: Longest text redacted; the normalizer already caps messages at 64 KiB.
MAX_TEXT = 1024 * 1024


@dataclass(frozen=True, slots=True)
class _Pattern:
    kind: str
    regex: re.Pattern[str]
    check: Callable[[str], bool] | None = None
    #: The regex runs only if one of these words occurs (lower-cased) in the text...
    words: tuple[str, ...] = ()
    #: ...or, for patterns without keywords, if this cheap regex finds something.
    probe: re.Pattern[str] | None = None


_DIGITS13 = re.compile(r"\d(?:[ -]?\d){12}")
_RUN32 = re.compile(r"[A-Za-z0-9+/_=-]{32}")


def luhn_ok(digits: str) -> bool:
    """Whether a 13-19 digit number passes the Luhn checksum (card numbers do)."""
    nums = [int(d) for d in digits if d.isdigit()]
    if not 13 <= len(nums) <= 19 or len(set(nums)) == 1:
        return False
    total = 0
    for i, digit in enumerate(reversed(nums)):
        total += (digit * 2 - 9 if digit > 4 else digit * 2) if i % 2 else digit
    return total % 10 == 0


def shannon_entropy(text: str) -> float:
    """Bits per character."""
    counts = Counter(text)
    return -sum(c / len(text) * math.log2(c / len(text)) for c in counts.values())


def looks_random(token: str) -> bool:
    """A long token mixing cases and digits with high entropy (not a hex id or a word).

    Hex strings (container ids, hashes) are left alone: LogLens needs them, and a hash is
    not a secret.
    """
    if re.fullmatch(r"[0-9a-fA-F]+", token) or re.fullmatch(r"[0-9]+", token):
        return False
    classes = sum(bool(re.search(p, token)) for p in (r"[a-z]", r"[A-Z]", r"[0-9]"))
    return classes == 3 and shannon_entropy(token) >= 4.0


_KEY_WORDS = (
    r"pass(?:word|wd|phrase)?|pwd|secret|client[_-]?secret|token|access[_-]?token|"
    r"refresh[_-]?token|auth[_-]?token|api[_-]?key|apikey|private[_-]?key"
)
#: Before a captured value: it may not itself be a key ("password= passwd: x" takes x),
#: or a crafted line could make a pattern swallow the next key and leave the secret.
_NOT_A_KEY = (
    rf"(?!(?:{_KEY_WORDS}|(?:proxy-)?authorization|cookie|session(?:[_-]?id)?|sid)"
    r"[\"']?\s*[:=])"
)
#: Order matters: earlier patterns run first, and replaced text cannot match later ones.
_PATTERNS = (
    _Pattern("private_key", re.compile(
        r"-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----[\s\S]*?"
        r"(?:-----END (?:[A-Z0-9 ]+ )?PRIVATE KEY-----|\Z)"), words=("private key",)),
    _Pattern("url_password", re.compile(
        r"(?<=[a-zA-Z0-9+.-]://)(?:[^\s/:@]{1,256}):(?P<s>[^\s/@]{1,256})(?=@)"),
        words=("://",)),
    _Pattern("authorization", re.compile(
        r"(?i)(?<![\w-])(?:proxy-)?authorization\s*[:=]\s*(?:basic|bearer|digest|token|negotiate)?"
        rf"\s*{_NOT_A_KEY}(?P<s>[^\s,;\"']{{4,}})"), words=("authoriz",)),
    _Pattern("bearer", re.compile(r"(?i)\bbearer\s+(?P<s>[A-Za-z0-9._~+/=-]{8,})"),
             words=("bearer",)),
    _Pattern("aws_access_key", re.compile(
        r"\b(?P<s>(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA|ANVA|AIPA)[A-Z0-9]{16})\b"),
        words=("akia", "asia", "agpa", "aida", "aroa", "anpa", "anva", "aipa")),
    _Pattern("aws_secret_key", re.compile(
        r"(?i)aws_?secret_?(?:access_?)?key[\"']?\s*[:=]\s*[\"']?(?P<s>[A-Za-z0-9/+]{40})"),
        words=("aws",)),
    _Pattern("github_token", re.compile(
        r"\b(?P<s>gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{22,255})\b"),
        words=("ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_")),
    _Pattern("stripe_key", re.compile(r"\b(?P<s>(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,247})\b"),
             words=("k_live_", "k_test_")),
    _Pattern("slack_token", re.compile(r"\b(?P<s>xox[abposr]-[A-Za-z0-9-]{10,250})"),
             words=("xox",)),
    _Pattern("jwt", re.compile(
        r"\b(?P<s>eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,})"),
        words=("eyj",)),
    _Pattern("cookie", re.compile(r"(?i)(?<![\w-])(?:set-)?cookie\s*:\s*(?P<s>[^\r\n]{1,4096})"),
             words=("cookie",)),
    _Pattern("session_id", re.compile(
        r"(?i)\b(?:session(?:[_-]?id)?|sid|phpsessid|jsessionid|connect\.sid|csrftoken|"
        rf"xsrf-token)\s*[=:]\s*{_NOT_A_KEY}(?P<s>[^\s;&,\"']{{8,256}})"),
        words=("sess", "sid", "csrf", "xsrf")),
    _Pattern("password", re.compile(
        rf"(?i)(?<![\w-])(?:{_KEY_WORDS})[\"']?\s*[:=]\s*[\"']?"
        rf"{_NOT_A_KEY}(?P<s>[^\s\"'&,;]{{3,256}})"),
        words=("pass", "pwd", "secret", "token", "key")),
    _Pattern("credit_card", re.compile(r"(?<![\d-])(?P<s>\d(?:[ -]?\d){12,18})(?![\d-])"),
             luhn_ok, probe=_DIGITS13),
    # Not after "SHA256:" / "MD5:": key fingerprints are public and identify the key.
    _Pattern("high_entropy", re.compile(
        r"(?<![\w+/=:-])(?<!SHA256:)(?<!SHA1:)(?<!MD5:)(?P<s>[A-Za-z0-9+/_=-]{32,512})(?![\w+/=-])"),
        looks_random, probe=_RUN32),
)  # fmt: skip
_HINT_WORDS = re.compile(
    "|".join(sorted({re.escape(w) for p in _PATTERNS for w in p.words}, key=len, reverse=True))
)


class SecretVault:
    """Local-only store of redacted originals (owner-only files), for explicit reveal."""

    def __init__(self, directory: Path) -> None:
        self.directory = directory
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        self._key_file = directory / "vault.key"
        self._file = directory / "vault.json"
        self._lock = threading.Lock()
        if not self._key_file.exists():
            _write_private(self._key_file, _secrets.token_hex(32))
        self._key = bytes.fromhex(self._key_file.read_text().strip())
        self._items: dict[str, str] = (
            json.loads(self._file.read_text()) if self._file.exists() else {}
        )

    def keep(self, secret: str) -> str:
        """Remember ``secret``; returns its token (stable for the same secret)."""
        with self._lock:
            token = hmac.new(self._key, secret.encode(), hashlib.sha256).hexdigest()[:12]
            if token not in self._items:
                self._items[token] = secret
                _write_private(self._file, json.dumps(self._items))
            return token

    def clear(self) -> None:
        """Forget every kept secret, in memory and on disk, and rotate the key (old
        tokens can no longer be resolved)."""
        with self._lock:
            self._items = {}
            self._file.unlink(missing_ok=True)
            self._key = bytes.fromhex(_secrets.token_hex(32))
            _write_private(self._key_file, self._key.hex())

    def reveal(self, text: str) -> str:
        """Put kept secrets back into ``text`` (explicit, local, user action only)."""
        with self._lock:
            items = dict(self._items)
        return re.sub(
            r"\[REDACTED:[a-z_]+:(?P<t>[0-9a-f]{12})\]", lambda m: items.get(m["t"], m[0]), text
        )


def _write_private(path: Path, text: str) -> None:
    tmp = path.with_suffix(".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(text)
    tmp.replace(path)


class Redactor:
    """Replaces secrets in text. Thread-safe (no mutable state but the optional vault)."""

    def __init__(
        self,
        custom: Iterable[str] = (),
        *,
        vault: SecretVault | None = None,
        enabled: bool = True,
    ) -> None:
        self.enabled = enabled
        self.vault = vault
        self.custom: list[Any] = []
        self.errors: list[str] = []
        for pattern in custom:
            try:
                self.custom.append(regex.compile(pattern))
            except regex.error as exc:
                self.errors.append(f"{pattern!r}: {exc}")

    def redact(self, text: str) -> tuple[str, int]:
        """``(redacted text, number of secrets replaced)``."""
        if not self.enabled or not text:
            return text, 0
        text = text[:MAX_TEXT]
        count = 0
        found = set(_HINT_WORDS.findall(text.lower()))  # one pass for all keywords
        for pattern in _PATTERNS:
            if pattern.probe.search(text) if pattern.probe else found.intersection(pattern.words):
                text, n = self._apply(pattern.kind, pattern.regex, pattern.check, text)
                count += n
        for custom in self.custom:
            try:
                text, n = self._apply_custom(custom, text)
            except TimeoutError:
                log.warning("custom redaction pattern timed out: %s", custom.pattern)
                continue
            count += n
        return text, count

    def _mark(self, kind: str, secret: str) -> str:
        if self.vault is None:
            return f"[REDACTED:{kind}]"
        return f"[REDACTED:{kind}:{self.vault.keep(secret)}]"

    def _apply(
        self, kind: str, pattern: re.Pattern[str], check: Callable[[str], bool] | None, text: str
    ) -> tuple[str, int]:
        count = 0

        def replace_one(m: re.Match[str]) -> str:
            nonlocal count
            group = "s" if "s" in pattern.groupindex else 0
            secret = m.group(group)
            if not secret or secret.startswith("[REDACTED") or (check and not check(secret)):
                return m.group(0)
            count += 1
            start, end = m.span(group)
            whole = m.group(0)
            offset = m.start(0)
            return whole[: start - offset] + self._mark(kind, secret) + whole[end - offset :]

        return pattern.sub(replace_one, text), count

    def _apply_custom(self, pattern: Any, text: str) -> tuple[str, int]:
        count = 0

        def replace_one(m: Any) -> str:
            nonlocal count
            count += 1
            return self._mark("custom", m.group(0))

        result = pattern.sub(replace_one, text, timeout=CUSTOM_TIMEOUT_S)
        return result, count

    def redact_value(self, value: Any) -> tuple[Any, int]:
        """Redact strings inside str / list / dict values (field values from logs)."""
        if isinstance(value, str):
            return self.redact(value)
        if isinstance(value, list):
            parts = [self.redact_value(v) for v in value]
            return [p[0] for p in parts], sum(p[1] for p in parts)
        if isinstance(value, Mapping):
            items = {k: self.redact_value(v) for k, v in value.items()}
            return {k: v[0] for k, v in items.items()}, sum(v[1] for v in items.values())
        return value, 0

    def redact_entry(self, entry: LogEntry) -> LogEntry:
        """The entry with secrets removed from message, raw text and field values; the
        count is recorded in ``fields["redacted"]``."""
        if not self.enabled:
            return entry
        message, n1 = self.redact(entry.message)
        raw, n2 = (message, 0) if entry.raw == entry.message else self.redact(entry.raw)
        fields, n3 = self.redact_value(dict(entry.fields))
        total = n1 + n2 + n3
        if not total:
            return entry
        fields["redacted"] = total
        return replace(entry, message=message, raw=raw, fields=fields)
