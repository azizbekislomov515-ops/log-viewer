"""Make hostile log text safe to show: no terminal escapes, no control characters, no
bidirectional overrides (which can make text read differently from what it is).

Used by every place that renders log content: the GUI, the CLI, text/CSV exports and
incident reports. JSON exports escape control characters by themselves.
"""

from __future__ import annotations

import re

#: CSI (``ESC [ ... final``), OSC (``ESC ] ... BEL|ST``, e.g. hyperlinks, window titles),
#: DCS/SOS/PM/APC strings, and two-byte ``ESC x`` sequences.
_ANSI = re.compile(
    r"\x1b\[[0-?]*[ -/]*[@-~]"
    r"|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)?"
    r"|\x1b[PX^_][^\x1b]*(?:\x1b\\)?"
    r"|\x1b[@-Z\\-_]"
    r"|\x9b[0-?]*[ -/]*[@-~]"
)
#: Characters that reorder or hide text ("Trojan Source"): LRE..RLO, LRI..PDI, LRM/RLM/ALM.
_BIDI = "".join(
    map(
        chr,
        (
            0x202A,
            0x202B,
            0x202C,
            0x202D,
            0x202E,
            0x2066,
            0x2067,
            0x2068,
            0x2069,
            0x200E,
            0x200F,
            0x061C,
        ),
    )
)
_TABLE = dict.fromkeys([*range(32), *range(127, 160)], "?")
_TABLE.update(dict.fromkeys(map(ord, _BIDI), "?"))
_TABLE[ord("\t")] = "    "


def strip_ansi(text: str) -> str:
    """Remove terminal escape sequences entirely."""
    return _ANSI.sub("", text) if ("\x1b" in text or "\x9b" in text) else text


def printable(text: str, *, keep_newlines: bool = True) -> str:
    """``text`` with escape sequences removed and every other control or bidi character
    replaced by ``?`` (tabs become spaces; newlines kept unless ``keep_newlines=False``)."""
    text = strip_ansi(text)
    if keep_newlines:
        return "\n".join(line.translate(_TABLE) for line in text.split("\n"))
    return text.translate(_TABLE)
