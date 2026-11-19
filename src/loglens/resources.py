"""Where LogLens's data files live: inside the installed package (``loglens/_data``, put
there by the wheel build) or, in a source checkout, in the repository."""

from __future__ import annotations

from pathlib import Path

_PACKAGED = Path(__file__).resolve().parent / "_data"
_REPO = Path(__file__).resolve().parents[2]
#: Packaged name -> path in a source checkout (pyproject.toml force-include mirrors this).
_IN_REPO = {"rules": "rules", "demo_logs": "tests/fixtures/logs", "demo_stack": "demo"}


def data_path(name: str) -> Path:
    """The directory of data set ``name`` (``rules``, ``demo_logs`` or ``demo_stack``)."""
    packaged = _PACKAGED / name
    return packaged if packaged.is_dir() else _REPO / _IN_REPO[name]
