import os
import time
from collections.abc import Iterator

import pytest

from loglens.parsers import timestamps


def _clear_tz_caches() -> None:
    for fn in (timestamps._local_tz, timestamps._rfc3164, timestamps.parse_ctime,
               timestamps.parse_clf):  # fmt: skip
        fn.cache_clear()


@pytest.fixture
def local_tz() -> Iterator[None]:
    """Run with TZ=UTC: naive timestamps in fixtures become deterministic."""
    yield from _with_tz("UTC")


def _with_tz(name: str) -> Iterator[None]:
    old = os.environ.get("TZ")
    os.environ["TZ"] = name
    time.tzset()
    _clear_tz_caches()
    try:
        yield
    finally:
        if old is None:
            del os.environ["TZ"]
        else:
            os.environ["TZ"] = old
        time.tzset()
        _clear_tz_caches()


@pytest.fixture
def tashkent_tz() -> Iterator[None]:
    """A fixed +05:00 zone without DST, to prove naive -> local -> UTC conversion."""
    yield from _with_tz("Asia/Tashkent")
