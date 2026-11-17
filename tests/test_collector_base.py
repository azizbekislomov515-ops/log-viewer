from collections.abc import AsyncIterator

import pytest

from loglens.collectors.base import Backoff, LineSplitter, reconnecting
from loglens.core.models import RawRecord
from tests.fakes import take


def test_line_splitter_lines_partials_and_offsets() -> None:
    s = LineSplitter()
    assert s.feed(b"one\ntw") == [(b"one", False, 4)]
    assert s.pending == 2
    assert s.feed(b"o\r\nthree\n") == [(b"two", False, 9), (b"three", False, 15)]
    assert s.feed(b"tail") == []
    assert s.flush() == (b"tail", False, 19)
    assert s.flush() is None


def test_line_splitter_caps_long_lines() -> None:
    s = LineSplitter(max_bytes=4)
    assert s.feed(b"abcdef\nok\n") == [(b"abcd", True, 7), (b"ok", False, 10)]
    # an over-long line still being written is emitted early, its tail dropped
    assert s.feed(b"0123456") == [(b"0123", True, 17)]
    assert s.feed(b"789") == []
    assert s.feed(b"\nnext\n") == [(b"next", False, 26)]
    assert s.pending == 0


def test_backoff() -> None:
    b = Backoff(initial=1, maximum=5, factor=2)
    assert [b.next_delay() for _ in range(5)] == [1, 2, 4, 5, 5]
    b.reset()
    assert b.next_delay() == 1
    assert Backoff(initial=10, maximum=0.1).next_delay() == 0.1


async def test_reconnecting_resumes_from_last_cursor_and_reports_errors() -> None:
    opened: list[str | None] = []
    errors: list[BaseException] = []

    async def open_stream(cursor: str | None) -> AsyncIterator[RawRecord]:
        opened.append(cursor)
        n = len(opened)
        yield RawRecord("s", f"line {n}", cursor=f"c{n}")
        if n == 1:
            raise ConnectionError("dropped")
        # second connection ends cleanly (e.g. container stopped)

    stream = reconnecting(
        open_stream,
        "s",
        cursor="c0",
        follow=True,
        backoff=Backoff(initial=0.001, maximum=0.001),
        on_error=lambda _, exc: errors.append(exc),
    )
    records = await take(stream, 3)
    assert [r.message for r in records] == ["line 1", "line 2", "line 3"]
    assert opened == ["c0", "c1", "c2"]
    assert [type(e) for e in errors] == [ConnectionError]


async def test_reconnecting_without_follow_raises() -> None:
    async def open_stream(cursor: str | None) -> AsyncIterator[RawRecord]:
        raise PermissionError("nope")
        yield  # pragma: no cover

    stream = reconnecting(
        open_stream, "s", cursor=None, follow=False, backoff=Backoff(), on_error=None
    )
    with pytest.raises(PermissionError):
        await take(stream, 1)
