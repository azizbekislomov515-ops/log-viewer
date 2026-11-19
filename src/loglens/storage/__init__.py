"""Persistence: SQLite (WAL) with FTS5 search, retention and schema migrations."""

from loglens.storage.sqlite import (
    EntryQuery,
    RetentionPolicy,
    SearchError,
    Storage,
    StorageError,
    default_db_path,
)

__all__ = [
    "EntryQuery",
    "RetentionPolicy",
    "SearchError",
    "Storage",
    "StorageError",
    "default_db_path",
]
