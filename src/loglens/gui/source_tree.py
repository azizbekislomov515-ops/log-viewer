"""SourceTreeModel: discovered sources grouped for the left dock.

Layout: four fixed categories (System services, Docker Compose, Standalone containers,
Log files). Compose projects and file groups (Squid, Nginx, ...) are nodes under their
category; systemd units and standalone containers sit directly under theirs.

``update`` is cheap when only statuses changed (items are edited in place); when sources
appear or disappear the tree is rebuilt and the view restores expansion by node id.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Sequence
from enum import IntEnum, StrEnum

from PySide6.QtCore import QObject, Qt
from PySide6.QtGui import QStandardItem, QStandardItemModel

from loglens.core.models import GroupKind, LogSource, ServiceGroup


class NodeKind(StrEnum):
    """What a tree row stands for."""

    CATEGORY = "category"
    GROUP = "group"
    SOURCE = "source"


class TreeRole(IntEnum):
    """Custom data roles of tree items."""

    KIND = Qt.ItemDataRole.UserRole + 1
    NODE_ID = Qt.ItemDataRole.UserRole + 2
    SOURCE = Qt.ItemDataRole.UserRole + 3
    GROUP = Qt.ItemDataRole.UserRole + 4
    UNREAD = Qt.ItemDataRole.UserRole + 5
    PINNED = Qt.ItemDataRole.UserRole + 6
    COUNT = Qt.ItemDataRole.UserRole + 7


CATEGORIES: tuple[tuple[str, str, tuple[GroupKind, ...]], ...] = (
    ("cat:system", "System services", (GroupKind.SYSTEM,)),
    ("cat:compose", "Docker Compose", (GroupKind.DOCKER_COMPOSE,)),
    ("cat:containers", "Standalone containers", (GroupKind.DOCKER_STANDALONE,)),
    ("cat:files", "Log files", (GroupKind.FILES,)),
)
#: Group kinds whose groups get their own node (the others list sources directly).
_NESTED = (GroupKind.DOCKER_COMPOSE, GroupKind.FILES)


class SourceTreeModel(QStandardItemModel):
    """Tree of categories -> (groups ->) sources, with unread-error counts and pins."""

    def __init__(self, parent: QObject | None = None) -> None:
        super().__init__(parent)
        self._sources: dict[str, LogSource] = {}
        self._groups: dict[str, ServiceGroup] = {}
        self._items: dict[str, QStandardItem] = {}
        self._unread: dict[str, int] = {}
        self._pinned: set[str] = set()
        self._shape: tuple[tuple[str, tuple[str, ...]], ...] = ()
        self.setHorizontalHeaderLabels(["Sources"])

    # ------------------------------------------------------------------ queries

    def source(self, source_id: str) -> LogSource | None:
        """A known source by id."""
        return self._sources.get(source_id)

    def group(self, group_id: str) -> ServiceGroup | None:
        """A known group by id."""
        return self._groups.get(group_id)

    def sources(self) -> list[LogSource]:
        """Every visible source, in tree order."""
        return list(self._sources.values())

    def display_names(self) -> dict[str, str]:
        """Source id -> display name."""
        return {sid: s.display_name for sid, s in self._sources.items()}

    def item_for(self, node_id: str) -> QStandardItem | None:
        """The item of a node id (``cat:...``, a group id or a source id)."""
        return self._items.get(node_id)

    # ------------------------------------------------------------------ updates

    def update(
        self, groups: Sequence[ServiceGroup], excluded: Callable[[str], bool] = lambda _: False
    ) -> bool:
        """Sync with a discovery result; returns True if the tree was rebuilt."""
        kept = [
            g.__class__(g.id, g.name, g.kind, tuple(s for s in g.sources if not excluded(s.id)))
            for g in groups
        ]
        kept = [g for g in kept if g.sources]
        shape = tuple((g.id, tuple(s.id for s in g.sources)) for g in kept)
        self._groups = {g.id: g for g in kept}
        self._sources = {s.id: s for g in kept for s in g.sources}
        if shape == self._shape:
            for source in self._sources.values():
                item = self._items.get(source.id)
                if item is not None and item.data(TreeRole.SOURCE) != source:
                    item.setData(source, TreeRole.SOURCE)
            return False
        self._shape = shape
        self._rebuild(kept)
        return True

    def _rebuild(self, groups: Sequence[ServiceGroup]) -> None:
        self.beginResetModel()
        self.blockSignals(True)
        try:
            self.removeRows(0, self.rowCount())
            self._items = {}
            root = self.invisibleRootItem()
            for cat_id, label, kinds in CATEGORIES:
                members = [g for g in groups if g.kind in kinds]
                if not members:
                    continue
                cat = self._node(cat_id, label, NodeKind.CATEGORY)
                total = 0
                for group in sorted(members, key=lambda g: g.name.lower()):
                    parent = cat
                    if group.kind in _NESTED:
                        parent = self._node(group.id, group.name, NodeKind.GROUP)
                        parent.setData(group, TreeRole.GROUP)
                        parent.setData(len(group.sources), TreeRole.COUNT)
                        cat.appendRow(parent)
                    for source in sorted(group.sources, key=lambda s: s.display_name.lower()):
                        parent.appendRow(self._source_item(source))
                        total += 1
                cat.setData(total, TreeRole.COUNT)
                root.appendRow(cat)
        finally:
            self.blockSignals(False)
        self.endResetModel()

    def _node(self, node_id: str, label: str, kind: NodeKind) -> QStandardItem:
        item = QStandardItem(label)
        item.setEditable(False)
        item.setData(kind.value, TreeRole.KIND)
        item.setData(node_id, TreeRole.NODE_ID)
        item.setData(label, Qt.ItemDataRole.AccessibleTextRole)
        self._items[node_id] = item
        return item

    def _source_item(self, source: LogSource) -> QStandardItem:
        item = self._node(source.id, source.display_name, NodeKind.SOURCE)
        item.setData(source, TreeRole.SOURCE)
        item.setData(self._unread.get(source.id, 0), TreeRole.UNREAD)
        item.setData(source.id in self._pinned, TreeRole.PINNED)
        item.setData(source.id, Qt.ItemDataRole.ToolTipRole)
        item.setData(
            f"{source.display_name}, {source.status.value}", Qt.ItemDataRole.AccessibleTextRole
        )
        return item

    # ------------------------------------------------------------------ badges and pins

    def add_unread(self, counts: dict[str, int]) -> None:
        """Add unread error counts per source id."""
        for source_id, n in counts.items():
            self._unread[source_id] = self._unread.get(source_id, 0) + n
            if (item := self._items.get(source_id)) is not None:
                item.setData(self._unread[source_id], TreeRole.UNREAD)

    def clear_unread(self, source_ids: Iterable[str]) -> None:
        """The user looked at these sources."""
        for source_id in source_ids:
            if self._unread.pop(source_id, 0) and (item := self._items.get(source_id)):
                item.setData(0, TreeRole.UNREAD)

    def unread(self, source_id: str) -> int:
        """Unread error count of a source."""
        return self._unread.get(source_id, 0)

    def set_pinned(self, source_ids: Iterable[str]) -> None:
        """Mark exactly these sources as pinned."""
        self._pinned = set(source_ids)
        for source_id, item in self._items.items():
            if item.data(TreeRole.KIND) == NodeKind.SOURCE:
                item.setData(source_id in self._pinned, TreeRole.PINNED)

    @property
    def pinned(self) -> set[str]:
        """Pinned source ids."""
        return set(self._pinned)
