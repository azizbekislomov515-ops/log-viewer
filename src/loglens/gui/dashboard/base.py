"""The frame every dashboard page shares: a header and a scrollable body on the canvas."""

from __future__ import annotations

from typing import TYPE_CHECKING

from PySide6.QtCore import Qt
from PySide6.QtGui import QShowEvent
from PySide6.QtWidgets import (
    QFrame,
    QHeaderView,
    QScrollArea,
    QSizePolicy,
    QTableWidget,
    QVBoxLayout,
    QWidget,
)

from loglens.gui import theme as themes
from loglens.gui.dashboard.widgets import PageHeader, Toggle, _Chart

if TYPE_CHECKING:
    from loglens.gui.main_window import MainWindow

#: Severity names as the pages show them, with the shape that goes with each color.
SEVERITY_WORDS = {
    "CRITICAL": "◆ Critical",
    "ERROR": "▲ Error",
    "WARNING": "● Warning",
    "NOTICE": "○ Notice",
}


class DashPage(QWidget):
    """Header + body. Subclasses fill ``self.body`` and override ``refresh``."""

    def __init__(
        self, window: MainWindow, title: str, subtitle: str, search: str, action: str
    ) -> None:
        super().__init__()
        self.w = window
        self.colors = themes.DARK
        self.setObjectName("dashPage")
        self.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
        # The pages share a stack with the log workspace: a hidden page's header must not
        # widen the window when the Sources page and its docks are showing.
        self.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Ignored)
        self.header = PageHeader(title, subtitle, search, action)
        self.header.search.setVisible(bool(search))
        self.header.bell.connect(lambda: window.show_page("alerts"))
        self.header.searched.connect(window.search_everywhere)
        content = QWidget()
        content.setObjectName("dashBody")
        self.body = QVBoxLayout(content)
        self.body.setContentsMargins(0, 0, 4, 0)
        self.body.setSpacing(20)
        scroll = QScrollArea()
        scroll.setObjectName("dashScroll")
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setWidget(content)
        outer = QVBoxLayout(self)
        outer.setContentsMargins(28, 24, 24, 20)
        outer.setSpacing(22)
        outer.addWidget(self.header)
        outer.addWidget(scroll, 1)

    def set_theme(self, theme: themes.Theme) -> None:
        """Restyle painted parts and re-render."""
        self.colors = theme
        for chart in self.findChildren(_Chart):
            chart.theme = theme
            chart.update()
        for toggle in self.findChildren(Toggle):
            toggle.theme = theme
            toggle.update()
        self.refresh()

    def refresh(self) -> None:
        """Re-render from the window's current state (overridden)."""

    def showEvent(self, event: QShowEvent) -> None:
        super().showEvent(event)
        self.refresh()


def clear_layout(layout: QVBoxLayout) -> None:
    """Remove and delete every widget in ``layout`` (detached at once, so nothing old is
    painted until Qt gets round to deleting it)."""
    while layout.count():
        item = layout.takeAt(0)
        if item is not None and (widget := item.widget()) is not None:
            widget.setParent(None)
            widget.deleteLater()


def table(headers: list[str]) -> QTableWidget:
    """A borderless, read-only, row-selecting table for the cards."""
    view = QTableWidget(0, len(headers))
    view.setObjectName("dashTable")
    view.setHorizontalHeaderLabels(headers)
    view.verticalHeader().hide()
    view.setShowGrid(False)
    view.setFocusPolicy(Qt.FocusPolicy.StrongFocus)
    view.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
    view.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
    view.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
    view.setWordWrap(False)
    view.horizontalHeader().setDefaultAlignment(Qt.AlignmentFlag.AlignLeft)
    view.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
    view.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
    view.verticalHeader().setDefaultSectionSize(40)
    return view
