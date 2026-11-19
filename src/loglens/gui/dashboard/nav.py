"""The left navigation bar: logo, one button per page, and who LogLens runs as."""

from __future__ import annotations

import os

from PySide6.QtCore import QPointF, QRectF, QSize, Qt, Signal
from PySide6.QtGui import QColor, QIcon, QPainter, QPainterPath, QPen, QPixmap
from PySide6.QtWidgets import QButtonGroup, QFrame, QHBoxLayout, QPushButton, QVBoxLayout, QWidget

from loglens.gui import theme as themes
from loglens.gui.dashboard.widgets import label

#: (key, label, shortcut) in display order.
PAGES: tuple[tuple[str, str, str], ...] = (
    ("overview", "Overview", "Ctrl+Shift+1"),
    ("timeline", "Timeline", "Ctrl+Shift+2"),
    ("sources", "Sources", "Ctrl+Shift+3"),
    ("access", "Access", "Ctrl+Shift+4"),
    ("alerts", "Alerts", "Ctrl+Shift+5"),
    ("settings", "Settings", "Ctrl+,"),
)


def _glyph(name: str) -> QPainterPath:
    """A 20x20 line icon."""
    path = QPainterPath()
    if name == "overview":
        for x, top in ((4, 10), (9, 6), (14, 12)):
            path.moveTo(x, 17)
            path.lineTo(x, top)
        path.moveTo(2, 17.5)
        path.lineTo(18, 17.5)
    elif name == "timeline":
        path.addRoundedRect(QRectF(3, 4.5, 14, 12.5), 2, 2)
        path.moveTo(3, 8.5)
        path.lineTo(17, 8.5)
        for x in (7, 13):
            path.moveTo(x, 2.5)
            path.lineTo(x, 6)
    elif name == "sources":
        for dy in (0.0, 4.0, 8.0):
            path.moveTo(2.5, 6 + dy)
            path.lineTo(10, 10 + dy)
            path.lineTo(17.5, 6 + dy)
        path.moveTo(2.5, 6)
        path.lineTo(10, 2)
        path.lineTo(17.5, 6)
    elif name == "access":
        path.addEllipse(QPointF(10, 6.5), 3.5, 3.5)
        path.moveTo(3.5, 17.5)
        path.cubicTo(3.5, 12, 16.5, 12, 16.5, 17.5)
    elif name == "alerts":
        path.addRoundedRect(QRectF(2.5, 4.5, 15, 11), 2, 2)
        path.moveTo(3, 5.5)
        path.lineTo(10, 11)
        path.lineTo(17, 5.5)
    elif name == "settings":
        for y, knob in ((6.0, 7.0), (14.0, 13.0)):
            path.moveTo(2.5, y)
            path.lineTo(17.5, y)
            path.addEllipse(QPointF(knob, y), 2.2, 2.2)
    elif name == "logo":
        path.addEllipse(QPointF(9, 9), 6, 6)
        path.moveTo(13.5, 13.5)
        path.lineTo(18, 18)
        path.moveTo(6.5, 8)
        path.lineTo(11.5, 8)
        path.moveTo(6.5, 10.5)
        path.lineTo(10, 10.5)
    return path


def icon(name: str, normal: str, active: str) -> QIcon:
    """``name``'s glyph in ``normal`` color, and in ``active`` when the button is checked."""
    result = QIcon()
    for color, state in ((normal, QIcon.State.Off), (active, QIcon.State.On)):
        pixmap = QPixmap(40, 40)
        pixmap.fill(Qt.GlobalColor.transparent)
        pixmap.setDevicePixelRatio(2.0)
        p = QPainter(pixmap)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        pen = QPen(QColor(color), 1.7)
        pen.setCapStyle(Qt.PenCapStyle.RoundCap)
        pen.setJoinStyle(Qt.PenJoinStyle.RoundJoin)
        p.setPen(pen)
        p.drawPath(_glyph(name))
        p.end()
        result.addPixmap(pixmap, QIcon.Mode.Normal, state)
    return result


class NavBar(QWidget):
    """Page buttons; ``chosen`` carries the page key."""

    chosen = Signal(str)

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("navPanel")
        self.logo = label("LogLens", name="navLogo")
        self.logo_icon = label()
        head = QHBoxLayout()
        head.setContentsMargins(10, 2, 0, 18)
        head.setSpacing(8)
        head.addWidget(self.logo_icon)
        head.addWidget(self.logo)
        head.addStretch()
        self.group = QButtonGroup(self)
        self.buttons: dict[str, QPushButton] = {}
        column = QVBoxLayout(self)
        column.setContentsMargins(4, 4, 4, 4)
        column.setSpacing(4)
        column.addLayout(head)
        for key, text, keys in PAGES:
            button = QPushButton(text)
            button.setProperty("nav", True)
            button.setCheckable(True)
            button.setIconSize(QSize(20, 20))
            button.setToolTip(f"{text} ({keys})")
            button.setAccessibleName(text)
            button.clicked.connect(lambda _=False, k=key: self.chosen.emit(k))
            self.group.addButton(button)
            self.buttons[key] = button
            column.addWidget(button)
        column.addStretch()
        machine = QFrame()
        machine.setObjectName("machine")
        box = QVBoxLayout(machine)
        box.setContentsMargins(12, 10, 12, 10)
        box.setSpacing(1)
        box.addWidget(label("This machine", name="rowTitle"))
        root = os.geteuid() == 0
        self.who = label("Running as root!" if root else "Read-only · not root", role="hint")
        box.addWidget(self.who)
        column.addWidget(machine)
        self.setMinimumWidth(200)

    def select(self, key: str) -> None:
        """Show ``key`` as the current page (without emitting ``chosen``)."""
        self.buttons[key].setChecked(True)

    def set_theme(self, theme: themes.Theme) -> None:
        """Repaint the icons in the theme's colors."""
        for key, button in self.buttons.items():
            button.setIcon(icon(key, theme.dim, theme.accent))
        self.logo_icon.setPixmap(icon("logo", theme.accent, theme.accent).pixmap(20, 20))
