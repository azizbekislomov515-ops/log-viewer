"""Building blocks of the dashboard pages: cards, the page header, KPI tiles, pills, a
switch and three small painted charts. All text is plain (log-derived values never
reach a rich-text label) and every color comes from the active ``Theme``."""

from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime

from PySide6.QtCore import QPointF, QRectF, QSize, Qt, Signal
from PySide6.QtGui import QColor, QMouseEvent, QPainter, QPainterPath, QPaintEvent, QPen
from PySide6.QtWidgets import (
    QAbstractButton,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QSizePolicy,
    QToolButton,
    QVBoxLayout,
    QWidget,
)

from loglens.gui import theme as themes


def label(text: str = "", *, role: str | None = None, name: str | None = None) -> QLabel:
    """A plain-text label (log-derived text must never be parsed as HTML)."""
    widget = QLabel(text)
    widget.setTextFormat(Qt.TextFormat.PlainText)
    if role:
        widget.setProperty("role", role)
    if name:
        widget.setObjectName(name)
    return widget


def alpha(hexcode: str, a: int) -> QColor:
    """``hexcode`` with alpha ``a`` (0-255)."""
    color = QColor(hexcode)
    color.setAlpha(a)
    return color


class Card(QFrame):
    """A rounded surface with a title row (title left, caption or widget right)."""

    def __init__(self, title: str = "", caption: str = "", parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("card")
        outer = QVBoxLayout(self)
        outer.setContentsMargins(20, 18, 20, 18)
        outer.setSpacing(14)
        self.head = QHBoxLayout()
        self.title = label(title, name="cardTitle")
        self.caption = label(caption, role="hint")
        self.head.addWidget(self.title)
        self.head.addStretch()
        self.head.addWidget(self.caption)
        if title or caption:
            outer.addLayout(self.head)
        self.body = QVBoxLayout()
        self.body.setSpacing(10)
        outer.addLayout(self.body, 1)


class Pill(QLabel):
    """A small rounded tag tinted with one theme color."""

    def __init__(self, text: str = "", color: str = "#8E98A6") -> None:
        super().__init__(text)
        self.setTextFormat(Qt.TextFormat.PlainText)
        self.setSizePolicy(QSizePolicy.Policy.Maximum, QSizePolicy.Policy.Fixed)
        self.set_color(color)

    def set_color(self, color: str) -> None:
        """Retint (text in ``color``, background ``color`` at 15%)."""
        tint = alpha(color, 40)
        self.setStyleSheet(
            f"color: {color}; background: rgba({tint.red()},{tint.green()},{tint.blue()},40);"
            "border-radius: 9px; padding: 2px 9px; font-size: 12px; font-weight: 600;"
        )


class Kpi(Card):
    """A figure tile: label, big value and a delta pill."""

    def __init__(self, caption: str) -> None:
        super().__init__()
        self.setAccessibleName(caption)
        self.label = label(caption, role="hint")
        self.value = label("-", name="kpiValue")
        self.pill = Pill()
        row = QHBoxLayout()
        row.addWidget(self.value)
        row.addStretch()
        row.addWidget(self.pill, 0, Qt.AlignmentFlag.AlignVCenter)
        self.body.addWidget(self.label)
        self.body.addLayout(row)

    def set_value(self, value: str, pill: str, color: str) -> None:
        """Set the figure and its pill (an empty pill hides it)."""
        self.value.setText(value)
        self.pill.setText(pill)
        self.pill.set_color(color)
        self.pill.setVisible(bool(pill))


class PageHeader(QWidget):
    """Title and subtitle, a search box, the alerts bell and the page's main action."""

    searched = Signal(str)
    bell = Signal()

    def __init__(self, title: str, subtitle: str, search: str, action: str) -> None:
        super().__init__()
        self.title = label(title, name="pageTitle")
        self.subtitle = label(subtitle, role="hint")
        column = QVBoxLayout()
        column.setSpacing(2)
        column.addWidget(self.title)
        column.addWidget(self.subtitle)
        self.search = QLineEdit()
        self.search.setPlaceholderText(search)
        self.search.setAccessibleName(search)
        self.search.setClearButtonEnabled(True)
        self.search.setFixedWidth(260)
        self.search.setObjectName("headerSearch")
        self.search.returnPressed.connect(lambda: self.searched.emit(self.search.text().strip()))
        self.bell_btn = QToolButton()
        self.bell_btn.setText("🔔")
        self.bell_btn.setToolTip("Alerts")
        self.bell_btn.setAccessibleName("Alerts")
        self.bell_btn.setObjectName("bellButton")
        self.bell_btn.clicked.connect(self.bell.emit)
        self.action = QPushButton(action)
        self.action.setObjectName("primary")
        self.action.setAccessibleName(action)
        row = QHBoxLayout(self)
        row.setContentsMargins(0, 0, 0, 0)
        row.setSpacing(12)
        row.addLayout(column)
        row.addStretch()
        row.addWidget(self.search)
        row.addWidget(self.bell_btn)
        row.addWidget(self.action)


class Toggle(QAbstractButton):
    """An on/off switch (a checkable button painted as a track and a knob)."""

    def __init__(self, text: str = "", parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setCheckable(True)
        self.setAccessibleName(text)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setFocusPolicy(Qt.FocusPolicy.StrongFocus)
        self.theme = themes.DARK

    def sizeHint(self) -> QSize:
        return QSize(40, 22)

    def paintEvent(self, event: QPaintEvent) -> None:
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        t = self.theme
        track = QRectF(1, 1, 38, 20)
        p.setPen(QPen(QColor(t.accent), 1.5) if self.hasFocus() else Qt.PenStyle.NoPen)
        p.setBrush(QColor(t.accent if self.isChecked() else t.raised))
        p.drawRoundedRect(track, 10, 10)
        p.setPen(Qt.PenStyle.NoPen)
        p.setBrush(QColor(t.canvas if self.isChecked() else t.dim))
        p.drawEllipse(QRectF(21 if self.isChecked() else 4, 4, 14, 14))


class _Chart(QWidget):
    """Shared chart plumbing: a theme and a fixed minimum height."""

    def __init__(self, height: int) -> None:
        super().__init__()
        self.theme = themes.DARK
        self.setMinimumHeight(height)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)

    def _painter(self) -> QPainter:
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        return p


class RateChart(_Chart):
    """All entries per hour (line and area) and ERROR-or-worse (dashed), with time labels."""

    def __init__(self) -> None:
        super().__init__(200)
        self.points: Sequence[tuple[datetime, int, int]] = ()
        self.setAccessibleName("Entries and errors per hour")

    def set_points(self, points: Sequence[tuple[datetime, int, int]]) -> None:
        """(hour start, all entries, errors), oldest first."""
        self.points = points
        total, errors = sum(p[1] for p in points), sum(p[2] for p in points)
        self.setToolTip(f"{total:,} entries and {errors:,} errors in {len(points)} hours")
        self.update()

    def paintEvent(self, event: QPaintEvent) -> None:
        p, t = self._painter(), self.theme
        plot = QRectF(0, 6, self.width(), self.height() - 30)
        for i in range(4):
            y = plot.top() + plot.height() * i / 3
            p.setPen(QPen(QColor(t.border if i < 3 else t.dim), 1))
            p.drawLine(QPointF(plot.left(), y), QPointF(plot.right(), y))
        if len(self.points) < 2:
            return
        peak = max(1, *(pt[1] for pt in self.points))
        step = plot.width() / (len(self.points) - 1)

        def xy(i: int, value: int) -> QPointF:
            return QPointF(plot.left() + i * step, plot.bottom() - value / peak * plot.height())

        line = QPainterPath(xy(0, self.points[0][1]))
        for i, pt in enumerate(self.points[1:], 1):
            line.lineTo(xy(i, pt[1]))
        area = QPainterPath(line)
        area.lineTo(plot.bottomRight())
        area.lineTo(plot.bottomLeft())
        p.fillPath(area, alpha(t.accent, 36))
        p.setPen(QPen(QColor(t.accent), 2))
        p.drawPath(line)
        errors = QPainterPath(xy(0, self.points[0][2]))
        for i, pt in enumerate(self.points[1:], 1):
            errors.lineTo(xy(i, pt[2]))
        pen = QPen(QColor(t.error), 1.6, Qt.PenStyle.DashLine)
        p.setPen(pen)
        p.drawPath(errors)
        p.setPen(QColor(t.dim))
        last = len(self.points) - 1
        for i in range(0, len(self.points), 4):
            text = "Now" if i == last else self.points[i][0].astimezone().strftime("%H:%M")
            x = plot.left() + i * step
            align = Qt.AlignmentFlag.AlignLeft if i == 0 else Qt.AlignmentFlag.AlignHCenter
            p.drawText(QRectF(x - (0 if i == 0 else 30), plot.bottom() + 6, 60, 18), align, text)
        p.drawText(
            QRectF(plot.right() - 60, plot.bottom() + 6, 60, 18), Qt.AlignmentFlag.AlignRight, "Now"
        )


class Donut(_Chart):
    """Shares of a whole as a ring, with a legend underneath (label, color, percent)."""

    def __init__(self) -> None:
        super().__init__(240)
        self.parts: Sequence[tuple[str, int, str]] = ()
        self.setAccessibleName("Entries by source kind")

    def set_parts(self, parts: Sequence[tuple[str, int, str]]) -> None:
        """(label, value, color hex)."""
        self.parts = [part for part in parts if part[1] > 0]
        self.setToolTip(", ".join(f"{name}: {value:,}" for name, value, _ in self.parts))
        self.update()

    def paintEvent(self, event: QPaintEvent) -> None:
        p, t = self._painter(), self.theme
        legend_h = 26 * max(1, len(self.parts))
        side = min(self.width(), self.height() - legend_h - 16) - 8
        ring = QRectF((self.width() - side) / 2, 4, side, side)
        width = max(10.0, side * 0.16)
        inner = ring.adjusted(width / 2, width / 2, -width / 2, -width / 2)
        total = sum(v for _, v, _ in self.parts)
        if not total:
            p.setPen(QPen(QColor(t.raised), width))
            p.drawEllipse(inner)
            p.setPen(QColor(t.dim))
            p.drawText(ring, Qt.AlignmentFlag.AlignCenter, "No entries yet")
            return
        start = 90 * 16
        for _, value, color in self.parts:
            span = -round(value / total * 360 * 16)
            p.setPen(QPen(QColor(color), width, Qt.PenStyle.SolidLine, Qt.PenCapStyle.FlatCap))
            p.drawArc(inner, start, span)
            start += span
        y = ring.bottom() + 18
        for name, value, color in self.parts:
            p.setPen(Qt.PenStyle.NoPen)
            p.setBrush(QColor(color))
            p.drawEllipse(QRectF(0, y + 5, 9, 9))
            p.setPen(QColor(t.text))
            p.drawText(QRectF(18, y, self.width() - 70, 20), Qt.AlignmentFlag.AlignVCenter, name)
            p.setPen(QColor(t.dim))
            p.drawText(
                QRectF(self.width() - 60, y, 60, 20),
                Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter,
                f"{value / total:.0%}",
            )
            y += 26


class DayBars(_Chart):
    """Errors per day as bars; the worst day is drawn in the error color."""

    def __init__(self) -> None:
        super().__init__(200)
        self.days: Sequence[tuple[datetime, int]] = ()
        self.setAccessibleName("Errors per day")

    def set_days(self, days: Sequence[tuple[datetime, int]]) -> None:
        """(day start, errors), oldest first."""
        self.days = days
        self.setToolTip("\n".join(f"{d.astimezone():%a %d %b}: {n:,} errors" for d, n in days))
        self.update()

    def paintEvent(self, event: QPaintEvent) -> None:
        p, t = self._painter(), self.theme
        if not self.days:
            return
        plot = QRectF(0, 4, self.width(), self.height() - 28)
        p.setPen(QPen(QColor(t.border), 1))
        p.drawLine(plot.bottomLeft(), plot.bottomRight())
        peak = max(n for _, n in self.days)
        slot = plot.width() / len(self.days)
        bar = min(26.0, slot * 0.6)
        for i, (day, n) in enumerate(self.days):
            x = plot.left() + i * slot + (slot - bar) / 2
            h = max(2.0, n / peak * plot.height()) if peak else 2.0
            p.setPen(Qt.PenStyle.NoPen)
            p.setBrush(QColor(t.error if n == peak and peak else t.accent))
            p.drawRoundedRect(QRectF(x, plot.bottom() - h, bar, h), 3, 3)
            p.setPen(QColor(t.dim))
            p.drawText(
                QRectF(plot.left() + i * slot, plot.bottom() + 6, slot, 18),
                Qt.AlignmentFlag.AlignHCenter,
                day.astimezone().strftime("%a"),
            )


class ShareRows(_Chart):
    """Name, count and a proportional bar per row; clicking a row emits its key."""

    clicked = Signal(str)
    ROW = 50

    def __init__(self) -> None:
        super().__init__(120)
        self.rows: Sequence[tuple[str, str, int]] = ()
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setAccessibleName("Busiest sources")

    def set_rows(self, rows: Sequence[tuple[str, str, int]]) -> None:
        """(key, display name, count), largest first."""
        self.rows = rows
        self.setMinimumHeight(self.ROW * max(1, len(rows)))
        self.update()

    def mousePressEvent(self, event: QMouseEvent) -> None:
        index = int(event.position().y() // self.ROW)
        if 0 <= index < len(self.rows):
            self.clicked.emit(self.rows[index][0])

    def paintEvent(self, event: QPaintEvent) -> None:
        p, t = self._painter(), self.theme
        if not self.rows:
            p.setPen(QColor(t.dim))
            p.drawText(self.rect(), Qt.AlignmentFlag.AlignCenter, "Nothing stored yet")
            return
        top = max(1, self.rows[0][2])
        w = self.width()
        for i, (_, name, n) in enumerate(self.rows):
            y = i * self.ROW
            p.setPen(QColor(t.text))
            p.drawText(QRectF(0, y, w - 90, 22), Qt.AlignmentFlag.AlignVCenter, name)
            p.setPen(QColor(t.dim))
            p.drawText(
                QRectF(w - 90, y, 90, 22),
                Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter,
                f"{n:,}",
            )
            p.setPen(Qt.PenStyle.NoPen)
            p.setBrush(QColor(t.raised))
            p.drawRoundedRect(QRectF(0, y + 28, w, 6), 3, 3)
            p.setBrush(QColor(t.accent))
            p.drawRoundedRect(QRectF(0, y + 28, max(6.0, w * n / top), 6), 3, 3)
