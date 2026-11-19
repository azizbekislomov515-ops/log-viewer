"""LogView: the virtualized log table, its painter (delegate) and the severity map.

* ``LogDelegate`` paints one cell: a severity rail with a shape per level (color is never
  the only cue), dim timestamps, service names in a stable per-service color, search
  matches highlighted inside the message, and a "+N lines" badge on multi-line entries.
* ``SeverityMap`` is the strip beside the scrollbar: the whole tab compressed to its
  height, each pixel row showing the worst severity there, search hits as ticks, and the
  visible window as a frame. Click or drag to jump.
* ``LogView`` combines them with follow-bottom, wrap, column toggles and copy.
"""

from __future__ import annotations

from collections.abc import Callable

from PySide6.QtCore import (
    QEvent,
    QModelIndex,
    QObject,
    QPersistentModelIndex,
    QPoint,
    QRect,
    QSize,
    Qt,
    QTimer,
    Signal,
)
from PySide6.QtGui import (
    QAction,
    QColor,
    QContextMenuEvent,
    QFont,
    QFontMetrics,
    QGuiApplication,
    QKeyEvent,
    QKeySequence,
    QMouseEvent,
    QPainter,
    QPaintEvent,
    QPolygon,
    QWheelEvent,
)
from PySide6.QtWidgets import (
    QAbstractItemView,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QMenu,
    QStyle,
    QStyledItemDelegate,
    QStyleOptionViewItem,
    QTableView,
    QVBoxLayout,
    QWidget,
)

from loglens.core.models import LogEntry, Severity
from loglens.gui import theme as themes
from loglens.gui.log_model import Column, LogTableModel, Role

AnyIndex = QModelIndex | QPersistentModelIndex
RAIL = 14  # px reserved at the left of the message column for the severity shape


class LogDelegate(QStyledItemDelegate):
    """Paints log cells. Kept free of state other than the theme and display flags."""

    def __init__(self, view: LogView) -> None:
        super().__init__(view)
        self._view = view
        self.theme = themes.DARK
        self.wrap = False
        self.inline = "off"  # off | compact | full: explanation shown with each row

    @property
    def variable_rows(self) -> bool:
        """Whether row heights depend on content (wrap, or full inline explanations)."""
        return self.wrap or self.inline == "full"

    def paint(self, painter: QPainter, option: QStyleOptionViewItem, index: AnyIndex) -> None:
        t = self.theme
        rect: QRect = option.rect
        severity: Severity = index.data(Role.SEVERITY)
        selected = bool(option.state & QStyle.StateFlag.State_Selected)
        painter.save()
        if selected:
            color = QColor(t.accent)
            color.setAlpha(60)
            painter.fillRect(rect, color)
        elif (tint := t.row_tint(severity)) is not None:
            painter.fillRect(rect, tint)
        column = index.column()
        text = index.data(Qt.ItemDataRole.DisplayRole) or ""
        painter.setFont(self._view.log_font())
        fm = painter.fontMetrics()
        inner = rect.adjusted(6, 0, -4, 0)
        if column == Column.MESSAGE:
            self._paint_rail(painter, rect, severity)
            inner = rect.adjusted(RAIL + 4, 0, -4, 0)
            self._paint_message(painter, inner, index, text, fm)
        else:
            if column == Column.TIME:
                painter.setPen(QColor(t.dim))
            elif column == Column.SEVERITY:
                painter.setPen(t.severity(severity))
            elif column == Column.SOURCE:
                painter.setPen(t.series_color(text) if text else QColor(t.dim))
            else:  # pragma: no cover
                painter.setPen(QColor(t.text))
            elided = fm.elidedText(text, Qt.TextElideMode.ElideRight, inner.width())
            align = Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignTop
            painter.drawText(inner.adjusted(0, 3, 0, 0), align, elided)
        has_focus = option.state & QStyle.StateFlag.State_HasFocus
        if has_focus and column == Column.MESSAGE:
            painter.setPen(QColor(t.accent))
            painter.drawRect(rect.adjusted(0, 0, -1, -1))
        painter.restore()

    def _paint_rail(self, painter: QPainter, rect: QRect, severity: Severity) -> None:
        color = self.theme.severity(severity)
        cx, cy, r = (
            rect.left() + RAIL // 2 + 1,
            rect.top() + 3 + QFontMetrics(painter.font()).height() // 2,
            4,
        )
        painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(color)
        if severity >= Severity.CRITICAL:
            painter.drawPolygon(
                QPolygon(
                    [
                        QPoint(cx, cy - r - 1),
                        QPoint(cx + r + 1, cy),
                        QPoint(cx, cy + r + 1),
                        QPoint(cx - r - 1, cy),
                    ]
                )
            )
        elif severity >= Severity.ERROR:
            painter.drawPolygon(
                QPolygon(
                    [QPoint(cx, cy - r), QPoint(cx + r, cy + r - 1), QPoint(cx - r, cy + r - 1)]
                )
            )
        elif severity >= Severity.WARNING:
            painter.drawEllipse(QPoint(cx, cy), r - 1, r - 1)
        elif severity >= Severity.NOTICE:
            painter.setBrush(Qt.BrushStyle.NoBrush)
            painter.setPen(color)
            painter.drawEllipse(QPoint(cx, cy), r - 1, r - 1)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing, False)

    def _paint_message(
        self, painter: QPainter, rect: QRect, index: AnyIndex, text: str, fm: QFontMetrics
    ) -> None:
        t = self.theme
        model = index.model()
        if not isinstance(model, LogTableModel):  # pragma: no cover
            return
        extra = int(index.data(Role.EXTRA_LINES) or 0)
        expanded = bool(index.data(Role.EXPANDED))
        badge = f" +{extra} lines" if extra and not expanded else ""
        explanation = index.data(Role.EXPLANATION) if self.inline != "off" else None
        if explanation is not None and self.inline == "compact":
            badge = f"  → {explanation.title}{badge}"
        lines = text.split("\n") if (expanded or self.wrap) else [text]
        if self.wrap:
            lines = [part for line in lines for part in _wrap(line, fm, rect.width())]
        line_h = fm.height()
        y = rect.top() + 3
        spans_for = model.highlighter.spans if index.data(Role.MATCH) else None
        match_bg = QColor(t.match)
        for line in lines:
            x = rect.left()
            if spans_for is not None:
                for start, end in spans_for(line):
                    left = fm.horizontalAdvance(line[:start])
                    width = fm.horizontalAdvance(line[start:end])
                    painter.fillRect(QRect(x + left, y, width, line_h), match_bg)
            painter.setPen(QColor(t.text))
            elided = (
                line
                if self.wrap
                else fm.elidedText(
                    line, Qt.TextElideMode.ElideRight, rect.width() - fm.horizontalAdvance(badge)
                )
            )
            painter.drawText(QRect(x, y, rect.width(), line_h), Qt.AlignmentFlag.AlignLeft, elided)
            y += line_h
        if explanation is not None and self.inline == "full":
            painter.setPen(QColor(t.dim))
            note = fm.elidedText(
                f"↳ {explanation.plain_text}", Qt.TextElideMode.ElideRight, rect.width()
            )
            painter.drawText(
                QRect(rect.left(), y, rect.width(), line_h), Qt.AlignmentFlag.AlignLeft, note
            )
        if badge:
            painter.setPen(QColor(t.dim))
            width = min(fm.horizontalAdvance(badge), rect.width() // 2)
            badge = fm.elidedText(badge, Qt.TextElideMode.ElideRight, width)
            painter.drawText(
                QRect(rect.right() - width, rect.top() + 3, width, line_h),
                Qt.AlignmentFlag.AlignTop | Qt.AlignmentFlag.AlignRight,
                badge,
            )

    def sizeHint(self, option: QStyleOptionViewItem, index: AnyIndex) -> QSize:
        """One line, or every line of an expanded/wrapped message."""
        fm = QFontMetrics(self._view.log_font())
        base = fm.height() + 6
        if index.column() != Column.MESSAGE:
            return QSize(fm.horizontalAdvance(str(index.data() or "")) + 12, base)
        expanded = bool(index.data(Role.EXPANDED))
        note = 1 if self.inline == "full" and index.data(Role.EXPLANATION) is not None else 0
        if not (expanded or self.wrap):
            return QSize(200, base + note * fm.height())
        text = str(index.data() or "")
        width = max(self._view.header().sectionSize(Column.MESSAGE) - RAIL - 8, 50)
        lines = text.split("\n")
        if self.wrap:
            lines = [p for line in lines for p in _wrap(line, fm, width)]
        return QSize(200, fm.height() * (len(lines) + note) + 6)


def _wrap(line: str, fm: QFontMetrics, width: int) -> list[str]:
    """Greedy character wrap (log lines rarely have good word breaks)."""
    if fm.horizontalAdvance(line) <= width or not line:
        return [line]
    per_line = max(1, width // max(fm.averageCharWidth(), 1))
    return [line[i : i + per_line] for i in range(0, len(line), per_line)]


class SeverityMap(QWidget):
    """Whole-tab overview: worst severity per pixel row, search ticks, viewport frame."""

    jumpRequested = Signal(int)  # row

    def __init__(self, view: QTableView, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._view = view
        self.theme = themes.DARK
        self.setFixedWidth(12)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setToolTip("Severity map: where errors and search hits are. Click to jump.")
        self.setAccessibleName("Severity map")
        view.verticalScrollBar().valueChanged.connect(self.update)

    def _model(self) -> LogTableModel | None:
        model = self._view.model()
        return model if isinstance(model, LogTableModel) else None

    def paintEvent(self, event: QPaintEvent) -> None:
        model = self._model()
        painter = QPainter(self)
        t = self.theme
        painter.fillRect(self.rect(), QColor(t.surface))
        rows = model.rowCount() if model else 0
        height = self.height()
        if not rows or not height or model is None:
            return
        block_rows, blocks = model.severity_blocks()
        per_px = rows / height
        for y in range(height):
            first = int(y * per_px) // block_rows
            last = max(first + 1, int((y + 1) * per_px) // block_rows + 1)
            worst = max(blocks[first:last], default=0)
            if worst >= Severity.ERROR:  # trouble: full width
                painter.fillRect(1, y, self.width() - 2, 1, t.severity(Severity(worst)))
            elif worst == Severity.WARNING:  # noise level: a thin mark, so errors stand out
                painter.fillRect(self.width() - 4, y, 3, 1, t.severity(Severity.WARNING))
        painter.setPen(QColor(t.accent))
        for row in model.match_rows[:: max(1, len(model.match_rows) // 2000)]:
            y = int(row / per_px)
            painter.drawLine(0, y, 3, y)
        first_visible = self._view.rowAt(0)
        last_visible = self._view.rowAt(self._view.viewport().height() - 1)
        if first_visible >= 0:
            last_visible = rows - 1 if last_visible < 0 else last_visible
            top, bottom = int(first_visible / per_px), int((last_visible + 1) / per_px)
            frame = QColor(t.text)
            frame.setAlpha(60)
            painter.fillRect(0, top, self.width(), max(bottom - top, 3), frame)

    def mousePressEvent(self, event: QMouseEvent) -> None:
        self._jump(event)

    def mouseMoveEvent(self, event: QMouseEvent) -> None:
        if event.buttons() & Qt.MouseButton.LeftButton:
            self._jump(event)

    def _jump(self, event: QMouseEvent) -> None:
        model = self._model()
        if model and model.rowCount():
            row = int(event.position().y() / max(self.height(), 1) * model.rowCount())
            self.jumpRequested.emit(max(0, min(row, model.rowCount() - 1)))


class LogTree(QTableView):
    """The table. A QTableView, not a QTreeView: at 1M rows QTreeView relays out every row
    on each append (~0.8 s), QTableView stays at ~6 ms. Row heights live in the (hidden)
    vertical header, so expanded or wrapped rows only resize themselves."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("logView")
        self.setShowGrid(False)
        self.setWordWrap(False)
        self.setCornerButtonEnabled(False)
        self.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        self.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.setVerticalScrollMode(QAbstractItemView.ScrollMode.ScrollPerPixel)
        self.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.setTabKeyNavigation(False)
        self.setAccessibleName("Log entries")
        self.verticalHeader().hide()
        self.verticalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Fixed)
        self.verticalHeader().setMinimumSectionSize(8)
        header = self.horizontalHeader()
        header.setStretchLastSection(True)
        header.setHighlightSections(False)
        header.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        header.setDefaultAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
        header.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)

    def header(self) -> QHeaderView:
        """The column header (QTreeView-compatible name)."""
        return self.horizontalHeader()


class LogView(QWidget):
    """One log table with its severity map. Owns follow/wrap state for its view."""

    copied = Signal(int, str)  # count, format
    followChanged = Signal(bool)

    def __init__(self, model: LogTableModel, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.model = model
        self.tree = LogTree(self)
        self.tree.setModel(model)
        self.delegate = LogDelegate(self)
        self.tree.setItemDelegate(self.delegate)
        self.map = SeverityMap(self.tree, self)
        self.map.jumpRequested.connect(self.go_to_row)
        self.caption = QLabel(self)
        self.caption.setTextFormat(Qt.TextFormat.PlainText)  # service names come from labels
        self.caption.setObjectName("paneCaption")
        self.caption.hide()
        row = QHBoxLayout()
        row.setContentsMargins(0, 0, 0, 0)
        row.setSpacing(0)
        row.addWidget(self.tree)
        row.addWidget(self.map)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        layout.addWidget(self.caption)
        layout.addLayout(row)
        self.follow = True
        #: Extra context-menu actions supplied by the window (explain, report, export).
        self.context_actions: Callable[[], list[QAction]] | None = None
        self._tall_rows: set[int] = set()  # rows whose height differs from the default
        self._fit_timer = QTimer(self)
        self._fit_timer.setSingleShot(True)
        self._fit_timer.setInterval(0)
        self._fit_timer.timeout.connect(self._fit_visible_rows)
        model.rowsAppended.connect(self._on_appended)
        model.modelReset.connect(self._on_reset)
        model.rowsRemoved.connect(lambda *_: self._on_reset())
        model.blocksChanged.connect(self.map.update)
        model.searchFinished.connect(lambda *_: self.map.update())
        model.dataChanged.connect(
            lambda *_: self.delegate.variable_rows and self._fit_timer.start()
        )
        self.tree.doubleClicked.connect(self._toggle_row)
        self.tree.header().customContextMenuRequested.connect(self._header_menu)
        self.tree.verticalScrollBar().valueChanged.connect(self._on_scrolled)
        self.tree.installEventFilter(self)
        self.tree.viewport().installEventFilter(self)
        self._apply_widths()

    def log_font(self) -> QFont:
        """The font rows are painted with."""
        return self.tree.font()

    def header(self) -> QHeaderView:
        """The table header (column widths)."""
        return self.tree.header()

    def set_caption(self, text: str, color: str) -> None:
        """Show a title above the table (used for split panes)."""
        self.caption.setText(text)
        self.caption.setStyleSheet(f"color: {color};")
        self.caption.setAccessibleName(f"{text} log")
        self.tree.setAccessibleName(f"Log entries of {text}")
        self.caption.show()

    def set_theme(self, theme: themes.Theme) -> None:
        """Repaint with another theme."""
        self.delegate.theme = theme
        self.map.theme = theme
        self.tree.viewport().update()
        self.map.update()

    def set_font(self, font: QFont) -> None:
        """Use the monospace log font."""
        self.tree.setFont(font)
        self._apply_widths()

    def row_height(self) -> int:
        """Height of a one-line row for the current font."""
        return QFontMetrics(self.tree.font()).height() + 6

    def _apply_widths(self) -> None:
        fm = QFontMetrics(self.tree.font())
        self.tree.verticalHeader().setDefaultSectionSize(self.row_height())
        header = self.tree.header()
        header.resizeSection(Column.TIME, fm.horizontalAdvance("00-00 00:00:00.000") + 16)
        header.resizeSection(Column.SOURCE, fm.horizontalAdvance("clamav-freshclam") + 16)
        header.resizeSection(Column.SEVERITY, fm.horizontalAdvance("CRITICAL") + 16)

    # ------------------------------------------------------------------ follow / wrap

    def set_wrap(self, wrap: bool) -> None:
        """Wrap long messages. Only rows on screen are measured (and re-measured as you
        scroll), so wrapping stays cheap with a million rows."""
        self.delegate.wrap = wrap
        self._apply_row_mode()

    def set_inline(self, mode: str) -> None:
        """Show explanations with rows: off, compact (title after the message) or full
        (a second line under explained rows)."""
        self.delegate.inline = mode
        self._apply_row_mode()

    def _apply_row_mode(self) -> None:
        if self.delegate.variable_rows:
            self._fit_visible_rows()
        else:
            self._reset_heights(keep_expanded=True)
        self.tree.viewport().update()

    def _visible_rows(self) -> range:
        tree = self.tree
        first = tree.rowAt(0)
        if first < 0:
            return range(0)
        last = tree.rowAt(tree.viewport().height() - 1)
        last = self.model.rowCount() - 1 if last < 0 else last
        return range(first, last + 1)

    def _fit_visible_rows(self) -> None:
        if not self.delegate.variable_rows:
            return
        header = self.tree.verticalHeader()
        option = QStyleOptionViewItem()
        for row in self._visible_rows():
            index = self.model.index(row, Column.MESSAGE)
            height = self.delegate.sizeHint(option, index).height()
            if header.sectionSize(row) != height:
                header.resizeSection(row, height)
                self._tall_rows.add(row)

    def _reset_heights(self, *, keep_expanded: bool) -> None:
        header = self.tree.verticalHeader()
        default = header.defaultSectionSize()
        for row in list(self._tall_rows):
            if row >= self.model.rowCount():
                self._tall_rows.discard(row)
                continue
            if keep_expanded and self.model.index(row, 0).data(Role.EXPANDED):
                continue
            header.resizeSection(row, default)
            self._tall_rows.discard(row)

    def _on_appended(self, _count: int) -> None:
        if self.follow:
            self.tree.scrollToBottom()
        if self.delegate.variable_rows:
            self._fit_timer.start()

    def _on_reset(self) -> None:
        self._tall_rows.clear()
        if self.follow:
            self.tree.scrollToBottom()
        if self.delegate.variable_rows:
            self._fit_timer.start()

    def _on_scrolled(self, value: int) -> None:
        bar = self.tree.verticalScrollBar()
        if self.delegate.variable_rows:
            self._fit_timer.start()
        at_bottom = value >= bar.maximum() - 2
        if self.follow and not at_bottom and bar.isSliderDown():
            self.set_follow(False)  # the user grabbed the scrollbar: stop following
        elif not self.follow and at_bottom and bar.isSliderDown():
            self.set_follow(True)

    def set_follow(self, follow: bool) -> None:
        """Keep the newest entry in view (emits ``followChanged``)."""
        if follow != self.follow:
            self.follow = follow
            self.followChanged.emit(follow)
        if follow:
            self.tree.scrollToBottom()

    def go_to_row(self, row: int) -> None:
        """Scroll to and select ``row`` (stops following)."""
        if not 0 <= row < self.model.rowCount():
            return
        if row != self.model.rowCount() - 1:
            self.set_follow(False)
        index = self.model.index(row, Column.MESSAGE)
        self.tree.scrollTo(index, QAbstractItemView.ScrollHint.PositionAtCenter)
        self.tree.setCurrentIndex(index)

    def current_row(self) -> int:
        """Row of the current index, or the first visible row."""
        current = self.tree.currentIndex()
        if current.isValid():
            return current.row()
        return max(self.tree.rowAt(0), 0)

    def _toggle_row(self, index: QModelIndex) -> None:
        row = index.row()
        expanded = self.model.toggle_expanded(row)
        header = self.tree.verticalHeader()
        if expanded or self.delegate.variable_rows:
            height = self.delegate.sizeHint(
                QStyleOptionViewItem(), self.model.index(row, Column.MESSAGE)
            ).height()
            header.resizeSection(row, height)
            self._tall_rows.add(row)
        else:
            header.resizeSection(row, header.defaultSectionSize())
            self._tall_rows.discard(row)

    # ------------------------------------------------------------------ menus and copy

    def _header_menu(self, pos: QPoint) -> None:
        menu = QMenu(self)
        header = self.tree.header()
        for column in Column:
            if column == Column.MESSAGE:
                continue
            action = menu.addAction(self.model.headerData(column, Qt.Orientation.Horizontal))
            action.setCheckable(True)
            action.setChecked(not header.isSectionHidden(column))
            action.toggled.connect(lambda on, c=column: header.setSectionHidden(c, not on))
        menu.exec(header.mapToGlobal(pos))

    def contextMenuEvent(self, event: QContextMenuEvent) -> None:
        menu = QMenu(self)
        rows = self.selected_rows()
        copy_text = menu.addAction("Copy as text")
        copy_text.setShortcut(QKeySequence.StandardKey.Copy)
        copy_json = menu.addAction("Copy as JSON")
        copy_text.setEnabled(bool(rows))
        copy_json.setEnabled(bool(rows))
        index = self.tree.indexAt(self.tree.viewport().mapFromGlobal(event.globalPos()))
        toggle: QAction | None = None
        if index.isValid() and index.data(Role.EXTRA_LINES):
            toggle = menu.addAction(
                "Collapse lines" if index.data(Role.EXPANDED) else "Expand lines"
            )
        if self.context_actions is not None:
            menu.addSeparator()
            for action in self.context_actions():
                menu.addAction(action)
        chosen = menu.exec(event.globalPos())
        if chosen is copy_text:
            self.copy_selected(as_json=False)
        elif chosen is copy_json:
            self.copy_selected(as_json=True)
        elif toggle is not None and chosen is toggle:
            self._toggle_row(index)

    def selected_rows(self) -> list[int]:
        """Selected row numbers, ascending."""
        return sorted({i.row() for i in self.tree.selectionModel().selectedRows()})

    def copy_selected(
        self, *, as_json: bool, clipboard: Callable[[str], None] | None = None
    ) -> None:
        """Copy the selected entries (fetching unloaded ones in the background)."""
        rows = self.selected_rows()
        if not rows:
            return
        put = clipboard or (lambda text: QGuiApplication.clipboard().setText(text))

        def done(entries: list[LogEntry]) -> None:
            put(LogTableModel.as_json(entries) if as_json else LogTableModel.as_text(entries))
            self.copied.emit(len(entries), "JSON" if as_json else "text")

        self.model.entries_for_rows(rows, done)

    def eventFilter(self, watched: QObject, event: QEvent) -> bool:
        if (
            watched is self.tree.viewport()
            and event.type() == QEvent.Type.Resize
            and self.delegate.variable_rows
        ):
            self._fit_timer.start()
        wheel_up = isinstance(event, QWheelEvent) and event.angleDelta().y() > 0
        if watched is self.tree and wheel_up and self.follow:
            self.set_follow(False)
        if (
            watched is self.tree
            and isinstance(event, QKeyEvent)
            and event.type() == QEvent.Type.KeyPress
        ):
            key = event
            if key.matches(QKeySequence.StandardKey.Copy):
                self.copy_selected(as_json=False)
                return True
            if key.key() in (Qt.Key.Key_Return, Qt.Key.Key_Enter, Qt.Key.Key_Space):
                current = self.tree.currentIndex()
                if current.isValid():
                    self._toggle_row(current)
                    return True
            if key.key() == Qt.Key.Key_End:
                self.set_follow(True)
            elif key.key() in (Qt.Key.Key_Up, Qt.Key.Key_PageUp, Qt.Key.Key_Home):
                self.set_follow(False)
        return super().eventFilter(watched, event)
