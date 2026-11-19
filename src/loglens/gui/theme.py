"""Light and dark themes from one token table: QPalette + one stylesheet + severity colors.

Severity colors follow the Okabe-Ito colorblind-safe palette (vermilion, orange, reddish
purple, sky blue), tuned per theme for >= 4.5:1 contrast on the log background, and every
severity also has a shape so color is never the only cue.
"""

from __future__ import annotations

from dataclasses import dataclass

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor, QFont, QFontDatabase, QGuiApplication, QPalette
from PySide6.QtWidgets import QApplication

from loglens.core.models import Severity

#: Shape drawn in the severity rail (and used in text) per severity.
SEVERITY_GLYPH = {
    Severity.CRITICAL: "◆",
    Severity.ERROR: "▲",
    Severity.WARNING: "●",
    Severity.NOTICE: "○",
    Severity.INFO: "",
    Severity.DEBUG: "·",
    Severity.TRACE: "·",
}
_MONO_FAMILIES = (
    "JetBrains Mono",
    "Iosevka",
    "Cascadia Mono",
    "Fira Code",
    "Source Code Pro",
    "Hack",
    "DejaVu Sans Mono",
    "Liberation Mono",
    "Monospace",
)


@dataclass(frozen=True, slots=True)
class Theme:
    """Color tokens. ``canvas`` is the log background, ``surface`` panels, ``raised``
    hover/selected chrome; ``text``/``dim`` are the two text levels."""

    name: str
    canvas: str
    surface: str
    raised: str
    border: str
    text: str
    dim: str
    accent: str
    on_accent: str
    match: str
    critical: str
    error: str
    warning: str
    notice: str
    ok: str
    #: Categorical colors for service prefixes in merged views (distinct from severities).
    series: tuple[str, ...]

    def severity(self, severity: Severity) -> QColor:
        """Text color for a severity."""
        hexcode = {
            Severity.CRITICAL: self.critical,
            Severity.ERROR: self.error,
            Severity.WARNING: self.warning,
            Severity.NOTICE: self.notice,
        }.get(severity, self.dim if severity <= Severity.DEBUG else self.text)
        return QColor(hexcode)

    def row_tint(self, severity: Severity) -> QColor | None:
        """Faint background for rows that need attention (ERROR and worse)."""
        if severity < Severity.ERROR:
            return None
        color = self.severity(severity)
        color.setAlpha(28 if self.name == "dark" else 22)
        return color

    def series_color(self, key: str) -> QColor:
        """Stable color for a service name (same name, same color, every run)."""
        index = sum(key.encode()) % len(self.series)
        return QColor(self.series[index])


DARK = Theme(
    name="dark",
    canvas="#111418",
    surface="#171B21",
    raised="#222832",
    border="#2C333D",
    text="#DCE1E8",
    dim="#8E98A6",
    accent="#7AB8F5",
    on_accent="#0B1220",
    match="#6B5B12",
    critical="#E895CA",
    error="#F4845A",
    warning="#F2B531",
    notice="#72C4F2",
    ok="#3FBF93",
    series=("#8FB8DE", "#C9A0DC", "#9CCB86", "#E6B88A", "#7FD1C7", "#D9A3A3", "#B8B8E8"),
)

LIGHT = Theme(
    name="light",
    canvas="#FFFFFF",
    surface="#F4F5F7",
    raised="#E6EAF0",
    border="#D3D8DF",
    text="#1B2129",
    dim="#596372",
    accent="#1E66B0",
    on_accent="#FFFFFF",
    match="#FFE58A",
    critical="#A0407C",
    error="#B83A0B",
    warning="#8A5A00",
    notice="#0A6896",
    ok="#0A7A57",
    series=("#2F6DA3", "#7A4C9A", "#3F7A2E", "#9A5B1E", "#1C7A70", "#9A3D3D", "#4E4EA6"),
)


def system_prefers_dark() -> bool:
    """The desktop's color scheme (Qt 6.5+), falling back to the window palette."""
    hints = QGuiApplication.styleHints()
    scheme = hints.colorScheme()
    if scheme != Qt.ColorScheme.Unknown:
        return scheme == Qt.ColorScheme.Dark
    return QGuiApplication.palette().window().color().lightness() < 128


def resolve(preference: str) -> Theme:
    """``system`` / ``light`` / ``dark`` -> a Theme."""
    if preference == "light":
        return LIGHT
    if preference == "dark":
        return DARK
    return DARK if system_prefers_dark() else LIGHT


def mono_font(point_size: float = 9.5) -> QFont:
    """The first installed monospace family from our preference list."""
    installed = set(QFontDatabase.families())
    family = next((f for f in _MONO_FAMILIES if f in installed), "Monospace")
    font = QFont(family)
    font.setPointSizeF(point_size)
    font.setStyleHint(QFont.StyleHint.Monospace)
    return font


def apply(app: QApplication, theme: Theme) -> None:
    """Install palette + stylesheet on the whole application."""
    app.setStyle("Fusion")
    app.setPalette(palette(theme))
    app.setStyleSheet(stylesheet(theme))


def palette(t: Theme) -> QPalette:
    """A QPalette built from the tokens (covers widgets the stylesheet doesn't)."""
    p = QPalette()
    roles = {
        QPalette.ColorRole.Window: t.surface,
        QPalette.ColorRole.WindowText: t.text,
        QPalette.ColorRole.Base: t.canvas,
        QPalette.ColorRole.AlternateBase: t.surface,
        QPalette.ColorRole.Text: t.text,
        QPalette.ColorRole.Button: t.surface,
        QPalette.ColorRole.ButtonText: t.text,
        QPalette.ColorRole.Highlight: t.accent,
        QPalette.ColorRole.HighlightedText: t.on_accent,
        QPalette.ColorRole.ToolTipBase: t.raised,
        QPalette.ColorRole.ToolTipText: t.text,
        QPalette.ColorRole.PlaceholderText: t.dim,
        QPalette.ColorRole.Link: t.accent,
        QPalette.ColorRole.Mid: t.border,
    }
    for role, hexcode in roles.items():
        p.setColor(role, QColor(hexcode))
    for role in (
        QPalette.ColorRole.Text,
        QPalette.ColorRole.WindowText,
        QPalette.ColorRole.ButtonText,
    ):
        p.setColor(QPalette.ColorGroup.Disabled, role, QColor(t.dim))
    return p


def stylesheet(t: Theme) -> str:
    """The one stylesheet. Quiet chrome: hairline borders, no gradients, pill chips."""
    return f"""
    QMainWindow, QDialog {{ background: {t.surface}; }}
    QToolBar {{ background: {t.surface}; border: none; border-bottom: 1px solid {t.border};
                padding: 4px 6px; spacing: 4px; }}
    QToolBar QLabel {{ color: {t.dim}; padding: 0 2px; }}
    QToolButton {{ color: {t.text}; background: transparent; border: 1px solid transparent;
                   border-radius: 5px; padding: 3px 8px; }}
    QToolButton:hover {{ background: {t.raised}; }}
    QToolButton:checked {{ background: {t.raised}; border-color: {t.border}; }}
    QToolButton:focus {{ border-color: {t.accent}; }}
    QToolButton[chip="true"] {{ border: 1px solid {t.border}; border-radius: 11px;
                                padding: 2px 7px; color: {t.dim}; }}
    QToolButton[chip="true"]:checked {{ color: {t.text}; background: {t.raised};
                                        border-color: {t.dim}; }}
    QLineEdit, QComboBox, QPlainTextEdit, QListWidget {{
        background: {t.canvas}; color: {t.text}; border: 1px solid {t.border};
        border-radius: 5px; padding: 3px 6px; selection-background-color: {t.accent};
        selection-color: {t.on_accent}; }}
    QLineEdit:focus, QComboBox:focus, QPlainTextEdit:focus,
    QListWidget:focus {{ border-color: {t.accent}; }}
    QLineEdit[invalid="true"] {{ border-color: {t.error}; }}
    QTabWidget::pane {{ border: none; }}
    QTabBar::tab {{ background: transparent; color: {t.dim}; padding: 6px 12px;
                    border: none; border-bottom: 2px solid transparent; }}
    QTabBar::tab:selected {{ color: {t.text}; border-bottom-color: {t.accent}; }}
    QTabBar::tab:hover {{ color: {t.text}; }}
    QToolButton#tabClose {{ color: {t.dim}; padding: 0 4px; border: none; font-size: 14px; }}
    QToolButton#tabClose:hover {{ color: {t.text}; background: {t.raised}; }}
    QDockWidget {{ color: {t.dim}; }}
    QDockWidget::title {{ background: {t.surface}; padding: 6px 8px;
                          border-bottom: 1px solid {t.border}; }}
    QTreeView, QListView {{ background: {t.surface}; color: {t.text}; border: none;
                            outline: 0; }}
    QTreeView#logView {{ background: {t.canvas}; }}
    QTreeView::item:selected, QListView::item:selected {{ background: {t.raised};
                                                          color: {t.text}; }}
    QHeaderView::section {{ background: {t.surface}; color: {t.dim}; border: none;
                            border-bottom: 1px solid {t.border}; padding: 4px 6px; }}
    QStatusBar {{ background: {t.surface}; color: {t.dim}; border-top: 1px solid {t.border}; }}
    QStatusBar QLabel {{ color: {t.dim}; padding: 0 8px; }}
    QStatusBar QToolButton {{ color: {t.dim}; }}
    QScrollBar:vertical {{ background: transparent; width: 10px; margin: 0; }}
    QScrollBar::handle:vertical {{ background: {t.border}; border-radius: 4px;
                                   min-height: 24px; margin: 1px; }}
    QScrollBar:horizontal {{ background: transparent; height: 10px; margin: 0; }}
    QScrollBar::handle:horizontal {{ background: {t.border}; border-radius: 4px;
                                     min-width: 24px; margin: 1px; }}
    QScrollBar::add-line, QScrollBar::sub-line {{ width: 0; height: 0; }}
    QScrollBar::add-page, QScrollBar::sub-page {{ background: none; }}
    QMenu {{ background: {t.raised}; color: {t.text}; border: 1px solid {t.border};
             padding: 4px; }}
    QMenu::item {{ padding: 5px 18px; border-radius: 4px; }}
    QMenu::item:selected {{ background: {t.accent}; color: {t.on_accent}; }}
    QPushButton {{ background: {t.raised}; color: {t.text}; border: 1px solid {t.border};
                   border-radius: 5px; padding: 5px 14px; }}
    QPushButton:default {{ background: {t.accent}; color: {t.on_accent};
                           border-color: {t.accent}; }}
    QPushButton:focus {{ border-color: {t.accent}; }}
    QLabel#bannerText {{ color: {t.text}; }}
    QFrame#banner {{ background: {t.raised}; border-bottom: 1px solid {t.border}; }}
    QFrame#palette {{ background: {t.raised}; border: 1px solid {t.border};
                      border-radius: 8px; }}
    QLabel#debugOverlay {{ background: rgba(0,0,0,170); color: #E8F0F8;
                           border-radius: 6px; padding: 6px 8px; }}
    QLabel[role="hint"] {{ color: {t.dim}; }}
    QLabel#paneCaption {{ background: {t.surface}; font-weight: 600; padding: 3px 10px;
                          border-bottom: 1px solid {t.border}; }}
    QFrame#palette QListWidget {{ border: none; background: transparent; }}
    QFrame#palette QListWidget::item {{ padding: 5px 6px; border-radius: 4px; }}
    QFrame#palette QListWidget::item:selected {{ background: {t.accent}; color: {t.on_accent}; }}
    """
