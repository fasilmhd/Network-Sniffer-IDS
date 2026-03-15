# gui/widgets/MLAlertToast.py
# ─────────────────────────────────────────────────────────────────────────────
# Floating toast notification for ML-IDS alerts.
# Slides in from the top-right, holds for a few seconds, then fades out.
# Usage:
#   toast = MLAlertToast(parent_window)
#   toast.show_alert("PortScan", "192.168.1.10", confidence=0.97)
# ─────────────────────────────────────────────────────────────────────────────

from PySide6.QtWidgets import QFrame, QVBoxLayout, QHBoxLayout, QLabel, QPushButton
from PySide6.QtCore import Qt, QTimer, QPropertyAnimation, QEasingCurve, QPoint, QRect
from PySide6.QtGui import QColor, QFont

# Severity colour map
_COLOURS = {
    "PortScan":          ("#FF6B35", "#2D1B00"),   # orange
    "DoS":               ("#FF3B5C", "#2D0010"),   # red
    "DDoS":              ("#FF3B5C", "#2D0010"),
    "Botnet":            ("#C044FF", "#1A0030"),   # purple
    "BENIGN":            ("#27AE60", "#001A0A"),   # green (shouldn't normally show)
}
_DEFAULT_COLOUR = ("#FFD700", "#1A1500")           # yellow for unknown


class MLAlertToast(QFrame):
    """One single reusable toast that lives as a child of the main window."""

    def __init__(self, parent):
        super().__init__(parent, Qt.FramelessWindowHint | Qt.Tool)
        self.setObjectName("MLAlertToast")
        self.setAttribute(Qt.WA_TranslucentBackground)
        self.setAttribute(Qt.WA_ShowWithoutActivating)

        self._hide_timer = QTimer(self)
        self._hide_timer.setSingleShot(True)
        self._hide_timer.timeout.connect(self._start_fadeout)

        self._anim = QPropertyAnimation(self, b"pos")
        self._anim.setEasingCurve(QEasingCurve.OutCubic)
        self._anim.setDuration(350)

        self._setup_ui()
        self.hide()

    # ── UI ───────────────────────────────────────────────────────────────────

    def _setup_ui(self):
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)

        self._card = QFrame(self)
        self._card.setObjectName("ToastCard")
        outer.addWidget(self._card)

        card_layout = QVBoxLayout(self._card)
        card_layout.setContentsMargins(16, 12, 16, 12)
        card_layout.setSpacing(6)

        # ── Header row ──
        header_row = QHBoxLayout()

        self._icon_lbl = QLabel("🤖")
        self._icon_lbl.setFont(QFont("Segoe UI Emoji", 18))

        self._title_lbl = QLabel("ML Detection")
        self._title_lbl.setFont(QFont("Segoe UI", 12, QFont.Bold))
        self._title_lbl.setObjectName("ToastTitle")

        close_btn = QPushButton("✕")
        close_btn.setFixedSize(20, 20)
        close_btn.setObjectName("ToastClose")
        close_btn.setCursor(Qt.PointingHandCursor)
        close_btn.clicked.connect(self._dismiss)

        header_row.addWidget(self._icon_lbl)
        header_row.addWidget(self._title_lbl, 1)
        header_row.addWidget(close_btn)
        card_layout.addLayout(header_row)

        # ── Detail row ──
        self._detail_lbl = QLabel()
        self._detail_lbl.setObjectName("ToastDetail")
        self._detail_lbl.setFont(QFont("Segoe UI", 10))
        self._detail_lbl.setWordWrap(True)
        card_layout.addWidget(self._detail_lbl)

        # ── Confidence bar ──
        self._conf_lbl = QLabel()
        self._conf_lbl.setObjectName("ToastConf")
        self._conf_lbl.setFont(QFont("Segoe UI", 9))
        card_layout.addWidget(self._conf_lbl)

        self.setFixedWidth(320)

    # ── Public API ───────────────────────────────────────────────────────────

    def show_custom_alert(self, title: str, description: str, duration_ms: int = 5000):
        """Slide in a general security toast."""
        # Style the card using the default yellow warning style
        accent, bg = _DEFAULT_COLOUR
        self._card.setStyleSheet(f"""
            #ToastCard {{
                background: {bg};
                border: 2px solid {accent};
                border-radius: 12px;
            }}
            #ToastTitle  {{ color: {accent}; }}
            #ToastDetail {{ color: #E0E0E0; font-size: 11px; }}
            #ToastConf   {{ color: #AAAAAA; }}
            #ToastClose  {{
                background: transparent;
                color: #888;
                border: none;
                font-size: 11px;
            }}
            #ToastClose:hover {{ color: #EEE; }}
        """)

        self._title_lbl.setText(f"⚠  {title}")
        self._detail_lbl.setText(description)
        self._conf_lbl.setText("")

        self.adjustSize()
        self._position_top_right()

        self._hide_timer.stop()
        self._anim.stop()

        self.setWindowOpacity(1.0)
        self.show()
        self.raise_()

        end_pos = self._target_pos()
        start_pos = QPoint(end_pos.x() + 340, end_pos.y())
        self.move(start_pos)
        self._anim.setStartValue(start_pos)
        self._anim.setEndValue(end_pos)
        self._anim.start()

        self._hide_timer.start(duration_ms)

    def show_alert(self, label: str, src_ip: str, confidence: float, duration_ms: int = 5000):
        """Slide in a toast. Safe to call from any thread via a signal."""
        # pick colours
        accent, bg = _DEFAULT_COLOUR
        for key, colours in _COLOURS.items():
            if key.lower() in label.lower():
                accent, bg = colours
                break

        # Style the card
        self._card.setStyleSheet(f"""
            #ToastCard {{
                background: {bg};
                border: 2px solid {accent};
                border-radius: 12px;
            }}
            #ToastTitle  {{ color: {accent}; }}
            #ToastDetail {{ color: #E0E0E0; }}
            #ToastConf   {{ color: #AAAAAA; }}
            #ToastClose  {{
                background: transparent;
                color: #888;
                border: none;
                font-size: 11px;
            }}
            #ToastClose:hover {{ color: #EEE; }}
        """)

        conf_bar   = "█" * int(confidence * 10) + "░" * (10 - int(confidence * 10))
        label_upper = label.upper()

        self._title_lbl.setText(f"⚠  {label_upper} Detected")
        self._detail_lbl.setText(f"Source IP: {src_ip}")
        self._conf_lbl.setText(f"Confidence: {confidence:.0%}  {conf_bar}")

        self.adjustSize()
        self._position_top_right()

        # Stop previous timers
        self._hide_timer.stop()
        self._anim.stop()

        self.setWindowOpacity(1.0)
        self.show()
        self.raise_()

        # Slide in from right
        end_pos = self._target_pos()
        start_pos = QPoint(end_pos.x() + 340, end_pos.y())
        self.move(start_pos)
        self._anim.setStartValue(start_pos)
        self._anim.setEndValue(end_pos)
        self._anim.start()

        self._hide_timer.start(duration_ms)

    # ── Internals ────────────────────────────────────────────────────────────

    def _target_pos(self) -> QPoint:
        pw = self.parent()
        if pw is None:
            return QPoint(20, 60)
        gr = pw.geometry()
        x  = gr.width() - self.width() - 20
        y  = 60
        return self.parent().mapToGlobal(QPoint(x, y)) if self.isWindow() else QPoint(x, y)

    def _position_top_right(self):
        self.move(self._target_pos())

    def _start_fadeout(self):
        fade = QPropertyAnimation(self, b"windowOpacity")
        fade.setDuration(500)
        fade.setStartValue(1.0)
        fade.setEndValue(0.0)
        fade.finished.connect(self.hide)
        fade.start()
        self._fade_anim = fade   # keep reference

    def _dismiss(self):
        self._hide_timer.stop()
        self._start_fadeout()
