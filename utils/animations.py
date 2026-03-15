from PySide6.QtCore import (
    QPropertyAnimation,
    QPoint,
    QAbstractAnimation,
    QEasingCurve,
    QVariantAnimation,
)
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QGraphicsOpacityEffect,
    QGraphicsColorizeEffect,
)


class AnimationUtils:
    """
    Static helper methods for common Qt animations:
      - fade_in
      - slide_in
      - bounce_button
      - flash_row
      - animate_bg_color
      - animate_button_color
    """

    @staticmethod
    def fade_in(widget, duration=500):
        effect = QGraphicsOpacityEffect(widget)
        widget.setGraphicsEffect(effect)
        anim = QPropertyAnimation(effect, b"opacity", widget)
        anim.setStartValue(0.0)
        anim.setEndValue(1.0)
        anim.setDuration(duration)
        anim.setEasingCurve(QEasingCurve.OutCubic)
        anim.start(QAbstractAnimation.DeleteWhenStopped)
        return anim

    @staticmethod
    def slide_in(widget, offset=(-200, 0), duration=400):
        start = widget.pos() + QPoint(*offset)
        end = widget.pos()
        widget.move(start)
        anim = QPropertyAnimation(widget, b"pos", widget)
        anim.setStartValue(start)
        anim.setEndValue(end)
        anim.setDuration(duration)
        anim.setEasingCurve(QEasingCurve.OutBack)
        anim.start(QAbstractAnimation.DeleteWhenStopped)
        return anim

    @staticmethod
    def bounce_button(btn, magnitude=6,     duration=300):
        orig = btn.geometry()
        bigger = orig.adjusted(-magnitude, -magnitude, magnitude, magnitude)
        anim = QPropertyAnimation(btn, b"geometry", btn)
        anim.setKeyValueAt(0.2, bigger)
        anim.setKeyValueAt(0.8, orig)
        anim.setDuration(duration)
        anim.setEasingCurve(QEasingCurve.OutBounce)
        anim.start(QAbstractAnimation.DeleteWhenStopped)
    # ✅ Correct debug print
        print(f"Bounced: {btn.text()}")
        return anim

    @staticmethod
    def flash_row(table_widget, row, color=QColor(0, 255, 0, 120), duration=600):
        effect = QGraphicsColorizeEffect(table_widget)
        table_widget.setGraphicsEffect(effect)
        anim = QPropertyAnimation(effect, b"color", table_widget)
        anim.setStartValue(color)
        anim.setEndValue(QColor(0, 0, 0, 0))
        anim.setDuration(duration)
        anim.setEasingCurve(QEasingCurve.InOutQuad)
        anim.start(QAbstractAnimation.DeleteWhenStopped)
        return anim

    @staticmethod
    def animate_bg_color(widget, start: QColor, end: QColor, duration=500):
        anim = QVariantAnimation(widget)
        anim.setStartValue(start)
        anim.setEndValue(end)
        anim.setDuration(duration)
        anim.setEasingCurve(QEasingCurve.InOutCubic)
        anim.valueChanged.connect(
            lambda c: widget.setStyleSheet(
                f"background-color: {c.name(QColor.HexArgb)};"
            )
        )
        widget._bg_anim = anim  # prevent GC
        anim.start()
        return anim

    @staticmethod
    def animate_button_color(btn, start: QColor, end: QColor, duration=400):
        anim = QVariantAnimation(btn)
        anim.setStartValue(start)
        anim.setEndValue(end)
        anim.setDuration(duration)
        anim.setEasingCurve(QEasingCurve.InOutCubic)
        anim.valueChanged.connect(
            lambda c: btn.setStyleSheet(
                f"background-color: {c.name()}; color: white; border-radius:4px;"
            )
        )
        btn._clr_anim = anim  # prevent GC
        anim.start()
        return anim

    @staticmethod
    def fade_window(window, duration=500):
        """
        Fade in (or out) a top-level widget by animating its windowOpacity.
        This avoids all QGraphicsEffect painter warnings.
        """
        # ensure we start invisible
        window.setWindowOpacity(0.0)

        anim = QPropertyAnimation(window, b"windowOpacity", window)
        anim.setStartValue(0.0)
        anim.setEndValue(1.0)
        anim.setDuration(duration)
        anim.setEasingCurve(QEasingCurve.OutCubic)
        anim.start(QAbstractAnimation.DeleteWhenStopped)
        return anim