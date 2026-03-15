from PySide6.QtWidgets import QListWidget


class AlertPanel(QListWidget):
    """Shows intrusion alerts."""

    def add_alert(self, message: str):
        self.insertItem(0, "⚠ " + message)