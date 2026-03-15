from PySide6.QtWidgets import QWidget, QVBoxLayout, QLabel, QTextEdit
from utils.packet_analyzer import PacketAnalyzer

class DetailsPanel(QWidget):
    def __init__(self):
        super().__init__()
        layout = QVBoxLayout(self)
        self.title = QLabel("Packet Details")
        layout.addWidget(self.title)


        self.text = QTextEdit()
        self.text.setReadOnly(True)
        self.text.setPlainText("Select a packet to view details...")
        layout.addWidget(self.text)

        self.details_locked = False
        self.locked_packet = None

    def clear(self):
        self.title.setText("Packet Details")
        self.text.setPlainText("Select a packet to view details...")

    def display(self, pkt):
        if self.details_locked:
            return  # Ignore updates if locked

        # Get summary for basic proto/src/dst info for the header
        summary, _ = PacketAnalyzer.summarize(pkt)
        proto = summary.get("protocol") or "UNKNOWN"
        src = summary.get("src") or "N/A"
        dst = summary.get("dst") or "N/A"

        # Get the rich formatted multiline text
        detail_text = PacketAnalyzer.details(pkt)

        formatted = f"""
Summary: {src} → {dst} ({proto})
---------------------------------------------------
{detail_text}
"""

        self.title.setText(f"Details — {proto}")
        self.text.setPlainText(formatted)
        self.locked_packet = pkt

    def lock(self):
        self.details_locked = True
        self.text.setToolTip("Details are locked. Press Esc or Backspace to unlock.")
    def unlock(self):
        self.details_locked = False
        self.locked_packet = None
        self.clear()
        self.text.setToolTip("")  # Clear the tooltip