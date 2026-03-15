from PySide6.QtWidgets import QDialog, QVBoxLayout, QLabel, QPushButton, QHBoxLayout
from PySide6.QtCore import Qt
from utils.constants import AppConstants

class AboutDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("About")
        self.setModal(True)
        self.resize(300,200)

        layout = QVBoxLayout(self)
        lbl = QLabel(f"{AppConstants.APP_NAME}")
        lbl.setAlignment(Qt.AlignCenter)
        lbl.setStyleSheet("font-size:16px;font-weight:bold;")
        layout.addWidget(lbl)

        ver = QLabel(f"Version {AppConstants.VERSION}")
        ver.setAlignment(Qt.AlignCenter)
        layout.addWidget(ver)

        desc = QLabel("Cybersecurity tool for scanning and analyzing network traffic, identifying vulnerabilities, and providing insights to enhance security posture.")
        desc.setWordWrap(True)
        desc.setAlignment(Qt.AlignCenter)
        layout.addWidget(desc)

        h = QHBoxLayout()
        h.addStretch()
        btn = QPushButton("OK"); btn.clicked.connect(self.accept)
        h.addWidget(btn)
        h.addStretch()
        layout.addLayout(h)