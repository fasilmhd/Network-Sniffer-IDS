from PySide6.QtWidgets import QWidget, QHBoxLayout, QLabel, QComboBox, QPushButton
from PySide6.QtCore import Signal
from PySide6.QtGui import QColor
import psutil, socket

from utils.constants import ProtocolFilters
from utils.animations import AnimationUtils as Anim

class ControlPanel(QWidget):
    start_capture = Signal(str, str)
    start_pcap    = Signal(str, str)  # (pcap_file, protocol)
    stop_capture  = Signal()
    clear_all     = Signal()
    export_data   = Signal()

    def __init__(self, cfg):
        super().__init__()
        self.cfg = cfg
        self.pcap_file = None
        layout = QHBoxLayout(self)

        # Interface dropdown
        self.iface = QComboBox()
        for iface, addrs in psutil.net_if_addrs().items():
            if any(a.family == socket.AF_INET for a in addrs):
                self.iface.addItem(iface)
        layout.addWidget(QLabel("Interface:"))
        layout.addWidget(self.iface)

        # Auto-select active interface
        try:
            from utils.interface_detector import get_active_interface
            active_iface = get_active_interface()
            if active_iface:
                index = self.iface.findText(active_iface)
                if index >= 0:
                    self.iface.setCurrentIndex(index)
        except Exception:
            pass

        # Protocol dropdown
        self.proto = QComboBox()
        self.proto.addItems(ProtocolFilters.list())
        layout.addWidget(QLabel("Protocol:"))
        layout.addWidget(self.proto)

        # Buttons
        self.start_btn  = QPushButton("▶ Start Capture")
        self.stop_btn   = QPushButton("⏹ Stop Capture")
        self.pcap_btn   = QPushButton("📂 Load PCAP")
        self.replay_btn = QPushButton("⏯ Replay Traffic")
        self.clear_btn  = QPushButton("🗑 Clear")
        self.export_btn = QPushButton("💾 Export")

        self.replay_btn.setEnabled(False)  # Disabled until PCAP is loaded

        layout.addWidget(self.start_btn)
        layout.addWidget(self.stop_btn)
        layout.addWidget(self.pcap_btn)
        layout.addWidget(self.replay_btn)
        layout.addWidget(self.clear_btn)
        layout.addWidget(self.export_btn)

        # Signals
        self.start_btn.clicked.connect(self._on_start)
        self.stop_btn.clicked.connect(self.stop_capture.emit)
        self.pcap_btn.clicked.connect(self._load_pcap)
        self.replay_btn.clicked.connect(self._on_replay)
        self.clear_btn.clicked.connect(self.clear_all.emit)
        self.export_btn.clicked.connect(self.export_data.emit)

        # 🎯 Animate feedback on click
        for btn in [self.start_btn, self.stop_btn, self.pcap_btn, self.replay_btn, self.clear_btn, self.export_btn]:
            btn.clicked.connect(lambda _, b=btn: self._animate_button(b))

    def _animate_button(self, btn):
     Anim.bounce_button(btn)
     Anim.animate_button_color(btn, QColor("#333"), QColor("#555777"))

     # ⏱ Reset style after animation ends (500ms)
     from PySide6.QtCore import QTimer
     QTimer.singleShot(500, lambda: btn.setStyleSheet(""))  # or restore default style if needed

    def _on_start(self):
        iface = self.iface.currentText()
        proto = self.proto.currentText()
        self.start_capture.emit(iface, ProtocolFilters.get(proto))

    def _load_pcap(self):
        from PySide6.QtWidgets import QFileDialog
        fname, _ = QFileDialog.getOpenFileName(self, "Open PCAP File", "", "PCAP Files (*.pcap *.pcapng);;All Files (*)")
        if fname:
            self.pcap_file = fname
            self.replay_btn.setEnabled(True)
            self.pcap_btn.setText("📂 Loaded")

    def _on_replay(self):
        if self.pcap_file:
            proto = self.proto.currentText()
            self.start_pcap.emit(self.pcap_file, ProtocolFilters.get(proto))