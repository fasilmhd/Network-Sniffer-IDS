from PySide6.QtWidgets import QDialog, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QComboBox, QFileDialog, QCheckBox, QLineEdit
from PySide6.QtCore import Qt

class ExportDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Export Packets")
        self.setModal(True)
        self.resize(400,200)

        layout = QVBoxLayout(self)
        fmt_layout = QHBoxLayout()
        fmt_layout.addWidget(QLabel("Format:"))
        self.fmt = QComboBox()
        self.fmt.addItems(["CSV","JSON","XML","PCAP"])
        fmt_layout.addWidget(self.fmt)
        layout.addLayout(fmt_layout)

        path_layout = QHBoxLayout()
        path_layout.addWidget(QLabel("File:"))
        self.path = QLineEdit()
        path_layout.addWidget(self.path)
        btn_b = QPushButton("Browse")
        btn_b.clicked.connect(self._browse)
        path_layout.addWidget(btn_b)
        layout.addLayout(path_layout)

        self.cb_hdr = QCheckBox("Include Headers"); self.cb_hdr.setChecked(True)
        layout.addWidget(self.cb_hdr)
        self.cb_pld = QCheckBox("Include Payload")
        layout.addWidget(self.cb_pld)

        btns = QHBoxLayout()
        btns.addStretch()
        ok = QPushButton("OK"); ok.clicked.connect(self.accept)
        btns.addWidget(ok)
        cn = QPushButton("Cancel"); cn.clicked.connect(self.reject)
        btns.addWidget(cn)
        layout.addLayout(btns)

    def _browse(self):
        ext = self.fmt.currentText().lower()
        fn, _ = QFileDialog.getSaveFileName(self, "Save As", f"packets.{ext}", f"{self.fmt.currentText()} Files (*.{ext})")
        if fn:
            self.path.setText(fn)

    def get_options(self):
        return {
            "format": self.fmt.currentText(),
            "path": self.path.text(),
            "headers": self.cb_hdr.isChecked(),
            "payload": self.cb_pld.isChecked()
        }