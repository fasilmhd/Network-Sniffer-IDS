from PySide6.QtWidgets import QDialog, QFormLayout, QLineEdit, QPushButton
from services.config_service import ConfigService
from utils.constants import AppConstants

class SettingsDialog(QDialog):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Settings")
        self.service = ConfigService()
        self.cfg = self.service.load() or {}

        form = QFormLayout(self)
        self.vt_key = QLineEdit(self.cfg.get("vt_api_key",""))
        form.addRow("VirusTotal API Key:", self.vt_key)
        
        self.abuseipdb_key = QLineEdit(self.cfg.get("abuseipdb_api_key", ""))
        form.addRow("AbuseIPDB API Key:", self.abuseipdb_key)

        self.ip_range = QLineEdit(self.cfg.get("default_ip_range",""))
        form.addRow("Default IP Range:", self.ip_range)

        self.port_range = QLineEdit(self.cfg.get("default_port_range",""))
        form.addRow("Default Port Range:", self.port_range)

        save = QPushButton("Save")
        save.clicked.connect(self._save)
        form.addRow(save)

    def _save(self):
        self.cfg["vt_api_key"] = self.vt_key.text()
        self.cfg["abuseipdb_api_key"] = self.abuseipdb_key.text()
        self.cfg["default_ip_range"] = self.ip_range.text()
        self.cfg["default_port_range"] = self.port_range.text()
        
        self.service.save(self.cfg)
        self.accept()