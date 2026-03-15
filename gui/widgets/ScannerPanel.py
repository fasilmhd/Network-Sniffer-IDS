# gui/widgets/ScannerPanel.py
# ─────────────────────────────────────────────────────────────────────────────
# "Smart Auto Scan" / Network Discovery Dashboard.
# Automatically detects current network range, scans for active devices,
# identifies vendors using mac-vendor-lookup, and scores network risk.
# ─────────────────────────────────────────────────────────────────────────────

import sys
import threading
from concurrent.futures import ThreadPoolExecutor

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QLabel, QTableWidget,
    QTableWidgetItem, QHeaderView, QProgressBar, QFrame, QGridLayout
)
from PySide6.QtCore import Qt, QThread, Signal
from PySide6.QtGui import QFont, QColor, QBrush

from utils.network_detector import get_local_ip, get_network_range
from core.scanners.port_scanner import ArpHostScanner

# Vendor lookup (safely imported)
try:
    from mac_vendor_lookup import MacLookup
    _mac = MacLookup()
    _mac.update_vendors()  # Cache vendor DB on load if possible
except Exception:
    _mac = None


class _ScanThread(QThread):
    """Background worker for network discovery to prevent freezing."""
    device_found   = Signal(dict)   # {ip, mac, vendor, is_new}
    progress_update = Signal(int)   # 0 to 100
    scan_complete  = Signal(list)   # list of devices

    def __init__(self, subnet: str, known_macs: set):
        super().__init__()
        self.subnet     = subnet
        self.known_macs = known_macs
        self.scanner    = ArpHostScanner()

    def run(self):
        devices = []
        try:
            # scapy ARP scan (blocking)
            self.progress_update.emit(20)
            hosts = self.scanner.discover_hosts(self.subnet)
            self.progress_update.emit(60)

            # Vendor resolution
            total = len(hosts)
            for i, h in enumerate(hosts):
                ip  = h.get("ip", "")
                mac = h.get("mac", "")
                
                vendor = "Unknown"
                if _mac and mac:
                    try:
                        vendor = _mac.lookup(mac)
                    except Exception:
                        pass
                
                is_new = mac not in self.known_macs
                dev = {"ip": ip, "mac": mac, "vendor": vendor, "is_new": is_new}
                devices.append(dev)
                
                self.device_found.emit(dev)
                self.progress_update.emit(60 + int((i+1)/total * 40))

        except Exception as e:
            print("Scan thread error:", e)

        self.progress_update.emit(100)
        self.scan_complete.emit(devices)


class ScannerPanel(QWidget):

    def __init__(self, cfg=None, parent=None):
        super().__init__(parent)
        self._local_ip    = get_local_ip()
        self._subnet      = get_network_range()
        self._known_macs  = set()
        
        # Scoring
        self._score       = 100
        self._devices     = []

        self._setup_ui()

    def _setup_ui(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(12, 12, 12, 12)
        root.setSpacing(12)

        # ── Header ──
        hdr = QHBoxLayout()
        title = QLabel("📡  Auto Network Discovery")
        title.setFont(QFont("Segoe UI", 16, QFont.Bold))
        title.setStyleSheet("color:#E0E0FF;")
        
        self._status_lbl = QLabel(f"Local IP: {self._local_ip}  |  Subnet: {self._subnet}")
        self._status_lbl.setStyleSheet("color:#88AADD; font-size:12px;")

        hdr.addWidget(title)
        hdr.addStretch()
        hdr.addWidget(self._status_lbl)
        root.addLayout(hdr)

        # ── Top Cards ──
        cards = QHBoxLayout()
        
        # Card 1: Risk Score
        self._score_frame = QFrame()
        self._score_frame.setStyleSheet("QFrame { background:#12122A; border:1px solid #2A2A4A; border-radius:8px; }")
        slayout = QVBoxLayout(self._score_frame)
        slayout.setContentsMargins(10, 10, 10, 10)
        s_title = QLabel("Network Security Score")
        s_title.setStyleSheet("color:#7788CC; font-size:10px; font-weight:bold; border:none;")
        self._score_lbl = QLabel("100 / 100")
        self._score_lbl.setFont(QFont("Segoe UI", 24, QFont.Bold))
        self._score_lbl.setStyleSheet("color:#27AE60; border:none;")
        self._risk_lbl = QLabel("🟢  Low Risk")
        self._risk_lbl.setStyleSheet("color:#27AE60; font-size:12px; border:none;")
        slayout.addWidget(s_title)
        slayout.addWidget(self._score_lbl)
        slayout.addWidget(self._risk_lbl)
        cards.addWidget(self._score_frame)

        # Card 2: Summary
        self._sum_frame = QFrame()
        self._sum_frame.setStyleSheet("QFrame { background:#12122A; border:1px solid #2A2A4A; border-radius:8px; }")
        mlayout = QVBoxLayout(self._sum_frame)
        mlayout.setContentsMargins(10, 10, 10, 10)
        m_title = QLabel("Device Summary")
        m_title.setStyleSheet("color:#7788CC; font-size:10px; font-weight:bold; border:none;")
        
        self._dev_count_lbl = QLabel("0 Devices Found")
        self._dev_count_lbl.setStyleSheet("color:#CCC; font-size:12px; border:none;")
        self._new_count_lbl = QLabel("0 New / Unknown")
        self._new_count_lbl.setStyleSheet("color:#FF9900; font-size:12px; border:none;")
        
        mlayout.addWidget(m_title)
        mlayout.addStretch()
        mlayout.addWidget(self._dev_count_lbl)
        mlayout.addWidget(self._new_count_lbl)
        cards.addWidget(self._sum_frame)

        # Card 3: Action
        self._act_frame = QFrame()
        self._act_frame.setStyleSheet("QFrame { background:#12122A; border:1px solid #2A2A4A; border-radius:8px; }")
        alayout = QVBoxLayout(self._act_frame)
        alayout.setContentsMargins(10, 10, 10, 10)
        
        self._scan_btn = QPushButton("🚀  Start Smart Auto Scan")
        self._scan_btn.setFixedHeight(40)
        self._scan_btn.clicked.connect(self._start_scan)
        self._scan_btn.setStyleSheet("""
            QPushButton { background:#3B82F6; color:#FFF; font-weight:bold; font-size:13px;
                          border:none; border-radius:6px; }
            QPushButton:hover { background:#4C93F9; }
            QPushButton:disabled { background:#223344; color:#555; }
        """)
        
        self._progress = QProgressBar()
        self._progress.setFixedHeight(8)
        self._progress.setTextVisible(False)
        self._progress.hide()
        self._progress.setStyleSheet("""
            QProgressBar { background:#1A1A2E; border:none; border-radius:4px; }
            QProgressBar::chunk { background:#3B82F6; border-radius:4px; }
        """)

        alayout.addWidget(self._scan_btn)
        alayout.addStretch()
        alayout.addWidget(self._progress)
        cards.addWidget(self._act_frame)

        root.addLayout(cards)

        # ── Devices Table ──
        table_lbl = QLabel("🔗 Network Devices")
        table_lbl.setStyleSheet("color:#E0E0E0; font-weight:bold; font-size:13px;")
        root.addWidget(table_lbl)

        self._table = QTableWidget()
        self._table.setColumnCount(4)
        self._table.setHorizontalHeaderLabels(["IP Address", "MAC Address", "Device Manufacturer", "Status"])
        self._table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self._table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self._table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        self._table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeToContents)
        self._table.setAlternatingRowColors(True)
        self._table.setEditTriggers(QTableWidget.NoEditTriggers)
        self._table.setShowGrid(False)
        self._table.setStyleSheet("""
            QTableWidget { background:#111122; color:#DDD; border:1px solid #2A2A4A; border-radius:6px; }
            QHeaderView::section { background:#1A1A30; color:#88AADD; padding:6px; border:none; }
            QTableWidget::item:alternate { background:#161626; }
            QTableWidget::item { padding:4px; }
        """)
        root.addWidget(self._table, 1)

    def _start_scan(self):
        self._scan_btn.setEnabled(False)
        self._scan_btn.setText("Scanning Network...")
        self._progress.setValue(0)
        self._progress.show()
        
        self._table.setRowCount(0)
        self._devices = []

        self._thread = _ScanThread(self._subnet, self._known_macs)
        self._thread.device_found.connect(self._add_device_row)
        self._thread.progress_update.connect(self._progress.setValue)
        self._thread.scan_complete.connect(self._scan_finished)
        self._thread.start()

    def _add_device_row(self, dev: dict):
        self._devices.append(dev)
        row = self._table.rowCount()
        self._table.insertRow(row)

        ip_item = QTableWidgetItem(dev["ip"])
        if dev["ip"] == self._local_ip:
            ip_item.setText(f"{dev['ip']} (This PC)")
            ip_item.setForeground(QBrush(QColor("#3B82F6")))
        
        mac_item = QTableWidgetItem(dev["mac"])
        
        vendor_item = QTableWidgetItem(dev["vendor"])
        if dev["vendor"] == "Unknown":
            vendor_item.setForeground(QBrush(QColor("#888")))
            
        status_item = QTableWidgetItem("⚠ New Device" if dev["is_new"] else "✅ Known")
        status_item.setForeground(QBrush(QColor("#FF9900") if dev["is_new"] else QColor("#27AE60")))

        self._table.setItem(row, 0, ip_item)
        self._table.setItem(row, 1, mac_item)
        self._table.setItem(row, 2, vendor_item)
        self._table.setItem(row, 3, status_item)

    def _scan_finished(self, devices: list):
        self._scan_btn.setEnabled(True)
        self._scan_btn.setText("🚀  Start Smart Auto Scan")
        self._progress.hide()

        # Update summary
        new_count = sum(1 for d in devices if d["is_new"])
        self._dev_count_lbl.setText(f"{len(devices)} Devices Found")
        self._new_count_lbl.setText(f"{new_count} New / Unknown")

        # Update MACs
        for d in devices:
            if d["mac"]:
                self._known_macs.add(d["mac"])

        # Calculate Score
        # -10 for every unknown device, max 50 points down
        penalty = min(50, new_count * 10)
        self._score = max(0, 100 - penalty)
        
        self._score_lbl.setText(f"{self._score} / 100")
        
        if self._score >= 90:
            col = "#27AE60" # green
            lbl = "🟢  Low Risk"
        elif self._score >= 60:
            col = "#F39C12" # yellow
            lbl = "🟡  Moderate Risk"
        else:
            col = "#FF3B5C" # red
            lbl = "🔴  High Risk"
            
        self._score_lbl.setStyleSheet(f"color:{col}; border:none;")
        self._risk_lbl.setText(lbl)
        self._risk_lbl.setStyleSheet(f"color:{col}; font-size:12px; border:none;")
        self._score_frame.setStyleSheet(f"QFrame {{ background:#12122A; border:2px solid {col}; border-radius:8px; }}")
