# gui/widgets/ProcessManagerPanel.py
# ─────────────────────────────────────────────────────────────────────────────
# Premium Process Manager with:
#  - Live auto-refresh (every 3 s)
#  - Sortable table: PID, Name, CPU%, RAM, Status, Network Connections
#  - Colour-coded CPU/RAM bars
#  - Search / filter box
#  - Kill process with confirmation
#  - Suspicious process highlighting (high CPU + network activity)
# ─────────────────────────────────────────────────────────────────────────────

import logging
import psutil

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QTableWidget, QTableWidgetItem,
    QPushButton, QLineEdit, QLabel, QHeaderView, QMessageBox, QProgressBar,
    QAbstractItemView, QCheckBox
)
from PySide6.QtCore import Qt, QTimer, Signal
from PySide6.QtGui import QFont, QColor, QBrush, QIcon

logger = logging.getLogger("ProcessManagerPanel")

_SUSPICIOUS_CPU  = 80.0   # % CPU that flags a process
_SUSPICIOUS_CONN = 10     # connections that flags a process


def _bar_colour(pct: float) -> str:
    if pct >= 80:
        return "#FF3B5C"
    if pct >= 50:
        return "#FF9900"
    return "#27AE60"

_SYSTEM_PROCS = {
    "svchost.exe", "system idle process", "system", "registry", "smss.exe", 
    "csrss.exe", "wininit.exe", "services.exe", "lsass.exe", "fontdrvhost.exe", 
    "dwm.exe", "explorer.exe", "taskhostw.exe", "runtimebroker.exe", 
    "searchindexer.exe", "searchhost.exe", "startmenuexperiencehost.exe", 
    "spoolsv.exe", "conhost.exe", "wmiprvse.exe", "dashost.exe", "sihost.exe", 
    "ctfmon.exe", "dllhost.exe", "securityhealthservice.exe", "taskmgr.exe",
    "wlanext.exe", "audiodg.exe", "winlogon.exe", "lsaiso.exe"
}

_PROC_CATEGORIES = {
    "chrome.exe": "🌐 Web Browser",
    "firefox.exe": "🌐 Web Browser",
    "msedge.exe": "🌐 Web Browser",
    "brave.exe": "🌐 Web Browser",
    "opera.exe": "🌐 Web Browser",
    "discord.exe": "💬 Communication",
    "slack.exe": "💬 Communication",
    "teams.exe": "💬 Communication",
    "zoom.exe": "📞 Video Call",
    "code.exe": "💻 Development",
    "pycharm64.exe": "💻 Development",
    "python.exe": "🐍 Python script",
    "java.exe": "☕ Java App",
    "steam.exe": "🎮 Gaming Hub",
    "epicgameslauncher.exe": "🎮 Gaming Hub",
    "spotify.exe": "🎵 Music Player",
    "vlc.exe": "🎬 Media Player",
    "wireshark.exe": "🛡 Network Tool",
    "network_sniffer.exe": "🛡 Security Platform",
}

def _categorize_process(name: str) -> str:
    name_lower = name.lower()
    if name_lower in _PROC_CATEGORIES:
        return _PROC_CATEGORIES[name_lower]
    if name_lower in _SYSTEM_PROCS:
        return "⚙ Windows System"
    if name_lower.endswith(".exe"):
        return "📦 Application"
    return "🔧 Background Task"


class _MiniBar(QProgressBar):
    """Slim progress bar used inside table cells."""
    def __init__(self, value: float, max_val: float = 100.0):
        super().__init__()
        self.setRange(0, int(max_val))
        self.setValue(min(int(value), int(max_val)))
        self.setTextVisible(True)
        self.setFixedHeight(16)
        col = _bar_colour(value / max_val * 100 if max_val else 0)
        self.setStyleSheet(f"""
            QProgressBar {{ border: none; background: #1E1E2E; border-radius: 3px; }}
            QProgressBar::chunk {{ background: {col}; border-radius: 3px; }}
        """)


class ProcessManagerPanel(QWidget):
    """Full-featured, auto-refreshing process manager."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._all_procs = []        # cache of current proc dicts
        self._filter_text = ""
        self._show_system = False
        self._setup_ui()

        # Auto-refresh every 3 seconds
        self._refresh_timer = QTimer(self)
        self._refresh_timer.setInterval(3000)
        self._refresh_timer.timeout.connect(self._refresh)
        self._refresh_timer.start()

        self._refresh()

    # ── UI ───────────────────────────────────────────────────────────────────

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(8)

        # ── Header ──
        header = QHBoxLayout()
        title = QLabel("⚙ Process Manager")
        title.setFont(QFont("Segoe UI", 15, QFont.Bold))
        title.setStyleSheet("color: #E0E0E0;")

        self._count_lbl = QLabel("Loading…")
        self._count_lbl.setStyleSheet("color: #888; font-size: 11px;")

        header.addWidget(title)
        header.addStretch()
        header.addWidget(self._count_lbl)
        layout.addLayout(header)

        # ── Search bar & Filters ──
        search_row = QHBoxLayout()
        self._search = QLineEdit()
        self._search.setPlaceholderText("🔍  Filter by name or PID…")
        self._search.textChanged.connect(self._apply_filter)
        self._search.setStyleSheet("""
            QLineEdit { background:#1E1E2E; color:#DDD; border:1px solid #333;
                        border-radius:6px; padding:6px 10px; font-size:12px; }
            QLineEdit:focus { border:1px solid #5555AA; }
        """)

        self._sys_cb = QCheckBox("Show System Apps")
        self._sys_cb.setStyleSheet("""
            QCheckBox { color: #AAA; font-size: 11px; }
            QCheckBox::indicator { width: 14px; height: 14px; }
        """)
        self._sys_cb.setChecked(self._show_system)
        self._sys_cb.toggled.connect(self._toggle_system_apps)

        refresh_btn = QPushButton("↻ Refresh")
        refresh_btn.setFixedWidth(90)
        refresh_btn.clicked.connect(self._refresh)
        refresh_btn.setStyleSheet("""
            QPushButton { background:#252540; color:#AAA; border:1px solid #444;
                          border-radius:6px; padding:6px; }
            QPushButton:hover { background:#3A3A5A; color:#EEE; }
        """)

        search_row.addWidget(self._search, 1)
        search_row.addWidget(self._sys_cb)
        search_row.addWidget(refresh_btn)
        layout.addLayout(search_row)

        # ── Table ──
        COLS = ["PID", "Process Name", "Category", "CPU %", "RAM (MB)", "Connections", "Status"]
        self._table = QTableWidget()
        self._table.setColumnCount(len(COLS))
        self._table.setHorizontalHeaderLabels(COLS)
        self._table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self._table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self._table.horizontalHeader().setSectionResizeMode(3, QHeaderView.Fixed)
        self._table.horizontalHeader().setSectionResizeMode(4, QHeaderView.Fixed)
        self._table.setColumnWidth(3, 90)
        self._table.setColumnWidth(4, 90)
        self._table.setColumnWidth(5, 90)
        self._table.setColumnWidth(6, 80)
        self._table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self._table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self._table.setAlternatingRowColors(True)
        self._table.setSortingEnabled(True)
        self._table.verticalHeader().setVisible(False)
        self._table.setStyleSheet("""
            QTableWidget { background:#111122; color:#DDD; gridline-color:#222;
                           font-size:12px; border: none; }
            QHeaderView::section { background:#1A1A30; color:#AAA; padding:6px;
                                   border-bottom:1px solid #333; font-size:11px; }
            QTableWidget::item:selected { background:#2A2A55; }
            QTableWidget::item:alternate { background:#161626; }
        """)
        layout.addWidget(self._table, 1)

        # ── Actions bar ──
        actions = QHBoxLayout()

        self._kill_btn = QPushButton("🛑  Kill Process")
        self._kill_btn.setFixedHeight(36)
        self._kill_btn.clicked.connect(self._kill_selected)
        self._kill_btn.setStyleSheet("""
            QPushButton { background:#4A1020; color:#FF6B6B; border:1px solid #882233;
                          border-radius:6px; padding:6px 16px; font-weight:bold; }
            QPushButton:hover { background:#FF3B5C; color:#FFF; }
        """)

        self._status_lbl = QLabel("")
        self._status_lbl.setStyleSheet("color:#888; font-size:11px;")

        legend = QLabel(
            "  🔴 High CPU/Network  (possible threat)"
        )
        legend.setStyleSheet("color:#AA4444; font-size:10px;")

        actions.addWidget(self._kill_btn)
        actions.addWidget(self._status_lbl, 1)
        actions.addWidget(legend)
        layout.addLayout(actions)

    # ── Data ─────────────────────────────────────────────────────────────────

    def _toggle_system_apps(self, checked: bool):
        self._show_system = checked
        self._apply_filter(self._filter_text)

    def _refresh(self):
        procs = []
        for p in psutil.process_iter(
            ["pid", "name", "cpu_percent", "memory_info", "status"]
        ):
            try:
                info = p.info
                # Fetch connections separately — raises on Windows for some procs
                try:
                    conns = len(p.net_connections())
                except Exception:
                    conns = 0
                ram = 0.0
                try:
                    mi = info.get("memory_info")
                    ram = mi.rss / (1024 * 1024) if mi else 0.0
                except Exception:
                    ram = 0.0
                procs.append({
                    "pid":    info["pid"],
                    "name":   info.get("name") or "?",
                    "cpu":    info.get("cpu_percent") or 0.0,
                    "ram":    ram,
                    "conns":  conns,
                    "status": info.get("status") or "?",
                    "category": _categorize_process(info.get("name", "")),
                    "is_system": info.get("name", "").lower() in _SYSTEM_PROCS,
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

        procs.sort(key=lambda x: x["cpu"], reverse=True)
        self._all_procs = procs
        self._apply_filter(self._filter_text)

    def _apply_filter(self, text: str):
        self._filter_text = text.lower()
        
        filtered = []
        for p in self._all_procs:
            if not self._show_system and p["is_system"]:
                continue
            if self._filter_text and self._filter_text not in p["name"].lower() and self._filter_text not in str(p["pid"]):
                continue
            filtered.append(p)

        self._populate_table(filtered)

    def _populate_table(self, procs: list):
        self._table.setSortingEnabled(False)
        self._table.setRowCount(0)

        for row, p in enumerate(procs):
            is_suspicious = p["cpu"] >= _SUSPICIOUS_CPU or p["conns"] >= _SUSPICIOUS_CONN
            self._table.insertRow(row)

            # PID
            item_pid = QTableWidgetItem(str(p["pid"]))
            item_pid.setTextAlignment(Qt.AlignCenter)
            self._table.setItem(row, 0, item_pid)

            # Name
            name_item = QTableWidgetItem(("⚠ " if is_suspicious else "") + p["name"])
            if is_suspicious:
                name_item.setForeground(QBrush(QColor("#FF6B6B")))
            self._table.setItem(row, 1, name_item)

            # Category
            cat_item = QTableWidgetItem(p["category"])
            cat_item.setForeground(QBrush(QColor("#B4B4CE")))
            self._table.setItem(row, 2, cat_item)

            # CPU bar
            cpu_item = QTableWidgetItem(f"{p['cpu']:.1f}%")
            cpu_item.setTextAlignment(Qt.AlignCenter)
            cpu_col = QColor("#FF3B5C") if p["cpu"] >= 80 else (
                QColor("#FF9900") if p["cpu"] >= 50 else QColor("#27AE60")
            )
            cpu_item.setForeground(QBrush(cpu_col))
            self._table.setItem(row, 3, cpu_item)

            # RAM
            ram_item = QTableWidgetItem(f"{p['ram']:.1f}")
            ram_item.setTextAlignment(Qt.AlignCenter)
            self._table.setItem(row, 4, ram_item)

            # Connections
            conn_item = QTableWidgetItem(str(p["conns"]))
            conn_item.setTextAlignment(Qt.AlignCenter)
            if p["conns"] >= _SUSPICIOUS_CONN:
                conn_item.setForeground(QBrush(QColor("#FF9900")))
            self._table.setItem(row, 5, conn_item)

            # Status
            status_item = QTableWidgetItem(p["status"])
            status_item.setTextAlignment(Qt.AlignCenter)
            self._table.setItem(row, 6, status_item)

            # Highlight entire row if suspicious
            if is_suspicious:
                for col in range(7):
                    it = self._table.item(row, col)
                    if it:
                        it.setBackground(QBrush(QColor(60, 15, 15)))

        total  = len(self._all_procs)
        shown  = len(procs)
        suspicious = sum(1 for p in procs if p["cpu"] >= _SUSPICIOUS_CPU or p["conns"] >= _SUSPICIOUS_CONN)
        self._count_lbl.setText(
            f"Showing {shown} of {total} processes  |  ⚠ {suspicious} suspicious"
        )
        self._table.setSortingEnabled(True)

    def _kill_selected(self):
        row = self._table.currentRow()
        if row < 0:
            QMessageBox.warning(self, "No Selection", "Select a process first.")
            return

        pid_item = self._table.item(row, 0)
        name_item = self._table.item(row, 1)
        if not pid_item:
            return

        pid  = int(pid_item.text())
        name = (name_item.text() if name_item else "?").lstrip("⚠ ")

        reply = QMessageBox.question(
            self, "Confirm Kill",
            f"Terminate  {name}  (PID {pid})?\n\nThis cannot be undone.",
            QMessageBox.Yes | QMessageBox.No
        )
        if reply != QMessageBox.Yes:
            return

        try:
            psutil.Process(pid).terminate()
            self._status_lbl.setText(f"✅  Terminated {name} (PID {pid})")
            self._status_lbl.setStyleSheet("color:#27AE60; font-size:11px;")
            self._refresh()
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Could not kill {pid}:\n{e}")
            self._status_lbl.setText(f"❌  Failed: {e}")
            self._status_lbl.setStyleSheet("color:#FF3B5C; font-size:11px;")