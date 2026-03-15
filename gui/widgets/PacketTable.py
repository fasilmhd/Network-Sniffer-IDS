# gui/widgets/PacketTable.py
# ─────────────────────────────────────────────────────────────────────────────
# Optimized: no PacketAnalyzer.summarize() on the GUI thread.
# Accepts pre-computed summary dict via add_packet_with_summary().
# Limits table to MAX_ROWS rows (oldest pruned automatically).
# ─────────────────────────────────────────────────────────────────────────────

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QTableWidget, QTableWidgetItem, QHeaderView, QLabel, QHBoxLayout
)
from PySide6.QtCore import Signal, Qt, QTimer
from PySide6.QtGui import QColor, QBrush

from utils.constants import AppConstants

MAX_ROWS = 500   # never accumulate more than this in the table


class PacketTable(QWidget):
    packet_selected = Signal(object)

    def __init__(self, details_panel):
        super().__init__()
        self.details_panel = details_panel
        self.packets = []
        self._total_seen = 0   # total packets ever received (for display)
        self._scroll_pending = False
        
        # Buffer for high-performance packet insertion
        self._buffer = []
        self._flush_timer = QTimer(self)
        self._flush_timer.setInterval(250)  # Flush 4 times a second
        self._flush_timer.timeout.connect(self._flush_buffer)
        self._flush_timer.start()

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(2)

        # Counter bar
        counter_row = QHBoxLayout()
        self._count_lbl = QLabel("Packets: 0  (showing last 500)")
        self._count_lbl.setStyleSheet("color: #888; font-size: 10px; padding: 2px 4px;")
        counter_row.addWidget(self._count_lbl)
        counter_row.addStretch()
        layout.addLayout(counter_row)

        self.table = QTableWidget()
        self.table.setColumnCount(6)
        self.table.setHorizontalHeaderLabels(
            ["#", "Time", "Source", "Dest", "Proto", "Info"]
        )
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.Stretch)
        self.table.itemSelectionChanged.connect(self._on_select)
        self.table.setAlternatingRowColors(True)
        layout.addWidget(self.table)

    # ── Called by packet_analyzed signal (summary pre-computed) ──────────────

    def add_packet_batch(self, batch: list):
        """Receive a batch of (pkt, summary, alerts) from the capture engine."""
        for pkt, summary, alerts in batch:
            self._total_seen += 1
            self._buffer.append((self._total_seen, pkt, summary, alerts))

    def _flush_buffer(self):
        if not self._buffer:
            return

        items = self._buffer[:]
        self._buffer.clear()

        self.table.setUpdatesEnabled(False)
        self.table.blockSignals(True)

        # ── Prune oldest row to keep table bounded ───────────────────────────
        target_len = self.table.rowCount() + len(items)
        if target_len > MAX_ROWS:
            diff = target_len - MAX_ROWS
            for _ in range(diff):
                if self.table.rowCount() > 0:
                    self.table.removeRow(0)
                if self.packets:
                    self.packets.pop(0)

        for pkt_id, pkt, summary, alerts in items:
            idx = self.table.rowCount()
            self.table.insertRow(idx)

            # Use pre-computed info — NO pyshark str() calls on GUI thread
            info = summary.get("info") or ""

            # Colour row by ML label
            ml_label = summary.get("ml_label", "")
            row_colour = None
            if ml_label and ml_label not in ("BENIGN", "UNKNOWN", ""):
                row_colour = QColor(60, 20, 20)   # dark red tint for attacks

            values = [
                str(pkt_id),
                summary.get("timestamp") or "",
                summary.get("src")       or "",
                summary.get("dst")       or "",
                summary.get("protocol")  or "",
                info,
            ]

            for col, val in enumerate(values):
                item = QTableWidgetItem(val)
                if row_colour:
                    item.setBackground(QBrush(row_colour))
                self.table.setItem(idx, col, item)

            self.packets.append(pkt)

        self.table.blockSignals(False)
        self.table.setUpdatesEnabled(True)

        # Only auto-scroll if not examining a row, throttle to avoid UI lock
        if not getattr(self.details_panel, "details_locked", False):
            if not self._scroll_pending:
                self._scroll_pending = True
                QTimer.singleShot(100, self._do_scroll)

        self._count_lbl.setText(
            f"Packets captured: {self._total_seen:,}  (showing last {MAX_ROWS})"
        )

    def _do_scroll(self):
        self._scroll_pending = False
        self.table.scrollToBottom()

    def add_packet_with_summary(self, pkt, summary: dict, alerts: list):
        """Compatibility shim — adds a single packet as a 1-item batch."""
        self.add_packet_batch([(pkt, summary, alerts)])

    def add_packet(self, pkt):
        """
        Compatibility shim — called when only the raw packet is available.
        Does a lightweight summary without ML.
        """
        try:
            from utils.packet_analyzer import PacketAnalyzer
            summary, alerts = PacketAnalyzer.summarize(pkt)
        except Exception:
            summary, alerts = {}, []
        self.add_packet_with_summary(pkt, summary, alerts)

    def clear(self):
        self.table.setRowCount(0)
        self.packets.clear()
        self._total_seen = 0
        self._count_lbl.setText("Packets: 0  (showing last 500)")

    def _on_select(self):
        if getattr(self.details_panel, "details_locked", False):
            return
        row = self.table.currentRow()
        if 0 <= row < len(self.packets):
            self.packet_selected.emit(self.packets[row])