# gui/widgets/SecurityStatusPanel.py
# ─────────────────────────────────────────────────────────────────────────────
# Premium Security Dashboard — 10 live panels:
#  1. Threat Level Indicator (pulsing coloured pill)
#  2. Attack Type Counters  (PortScan / DoS / ARP / ML detections)
#  3. Traffic Rate Monitor  (pkts/s + KB/s, updated every second)
#  4. Top Attacker IPs      (sorted by hit count)
#  5. GeoIP Attack Sources  (country breakdown via geoip_lookup)
#  6. Most Targeted Ports
#  7. Active Connections    (last 8 live flows)
#  8. Firewall Block List
#  9. System Security Check (firewall + AV status)
# 10. Alert Timeline        (scrolling rich-text log)
# ─────────────────────────────────────────────────────────────────────────────

import subprocess
import threading
import collections
from datetime import datetime

import psutil

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QTextEdit,
    QPushButton, QScrollArea, QFrame, QGridLayout, QSizePolicy
)
from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QFont, QColor, QTextCursor, QTextCharFormat, QBrush

from utils.geoip_lookup import get_location
from services.threat_intel import ThreatIntelService

# ── Threat level thresholds ───────────────────────────────────────────────────
_LEVELS = [
    (0,  "SECURE",   "#27AE60", "🟢"),
    (3,  "LOW",      "#2ECC71", "🟢"),
    (10, "MEDIUM",   "#F39C12", "🟡"),
    (25, "HIGH",     "#E67E22", "🟠"),
    (50, "CRITICAL", "#FF3B5C", "🔴"),
]

_PORT_NAMES = {
    21: "FTP",  22: "SSH",   23: "Telnet", 25: "SMTP",
    53: "DNS",  80: "HTTP",  110: "POP3",  143: "IMAP",
    443: "HTTPS", 445: "SMB", 3306: "MySQL", 3389: "RDP",
    8080: "HTTP-Alt", 8443: "HTTPS-Alt",
}


def _level_for(total_attacks: int):
    lvl = _LEVELS[0]
    for threshold, name, colour, emoji in _LEVELS:
        if total_attacks >= threshold:
            lvl = (threshold, name, colour, emoji)
    return lvl


# ── Reusable card widget ──────────────────────────────────────────────────────

class _Card(QFrame):
    """Dark card with a subtle border, title, and a main content area."""

    def __init__(self, title: str, parent=None):
        super().__init__(parent)
        self.setFrameShape(QFrame.StyledPanel)
        self.setStyleSheet("""
            QFrame {
                background: #12122A;
                border: 1px solid #2A2A4A;
                border-radius: 8px;
            }
        """)
        outer = QVBoxLayout(self)
        outer.setContentsMargins(10, 8, 10, 10)
        outer.setSpacing(6)

        hdr = QLabel(title)
        hdr.setFont(QFont("Segoe UI", 9, QFont.Bold))
        hdr.setStyleSheet("color:#7788CC; border:none;")
        outer.addWidget(hdr)

        self.body = QVBoxLayout()
        self.body.setAlignment(Qt.AlignTop)
        self.body.setSpacing(3)
        outer.addLayout(self.body)

    def clear_body(self):
        while self.body.count():
            item = self.body.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

    def add_row(self, left: str, right: str, colour: str = "#CCCCCC"):
        row = QHBoxLayout()
        lbl = QLabel(left)
        lbl.setStyleSheet(f"color:{colour}; font-size:11px; border:none;")
        val = QLabel(right)
        val.setStyleSheet(f"color:{colour}; font-size:11px; font-weight:bold; border:none;")
        val.setAlignment(Qt.AlignRight)
        row.addWidget(lbl, 1)
        row.addWidget(val)
        self.body.addLayout(row)

    def add_label(self, text: str, colour: str = "#CCCCCC", bold: bool = False):
        lbl = QLabel(text)
        lbl.setStyleSheet(
            f"color:{colour}; font-size:11px; border:none;"
            + (" font-weight:bold;" if bold else "")
        )
        lbl.setWordWrap(True)
        self.body.addWidget(lbl)


# ── Main panel ────────────────────────────────────────────────────────────────

class SecurityStatusPanel(QWidget):

    def __init__(self, cfg=None, parent=None):
        super().__init__(parent)
        self._cfg = cfg or {}
        
        # Threat Intel integration
        api_key = self._cfg.get("abuseipdb_api_key", "")
        self.ti_service = ThreatIntelService(api_key) if api_key else None

        # ── State ──────────────────────────────────────────────────────────
        self._attack_counts   = collections.Counter()  # type → count
        self._attacker_ips    = collections.Counter()  # ip → count
        self._geo_countries   = collections.Counter()  # country → count
        self._port_counts     = collections.Counter()  # port → count
        self._active_flows    = collections.deque(maxlen=8)
        self._blocked_ips     = []
        self._total_attacks   = 0
        self._pkt_count       = 0
        self._byte_count      = 0
        self._pkt_per_sec     = 0
        self._byte_per_sec    = 0
        self._total_pkts      = 0     # cumulative (never reset)
        self._total_bytes     = 0     # cumulative (never reset)

        self._setup_ui()

        # ── Dirty-flag rendering throttle ──────────────────────────────
        self._dirty = False
        self._render_timer = QTimer(self)
        self._render_timer.setInterval(500)  # Refresh at most 2x/sec
        self._render_timer.timeout.connect(self._flush_if_dirty)
        self._render_timer.start()

        # 1-second ticker for traffic rate
        self._rate_timer = QTimer(self)
        self._rate_timer.setInterval(1000)
        self._rate_timer.timeout.connect(self._tick_rate)
        self._rate_timer.start()

        # 8-second full refresh for system status
        self._sys_timer = QTimer(self)
        self._sys_timer.setInterval(8000)
        self._sys_timer.timeout.connect(self._refresh_system)
        self._sys_timer.start()
        self._refresh_system()

    def update_config(self, cfg):
        self._cfg = cfg
        api_key = self._cfg.get("abuseipdb_api_key", "")
        if api_key:
            if self.ti_service:
                self.ti_service.api_key = api_key
            else:
                from services.threat_intel import ThreatIntelService
                self.ti_service = ThreatIntelService(api_key)
        else:
            self.ti_service = None


    # ── UI scaffolding ────────────────────────────────────────────────────────

    def _setup_ui(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(10, 10, 10, 10)
        root.setSpacing(8)

        # ── Page header ──
        hdr_row = QHBoxLayout()
        page_title = QLabel("🛡  Security Dashboard")
        page_title.setFont(QFont("Segoe UI", 16, QFont.Bold))
        page_title.setStyleSheet("color:#E0E0FF;")

        self._timestamp_lbl = QLabel("")
        self._timestamp_lbl.setStyleSheet("color:#446; font-size:10px;")

        hdr_row.addWidget(page_title)
        hdr_row.addStretch()
        hdr_row.addWidget(self._timestamp_lbl)
        root.addLayout(hdr_row)

        # ── Threat pill (full width) ──────────────────────────────────────
        self._threat_card = _Card("THREAT LEVEL")
        self._threat_lbl  = QLabel("🟢  SECURE")
        self._threat_lbl.setAlignment(Qt.AlignCenter)
        self._threat_lbl.setFont(QFont("Segoe UI", 22, QFont.Bold))
        self._threat_lbl.setStyleSheet("color:#27AE60; border:none; padding:6px;")
        self._threat_lbl.setFixedHeight(60)
        self._threat_card.body.addWidget(self._threat_lbl)
        root.addWidget(self._threat_card)

        # ── Scrollable grid of cards ──────────────────────────────────────
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)
        scroll.setStyleSheet("QScrollArea { background:transparent; border:none; }")
        scroll_w = QWidget()
        grid = QGridLayout(scroll_w)
        grid.setSpacing(8)
        scroll.setWidget(scroll_w)
        root.addWidget(scroll, 1)

        # Row 0 — attack counters + traffic rate
        self._attacks_card = _Card("⚔  Attack Statistics")
        grid.addWidget(self._attacks_card, 0, 0)

        self._rate_card = _Card("📡  Traffic Rate")
        grid.addWidget(self._rate_card, 0, 1)

        # Row 1 — top attackers + geo sources
        self._attackers_card = _Card("🔴  Top Attacker IPs")
        grid.addWidget(self._attackers_card, 1, 0)

        self._geo_card = _Card("🌍  GeoIP Attack Sources")
        grid.addWidget(self._geo_card, 1, 1)

        # Row 2 — targeted ports + active connections
        self._ports_card = _Card("🎯  Most Targeted Ports")
        grid.addWidget(self._ports_card, 2, 0)

        self._conns_card = _Card("🔗  Active Connections")
        grid.addWidget(self._conns_card, 2, 1)

        # Row 3 — blocked IPs + system status
        self._blocked_card = _Card("🚫  Firewall Block List")
        grid.addWidget(self._blocked_card, 3, 0)

        self._sys_card = _Card("💻  System Security")
        grid.addWidget(self._sys_card, 3, 1)

        # Row 4 — alert timeline (full width)
        timeline_card = _Card("🕐  Alert Timeline")
        self._log = QTextEdit()
        self._log.setReadOnly(True)
        self._log.setFont(QFont("Consolas", 9))
        self._log.setFixedHeight(160)
        self._log.setStyleSheet("""
            QTextEdit { background:#0A0A18; color:#CCC; border:none;
                        border-radius:4px; padding:4px; }
        """)
        timeline_card.body.addWidget(self._log)
        grid.addWidget(timeline_card, 4, 0, 1, 2)

        # Initial renders
        self._render_attacks()
        self._render_traffic()
        self._render_attackers()
        self._render_geo()
        self._render_ports()
        self._render_conns()
        self._render_blocked()

    # ── Public API (called by MainWindow) ─────────────────────────────────────

    def add_alert(self, message: str, alert_type: str = ""):
        """Called by MainWindow on every security event.
        
        Parameters
        ----------
        message   : The human-readable alert string.
        alert_type: Optional pre-classified type from PacketAnalyzer (e.g. 'Port Scan',
                    'DoS / SYN Flood', 'ARP Spoofing', 'DNS Tunneling', 'ML Detection').
        """
        ts  = datetime.now().strftime("%H:%M:%S")
        msg = message.strip()
        ml  = msg.lower()

        # ── Classify (prefer explicit type, fall back to substring match) ───
        _type = alert_type.strip() if alert_type else ""

        if not _type:
            if "port scan" in ml or "portscan" in ml or "scan" in ml:
                _type = "Port Scan"
            elif "syn flood" in ml or "dos" in ml or "flood" in ml or "icmp" in ml:
                _type = "DoS / SYN Flood"
            elif "arp" in ml:
                _type = "ARP Spoofing"
            elif "dns" in ml and "tunnel" in ml:
                _type = "DNS Tunneling"
            elif "ml" in ml and ("detection" in ml or "anomaly" in ml):
                _type = "ML Detection"

        if _type and _type in (
            "Port Scan", "DoS / SYN Flood", "ARP Spoofing",
            "DNS Tunneling", "ML Detection"
        ):
            self._attack_counts[_type] += 1
            self._total_attacks += 1

        # ── Extract attacker IP ──────────────────────────────────────────
        import re
        ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', msg)
        if ips:
            attacker = ips[0]
            self._attacker_ips[attacker] += 1
            threading.Thread(target=self._bg_geo, args=(attacker,), daemon=True).start()
            if self.ti_service:
                threading.Thread(target=self._bg_threat_intel, args=(attacker,), daemon=True).start()

        # ── Active flow ──────────────────────────────────────────────────
        if len(ips) >= 2:
            self._active_flows.append(f"{ips[0]} \u2192 {ips[1]}")

        # ── Threat level colour ──────────────────────────────────────────
        if _type in ("ARP Spoofing", "DoS / SYN Flood"):
            colour = "#FF3B5C"
        elif _type in ("Port Scan", "ML Detection"):
            colour = "#FF9900"
        elif _type == "DNS Tunneling":
            colour = "#F39C12"
        else:
            colour = "#27AE60"

        self._log_line(f"[{ts}]  {msg}", colour)

        # Mark dirty — rendering happens on the next timer tick
        self._dirty = True

    def _flush_if_dirty(self):
        """Called by _render_timer every 500ms. Rebuilds cards only when dirty."""
        if not self._dirty:
            return
        self._dirty = False
        self._update_threat_level()
        self._render_attacks()
        self._render_attackers()
        self._render_ports()
        self._render_conns()

    def record_packet(self, src: str, dst: str, dst_port: int, length: int):
        """Called from _process_batch to track per-packet stats."""
        self._pkt_count   += 1
        self._byte_count  += length
        self._total_pkts  += 1
        self._total_bytes += length
        if dst_port:
            self._port_counts[dst_port] += 1
        # Track active flows (lightweight)
        if src and dst:
            flow = f"{src} → {dst}"
            if not self._active_flows or self._active_flows[-1] != flow:
                self._active_flows.append(flow)

    def record_blocked_ip(self, ip: str):
        if ip and ip not in self._blocked_ips:
            self._blocked_ips.append(ip)
            self._render_blocked()

    # ── Render helpers ────────────────────────────────────────────────────────

    def _update_threat_level(self):
        _, name, colour, emoji = _level_for(self._total_attacks)
        self._threat_lbl.setText(f"{emoji}  {name}")
        self._threat_lbl.setStyleSheet(
            f"color:{colour}; border:none; padding:6px; font-size:22px; font-weight:bold;"
        )
        self._threat_card.setStyleSheet(
            f"QFrame {{ background:#12122A; border:2px solid {colour};"
            f"border-radius:8px; }}"
        )
        self._timestamp_lbl.setText(datetime.now().strftime("Updated %H:%M:%S"))

    def _render_attacks(self):
        self._attacks_card.clear_body()
        defaults = ["Port Scan", "DoS / SYN Flood", "ARP Spoofing",
                    "DNS Tunneling", "ML Detection"]
        for k in defaults:
            v = self._attack_counts.get(k, 0)
            col = "#FF3B5C" if v > 0 else "#446"
            self._attacks_card.add_row(k, str(v), col)

    def _render_traffic(self):
        self._rate_card.clear_body()
        kb = self._byte_per_sec / 1024
        mb = kb / 1024
        rate_str = f"{mb:.1f} MB/s" if mb >= 1 else f"{kb:.1f} KB/s"
        self._rate_card.add_row("Packets / sec", str(self._pkt_per_sec), "#3B82F6")
        self._rate_card.add_row("Throughput",    rate_str,               "#8B5CF6")
        total_mb = self._total_bytes / (1024 * 1024)
        self._rate_card.add_row("Total Packets", f"{self._total_pkts:,}", "#555")
        self._rate_card.add_row("Total Data",    f"{total_mb:.2f} MB",   "#555")

    def _render_attackers(self):
        try:
            self._attackers_card.clear_body()
            # Wrap in list or try/except to prevent thread mutation crash
            top = self._attacker_ips.most_common(6)
            if not top:
                self._attackers_card.add_label("No attackers recorded yet", "#446")
                return
            for ip, count in top:
                col = "#FF3B5C" if count > 10 else "#FF9900" if count > 3 else "#CCC"
                self._attackers_card.add_row(ip, f"{count} hits", col)
        except RuntimeError:
            pass

    def _render_geo(self):
        try:
            self._geo_card.clear_body()
            top = self._geo_countries.most_common(6)
            if not top:
                self._geo_card.add_label("No geo data yet", "#446")
                return
            for country, count in top:
                col = "#FF3B5C" if count > 5 else "#FF9900" if count > 2 else "#CCC"
                self._geo_card.add_row(country, str(count), col)
        except RuntimeError:
            pass

    def _render_ports(self):
        try:
            self._ports_card.clear_body()
            top = self._port_counts.most_common(6)
            if not top:
                self._ports_card.add_label("No port data yet", "#446")
                return
            for port, count in top:
                name = _PORT_NAMES.get(port, "")
                label = f"{port}  {('(' + name + ')') if name else ''}"
                col = "#FF3B5C" if port in (22, 23, 3389, 445) else "#CCC"
                self._ports_card.add_row(label, f"{count}", col)
        except RuntimeError:
            pass

    def _render_conns(self):
        try:
            self._conns_card.clear_body()
            flows = list(self._active_flows)[-8:]
            if not flows:
                self._conns_card.add_label("No active flows", "#446")
                return
            for f in reversed(flows):
                self._conns_card.add_label(f"• {f}", "#88AADD")
        except RuntimeError:
            pass

    def _render_blocked(self):
        self._blocked_card.clear_body()
        if not self._blocked_ips:
            self._blocked_card.add_label("No IPs blocked", "#446")
            return
        for ip in self._blocked_ips[-8:]:
            self._blocked_card.add_label(f"🚫  {ip}", "#FF3B5C")

    # ── Background workers ────────────────────────────────────────────────────

    def _bg_geo(self, ip: str):
        try:
            country, _ = get_location(ip)
            if country and country not in ("Unknown", "Private / LAN"):
                self._geo_countries[country] += 1
                # Re-render geo card from GUI thread via zero-ms timer
                QTimer.singleShot(0, self._render_geo)
        except Exception:
            pass

    def _bg_threat_intel(self, ip: str):
        try:
            res = self.ti_service.lookup(ip)
            if res and not "error" in res:
                score = res.get("score", 0)
                if score > 0:
                    threat_msg = f"⚠ Threat Intel: {ip} has Abuse Score: {score}/100"
                    usage = res.get("usage")
                    if usage and usage != "Unknown":
                        threat_msg += f" (Usage: {usage})"
                    
                    # Safely post back to the GUI thread
                    QTimer.singleShot(0, lambda m=threat_msg: self._log_line(m, "#FF3B5C"))
        except Exception:
            pass

    def _tick_rate(self):
        self._pkt_per_sec  = self._pkt_count
        self._byte_per_sec = self._byte_count
        self._pkt_count    = 0
        self._byte_count   = 0
        self._render_traffic()
        # Keep timestamp alive so dashboard looks responsive
        self._timestamp_lbl.setText(datetime.now().strftime("Updated %H:%M:%S"))
        # Also refresh ports + connections card every second (cheap)
        self._render_ports()
        self._render_conns()

    def _refresh_system(self):
        self._sys_card.clear_body()
        # Firewall
        try:
            # Check just the active profile instead of 'allprofiles' which can be confusing
            fw = subprocess.check_output(
                "netsh advfirewall show currentprofile state", shell=True, timeout=3
            ).decode()
            fw_status = "ON ✅" if "ON" in fw.upper() else "OFF ⚠"
            fw_col    = "#27AE60" if "ON" in fw_status else "#FF3B5C"
        except Exception:
            fw_status, fw_col = "Unknown", "#888"
        self._sys_card.add_row("🔥 Firewall", fw_status, fw_col)

        # Windows Defender
        try:
            av = subprocess.check_output(
                "sc query WinDefend", shell=True, timeout=3
            ).decode()
            av_status = "Running ✅" if "RUNNING" in av else "Stopped ⚠"
            av_col    = "#27AE60" if "Running" in av_status else "#FF9900"
        except Exception:
            av_status, av_col = "Unknown", "#888"
        self._sys_card.add_row("🛡 Defender", av_status, av_col)

        # Spacer
        self._sys_card.add_label("")

        # Listening ports (Unique, sorted, formatted nicely)
        try:
            listening_ports = set()
            for c in psutil.net_connections():
                if c.status == "LISTEN" and c.laddr:
                    listening_ports.add(c.laddr.port)
            
            ports = sorted(list(listening_ports))[:6]  # Top 6 to fit nicely
            
            self._sys_card.add_label(f"👂 Listening Ports ({len(listening_ports)}):", "#7788CC", bold=True)
            
            for port in ports:
                name = _PORT_NAMES.get(port, "")
                if not name:
                    # Extended common ports for cleaner display
                    ext_ports = {135: "RPC", 137: "NetBIOS", 138: "NetBIOS", 
                                 139: "NetBIOS", 445: "SMB", 5037: "ADB", 
                                 5353: "mDNS", 5355: "LLMNR", 7680: "DO"}
                    name = ext_ports.get(port, "System")
                    
                self._sys_card.add_row(f"  {port}", name, "#888")
                
        except Exception:
            pass

    # ── Log helper ────────────────────────────────────────────────────────────

    def _log_line(self, text: str, colour: str = "#CCC"):
        fmt = QTextCharFormat()
        fmt.setForeground(QColor(colour))
        cursor = self._log.textCursor()
        cursor.movePosition(QTextCursor.End)
        cursor.insertText(text + "\n", fmt)
        self._log.setTextCursor(cursor)
        self._log.ensureCursorVisible()
        # Keep log to last 300 lines
        doc = self._log.document()
        while doc.blockCount() > 300:
            c = QTextCursor(doc.begin())
            c.select(QTextCursor.BlockUnderCursor)
            c.deleteChar()
