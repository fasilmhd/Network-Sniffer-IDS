# gui/widgets/TrafficMapWidget.py
# ─────────────────────────────────────────────────────────────────────────────
# Enhanced mini traffic map for the left sidebar.
# Shows colour-coded nodes (red=attacker, orange=victim, blue=normal),
# animated flow lines, live packet/attack counters, and a mini alert ticker.
# ─────────────────────────────────────────────────────────────────────────────

import random
import math

from PySide6.QtWidgets import QWidget, QVBoxLayout, QLabel, QHBoxLayout
from PySide6.QtCore import Qt, QTimer, QPointF, QRectF
from PySide6.QtGui import (
    QPainter, QPen, QColor, QBrush, QFont, QLinearGradient,
    QPainterPath, QRadialGradient
)

_COLORS = {
    "normal":   QColor("#3B82F6"),   # blue
    "attacker": QColor("#FF3B5C"),   # red
    "victim":   QColor("#FF9900"),   # orange
}
_EDGE_ATTACK  = QColor(255, 59, 92,  140)   # red, semi-transparent
_EDGE_NORMAL  = QColor(100, 160, 255, 60)   # blue, very light


class _Node:
    __slots__ = ("x", "y", "role", "pulse", "vx", "vy")

    def __init__(self, x, y):
        self.x    = float(x)
        self.y    = float(y)
        self.role = "normal"
        self.pulse = 0.0      # 0→1 animation for flash
        self.vx   = random.uniform(-0.3, 0.3)
        self.vy   = random.uniform(-0.3, 0.3)


class _Edge:
    __slots__ = ("src_ip", "dst_ip", "ttl", "is_attack", "progress")

    def __init__(self, src_ip, dst_ip, is_attack):
        self.src_ip    = src_ip
        self.dst_ip    = dst_ip
        self.ttl       = 90    # frames
        self.is_attack = is_attack
        self.progress  = 0.0  # animated dot 0→1


class TrafficMapWidget(QWidget):
    """Compact, animated mini-map for the sidebar."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setMinimumSize(170, 190)
        self.setMaximumSize(200, 240)

        self._nodes: dict[str, _Node] = {}
        self._edges: list[_Edge]      = []
        self._total_packets = 0
        self._total_attacks = 0
        self._last_alert    = ""

        # Animation timer — 15 fps (smooth but light on CPU)
        self._timer = QTimer(self)
        self._timer.setInterval(66)
        self._timer.timeout.connect(self._tick)
        self._timer.start()

        self.setToolTip("Live Traffic Map\nRed=Attacker  Orange=Victim  Blue=Normal")

    # ── Public API ───────────────────────────────────────────────────────────

    def add_flow(self, src_ip: str, dst_ip: str, protocol: str = "", is_attack: bool = False):
        if not src_ip or not dst_ip:
            return
        self._total_packets += 1
        if is_attack:
            self._total_attacks += 1

        self._get_or_create_node(src_ip)
        self._get_or_create_node(dst_ip)

        # Role assignment
        if is_attack:
            self._nodes[src_ip].role  = "attacker"
            self._nodes[src_ip].pulse = 1.0
            if self._nodes[dst_ip].role != "attacker":
                self._nodes[dst_ip].role = "victim"

        # Add edge (cap at 12 edges)
        self._edges.append(_Edge(src_ip, dst_ip, is_attack))
        if len(self._edges) > 12:
            self._edges.pop(0)

    def highlight_node(self, ip: str, role: str = "attacker"):
        """Highlight existing or create a new node."""
        node = self._get_or_create_node(ip)
        node.role  = role
        node.pulse = 1.0

    def set_last_alert(self, text: str):
        self._last_alert = text[:35] + ("…" if len(text) > 35 else "")

    # ── Private ──────────────────────────────────────────────────────────────

    def _get_or_create_node(self, ip: str) -> _Node:
        if ip not in self._nodes:
            margin = 18
            x = random.randint(margin, self.width()  - margin) if self.width()  > 40 else 80
            y = random.randint(margin, self.height() - margin) if self.height() > 40 else 80
            self._nodes[ip] = _Node(x, y)
            # Evict oldest if too many nodes
            if len(self._nodes) > 20:
                oldest = next(iter(self._nodes))
                del self._nodes[oldest]
        return self._nodes[ip]

    def _tick(self):
        try:
            W, H = self.width(), self.height()

            # Drift nodes gently (organic movement)
            for node in list(self._nodes.values()):
                node.x = max(12, min(W - 12, node.x + node.vx))
                node.y = max(28, min(H - 28, node.y + node.vy))
                if node.x <= 12 or node.x >= W - 12:
                    node.vx *= -1
                if node.y <= 28 or node.y >= H - 28:
                    node.vy *= -1
                node.vx += random.uniform(-0.04, 0.04)
                node.vy += random.uniform(-0.04, 0.04)
                node.vx  = max(-0.6, min(0.6, node.vx))
                node.vy  = max(-0.6, min(0.6, node.vy))
                # Fade pulse
                if node.pulse > 0:
                    node.pulse = max(0.0, node.pulse - 0.04)

            # Age edges
            for edge in list(self._edges):
                edge.ttl      -= 1
                edge.progress  = min(1.0, edge.progress + 0.03)
            self._edges = [e for e in self._edges if e.ttl > 0]

            self.update()
        except RuntimeError:
            pass

    # ── Painting ─────────────────────────────────────────────────────────────

    def paintEvent(self, event):
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        W, H = self.width(), self.height()

        # ── Background ────────────────────────────────────────────────────
        bg = QLinearGradient(0, 0, 0, H)
        bg.setColorAt(0, QColor("#1A1A2E"))
        bg.setColorAt(1, QColor("#0F0F1A"))
        p.fillRect(0, 0, W, H, bg)

        # ── Border ─────────────────────────────────────────────────────────
        p.setPen(QPen(QColor("#2A2A4A"), 1))
        p.drawRoundedRect(0, 0, W - 1, H - 1, 6, 6)

        # ── Title bar ──────────────────────────────────────────────────────
        p.setFont(QFont("Segoe UI", 8, QFont.Bold))
        p.setPen(QColor("#8888CC"))
        p.drawText(QRectF(4, 2, W - 8, 16), Qt.AlignCenter, "🌐 Live Traffic")

        try:
            # ── Edges ──────────────────────────────────────────────────────────
            for edge in list(self._edges):
                src = self._nodes.get(edge.src_ip)
                dst = self._nodes.get(edge.dst_ip)
                if not src or not dst:
                    continue

                alpha = int(min(255, edge.ttl * 2.8))
                if edge.is_attack:
                    col = QColor(255, 59, 92, alpha)
                else:
                    col = QColor(100, 160, 255, alpha // 4)

                pen = QPen(col, 1.2 if edge.is_attack else 0.7)
                pen.setStyle(Qt.DashLine if edge.is_attack else Qt.SolidLine)
                p.setPen(pen)
                p.drawLine(QPointF(src.x, src.y), QPointF(dst.x, dst.y))

                # Animated travelling dot
                t   = edge.progress
                dx  = dst.x - src.x
                dy  = dst.y - src.y
                dot = QPointF(src.x + dx * t, src.y + dy * t)
                dot_col = QColor(255, 200, 50) if edge.is_attack else QColor(100, 200, 255)
                p.setPen(Qt.NoPen)
                p.setBrush(QBrush(dot_col))
                p.drawEllipse(dot, 2.5, 2.5)

            # ── Nodes ──────────────────────────────────────────────────────────
            for ip, node in list(self._nodes.items()):
                base_col = _COLORS.get(node.role, _COLORS["normal"])

                # Pulse glow for new/attacker nodes
                if node.pulse > 0:
                    glow_r = int(8 + node.pulse * 10)
                    glow = QRadialGradient(node.x, node.y, glow_r)
                    glow_col = QColor(base_col)
                    glow_col.setAlpha(int(node.pulse * 180))
                    glow.setColorAt(0, glow_col)
                    glow.setColorAt(1, QColor(0, 0, 0, 0))
                    p.setPen(Qt.NoPen)
                    p.setBrush(QBrush(glow))
                    p.drawEllipse(QPointF(node.x, node.y), glow_r, glow_r)

                # Node circle
                r = 5 if node.role == "attacker" else 4
                p.setPen(QPen(QColor(255, 255, 255, 60), 0.8))
                p.setBrush(QBrush(base_col))
                p.drawEllipse(QPointF(node.x, node.y), r, r)
        except RuntimeError:
            pass

        # ── Stats bar ──────────────────────────────────────────────────────
        p.setPen(QColor("#555577"))
        p.drawLine(0, H - 36, W, H - 36)

        p.setFont(QFont("Segoe UI", 7))
        p.setPen(QColor("#6699AA"))
        p.drawText(QRectF(4, H - 34, W - 8, 14), Qt.AlignLeft, f"📦 {self._total_packets:,}")

        atk_col = QColor("#FF3B5C") if self._total_attacks else QColor("#556677")
        p.setPen(atk_col)
        p.drawText(QRectF(4, H - 34, W - 8, 14), Qt.AlignRight, f"⚠ {self._total_attacks}")

        # ── Alert ticker ───────────────────────────────────────────────────
        if self._last_alert:
            p.setFont(QFont("Segoe UI", 6))
            p.setPen(QColor("#FF8888"))
            p.drawText(QRectF(4, H - 18, W - 8, 14), Qt.AlignLeft | Qt.TextWordWrap, self._last_alert)

        p.end()