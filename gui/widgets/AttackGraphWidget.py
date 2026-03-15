# gui/widgets/AttackGraphWidget.py
# ─────────────────────────────────────────────────────────────────────────────
# Live attack graph using networkx + matplotlib embedded in a PySide6 widget.
# IMPORTANT: do NOT call matplotlib.use() before importing backend_qtagg —
# backend_qtagg handles its own backend selection.
# ─────────────────────────────────────────────────────────────────────────────

import matplotlib
import matplotlib.pyplot as plt
import networkx as nx

from matplotlib.backends.backend_qtagg import FigureCanvasQTAgg as FigureCanvas

from PySide6.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QLabel
from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QFont

# Node role → colour
_ROLE_COLOUR = {
    "attacker": "#FF3B5C",
    "victim":   "#FF9900",
    "normal":   "#3B82F6",
}

MAX_GRAPH_NODES = 50   # prune oldest nodes beyond this


class AttackGraphWidget(QWidget):
    """
    Full-page widget showing a live directed graph of network flows.
    Red nodes = attackers, Orange = victims, Blue = normal traffic.
    """

    def __init__(self, parent=None):
        super().__init__(parent)
        self._graph         = nx.DiGraph()
        self._roles         = {}
        self._total_attacks = 0
        self._pkt_counter   = 0    # throttle: accept 1-in-5 calls

        self._setup_ui()

        # Redraw at most once per 3 seconds (spring_layout is expensive)
        self._dirty      = False
        self._draw_timer = QTimer(self)
        self._draw_timer.setInterval(3000)
        self._draw_timer.timeout.connect(self._redraw_if_dirty)
        self._draw_timer.start()

    # ── UI ───────────────────────────────────────────────────────────────────

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(8)

        # Header row
        header = QHBoxLayout()
        title = QLabel("🔴 Live Attack Graph")
        title.setFont(QFont("Segoe UI", 14, QFont.Bold))
        title.setStyleSheet("color: #E0E0E0;")

        self._stats_lbl = QLabel("Nodes: 0  |  Edges: 0  |  Attacks: 0")
        self._stats_lbl.setStyleSheet("color: #888; font-size: 11px;")

        clear_btn = QPushButton("Clear")
        clear_btn.setFixedWidth(70)
        clear_btn.clicked.connect(self.clear_graph)
        clear_btn.setStyleSheet("""
            QPushButton { background:#2D2D2D; color:#AAA; border:1px solid #444;
                          border-radius:4px; padding:3px 8px; }
            QPushButton:hover { background:#3A3A3A; color:#EEE; }
        """)

        legend = QLabel("  🔴 Attacker    🟠 Victim    🔵 Normal")
        legend.setStyleSheet("color:#888; font-size:10px;")

        header.addWidget(title)
        header.addStretch()
        header.addWidget(legend)
        header.addWidget(self._stats_lbl)
        header.addWidget(clear_btn)
        layout.addLayout(header)

        # Matplotlib figure — no explicit backend.use() call needed
        self._fig, self._ax = plt.subplots(figsize=(9, 6))
        self._fig.patch.set_facecolor("#1B1B1B")
        self._ax.set_facecolor("#1B1B1B")

        self._canvas = FigureCanvas(self._fig)
        self._canvas.setMinimumHeight(400)
        layout.addWidget(self._canvas, 1)

        self._draw_placeholder()

    # ── Public API ───────────────────────────────────────────────────────────

    def add_flow(self, src: str, dst: str, is_attack: bool = False):
        """Accept 1-in-5 calls to keep graph updates manageable."""
        if not src or not dst or src == dst:
            return

        self._pkt_counter += 1
        if self._pkt_counter % 5 != 0:
            return

        self._graph.add_edge(src, dst)

        # Roles
        if is_attack:
            self._roles[src] = "attacker"
            if self._roles.get(dst) != "attacker":
                self._roles[dst] = "victim"
            self._total_attacks += 1
        else:
            self._roles.setdefault(src, "normal")
            self._roles.setdefault(dst, "normal")

        # Prune to MAX_GRAPH_NODES
        while self._graph.number_of_nodes() > MAX_GRAPH_NODES:
            oldest = next(iter(self._graph.nodes()))
            self._graph.remove_node(oldest)
            self._roles.pop(oldest, None)

        self._dirty = True

    def mark_attacker(self, ip: str):
        if ip:
            self._roles[ip] = "attacker"
            self._dirty = True

    def clear_graph(self):
        self._graph.clear()
        self._roles.clear()
        self._total_attacks = 0
        self._pkt_counter   = 0
        self._dirty = True

    # ── Drawing (always on the GUI thread via QTimer) ─────────────────────

    def _redraw_if_dirty(self):
        if self._dirty:
            self._dirty = False
            self._draw()

    def _draw_placeholder(self):
        self._ax.clear()
        self._ax.set_facecolor("#1B1B1B")
        self._ax.text(
            0.5, 0.5,
            "Start a capture to see\nthe live attack graph",
            ha="center", va="center",
            color="#555", fontsize=13,
            transform=self._ax.transAxes,
        )
        self._ax.axis("off")
        self._canvas.draw()

    def _draw(self):
        if self._graph.number_of_nodes() == 0:
            self._draw_placeholder()
            self._stats_lbl.setText("Nodes: 0  |  Edges: 0  |  Attacks: 0")
            return

        self._ax.clear()
        self._ax.set_facecolor("#1B1B1B")

        try:
            pos = nx.spring_layout(self._graph, seed=42, k=2.0)
        except Exception:
            pos = nx.random_layout(self._graph)

        node_colours = [
            _ROLE_COLOUR.get(self._roles.get(n, "normal"), "#3B82F6")
            for n in self._graph.nodes()
        ]
        edge_colours = [
            "#FF3B5C" if self._roles.get(u) == "attacker" else "#555"
            for u, v in self._graph.edges()
        ]

        nx.draw_networkx(
            self._graph,
            pos        = pos,
            ax         = self._ax,
            node_color = node_colours,
            edge_color = edge_colours,
            node_size  = 800,
            font_size  = 7,
            font_color = "#FFFFFF",
            arrows     = True,
            arrowsize  = 14,
            width      = 1.5,
        )

        self._ax.axis("off")
        self._ax.set_title(
            "Live Network Attack Graph",
            color="#CCCCCC", fontsize=11, pad=6
        )

        self._canvas.draw()   # use draw() not draw_idle() so it flushes immediately

        n = self._graph.number_of_nodes()
        e = self._graph.number_of_edges()
        self._stats_lbl.setText(
            f"Nodes: {n}  |  Edges: {e}  |  Attacks: {self._total_attacks}"
        )
