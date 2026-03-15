
from PySide6.QtWidgets import (
    QMainWindow, QWidget, QHBoxLayout, QVBoxLayout,
    QStackedWidget, QPushButton, QStatusBar, QMessageBox,
    QSizePolicy, QLabel
)

from PySide6.QtGui import QAction, QIcon, QKeySequence
from PySide6.QtCore import Qt, QPropertyAnimation, QEasingCurve, QTimer

from utils.constants import AppConstants
from utils.logging import setup_logger
from utils.packet_analyzer import PacketAnalyzer  # still used in DetailsPanel path
from core.capture import LiveCaptureEngine

from gui.widgets.SettingsDialog import SettingsDialog
from gui.widgets.ControlPanel import ControlPanel
from gui.widgets.PacketTable import PacketTable
from gui.widgets.DetailsPanel import DetailsPanel
from gui.widgets.MonitorPanel import MonitorPanel
from gui.widgets.ProcessManagerPanel import ProcessManagerPanel
from gui.widgets.ScannerPanel import ScannerPanel
from gui.widgets.MalwarePanel import MalwarePanel
from gui.widgets.SecurityStatusPanel import SecurityStatusPanel
from gui.widgets.ReportGenerator import ReportGeneratorDialog
from gui.widgets.AboutDialog import AboutDialog
from gui.widgets.TrafficMapWidget import TrafficMapWidget

from utils.animations import AnimationUtils as Animations
from core.ips_controller import IPSController
from utils.firewall_blocker import block_ip
from utils.geoip_lookup import format_location
from gui.widgets.MLAlertToast import MLAlertToast
from gui.widgets.AttackGraphWidget import AttackGraphWidget
from utils.interface_detector import get_active_interface, is_interface_active


class MainWindow(QMainWindow):

    def __init__(self, config, parent=None):
        super().__init__(parent)

        setup_logger()
        self.cfg = config

        self.setWindowTitle(f"{AppConstants.APP_NAME} v{AppConstants.VERSION}")
        self.setWindowIcon(QIcon(AppConstants.APP_ICON))
        self.resize(1200, 800)

        self._init_ui()
        self._init_menu()
        self._init_capture_handling()

    def keyPressEvent(self, event):
        key = event.key()

        if key in [Qt.Key_Escape, Qt.Key_Backspace]:
            try:
                self.details_panel.unlock()
            except Exception:
                pass

            try:
                self.packet_table.clearSelection()
            except Exception:
                pass

    def switch_to_page(self, target_widget):

        if target_widget is not self.stack.currentWidget():

            target_widget.setWindowOpacity(0.0)
            self.stack.setCurrentWidget(target_widget)

            animation = QPropertyAnimation(target_widget, b"windowOpacity")
            animation.setDuration(400)
            animation.setStartValue(0.0)
            animation.setEndValue(1.0)
            animation.setEasingCurve(QEasingCurve.InOutQuad)
            animation.start(QPropertyAnimation.DeleteWhenStopped)

    def _init_ui(self):

        container = QWidget()
        main_layout = QHBoxLayout(container)

        main_layout.setSpacing(12)
        main_layout.setContentsMargins(12, 12, 12, 12)

        self.setCentralWidget(container)

        nav_widget = QWidget()
        nav_layout = QVBoxLayout(nav_widget)

        nav_layout.setAlignment(Qt.AlignTop)
        nav_layout.setSpacing(10)

        main_layout.addWidget(nav_widget, 1)

        # Sniffer page
        sniff_page = QWidget()
        sniff_layout = QVBoxLayout(sniff_page)

        self.control_panel = ControlPanel(self.cfg)
        self.details_panel = DetailsPanel()
        self.packet_table = PacketTable(self.details_panel)

        self.packet_table.packet_selected.connect(self.details_panel.display)

        sniff_layout.addWidget(self.control_panel)
        sniff_layout.addWidget(self.packet_table)
        sniff_layout.addWidget(self.details_panel)

        self.stack = QStackedWidget()
        self.stack.addWidget(sniff_page)

        # Other panels
        self.scanner_panel = ScannerPanel(self.cfg)
        self.monitor_panel = MonitorPanel()
        self.proc_panel = ProcessManagerPanel()
        self.malware_panel = MalwarePanel(self.cfg)
        self.status_panel = SecurityStatusPanel(self.cfg)

        # 📊 Live Attack Graph page
        self.attack_graph = AttackGraphWidget()

        self.stack.addWidget(self.scanner_panel)
        self.stack.addWidget(self.monitor_panel)
        self.stack.addWidget(self.proc_panel)
        self.stack.addWidget(self.malware_panel)
        self.stack.addWidget(self.status_panel)
        self.stack.addWidget(self.attack_graph)

        main_layout.addWidget(self.stack, 4)

        pages = [
            ("Sniffer",       sniff_page),
            ("Processes",     self.proc_panel),
            ("Malware",       self.malware_panel),
            ("Status",        self.status_panel),
            ("Attack Graph",  self.attack_graph),
        ]

        for name, widget in pages:
            self._setup_nav_button(name, widget, nav_layout)

        # Traffic map
        self.traffic_map = TrafficMapWidget()
        self.traffic_map.setFixedSize(180, 120)

        map_label = QLabel("Live Traffic Map")
        map_label.setAlignment(Qt.AlignCenter)

        map_container = QWidget()
        map_layout = QVBoxLayout(map_container)

        map_layout.addWidget(map_label)
        map_layout.addWidget(self.traffic_map)

        nav_layout.addWidget(map_container)
        nav_layout.addStretch()

        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_bar.showMessage("Ready")

        # Floating ML alert toast (top-right, reusable)
        self._ml_toast = MLAlertToast(self)

    def _init_menu(self):

        menubar = self.menuBar()
        
        # 1. System Core Menu
        file_menu = menubar.addMenu("&SYSTEM CORE")

        settings_act = QAction("⚙ &Global Settings", self)
        
        def _open_settings():
            from gui.widgets.SettingsDialog import SettingsDialog
            from utils.config_loader import ConfigLoader
            dlg = SettingsDialog()
            if dlg.exec_():
                new_cfg = ConfigLoader.load()
                if hasattr(self, "status_panel") and hasattr(self.status_panel, "update_config"):
                    self.status_panel.update_config(new_cfg)

        settings_act.triggered.connect(_open_settings)

        file_menu.addAction(settings_act)

        export_act = QAction("📄 &Export Security Report...", self)
        export_act.setShortcut(QKeySequence.Save)

        export_act.triggered.connect(lambda: ReportGeneratorDialog(self.status_panel, self).exec_())
        file_menu.addAction(export_act)

        file_menu.addSeparator()

        exit_act = QAction("🛑 E&xit Platform", self)
        exit_act.setShortcut(QKeySequence.Quit)
        exit_act.triggered.connect(self.close)

        file_menu.addAction(exit_act)

        # 2. Support Menu
        help_menu = menubar.addMenu("&DIAGNOSTICS")

        about_act = QAction("ℹ &About Platform", self)
        about_act.triggered.connect(lambda: AboutDialog(self).exec_())

        help_menu.addAction(about_act)
        
        # 3. Premium Branding Label on Menu Bar
        brand_label = QLabel(" /// AI CYBERSECURITY PLATFORM ")
        brand_label.setStyleSheet("color: #00E5FF; font-weight: 900; font-style: italic; font-size: 12pt; padding-right: 20px; letter-spacing: 2px; background: transparent;")
        brand_label.setAlignment(Qt.AlignVCenter | Qt.AlignRight)
        menubar.setCornerWidget(brand_label, Qt.TopRightCorner)

    def _init_capture_handling(self):

        self.capture_engine = None
        self._iface_timer = QTimer(self)
        self._iface_timer.setInterval(3000)
        self._iface_timer.timeout.connect(self._check_iface_drop)

        cp = self.control_panel

        cp.start_capture.connect(self.start_capture)
        cp.start_pcap.connect(self.start_pcap)
        cp.stop_capture.connect(self.stop_capture)
        cp.clear_all.connect(self.clear_all_data)
        cp.export_data.connect(lambda: ReportGeneratorDialog(self.status_panel, self).exec_())

    def clear_all_data(self):
        """Reset all UI data and IDS tracking state."""
        self.packet_table.clear()
        PacketAnalyzer.reset_state()
        if hasattr(self.status_panel, "log_view"):
            # Optionally clear the UI visual panels if needed, but table+analyzer is priority
            pass

    def start_pcap(self, pcap_file: str, protocol: str):
        if self.capture_engine and self.capture_engine.isRunning():
            QMessageBox.warning(self, "Already Capturing", "Stop the current capture first.")
            return

        self.capture_engine = LiveCaptureEngine(interface=None, display_filter=protocol, pcap_file=pcap_file)
        self._wire_capture_engine()

    def start_capture(self, interface: str, protocol: str):

        if self.capture_engine and self.capture_engine.isRunning():
            self.capture_engine.stop()
            self.capture_engine.wait(1000)
            if self.capture_engine.isRunning():
                # Force kill if it's hung (pyshark dumpcap deadlock)
                self.capture_engine.terminate()
                self.capture_engine.wait(500)

        if not is_interface_active(interface):
            active = get_active_interface()
            if active:
                reply = QMessageBox.question(
                    self, "Disconnected Interface",
                    f"The selected interface '{interface}' has no active connection.\nWould you like to switch to '{active}'?",
                    QMessageBox.Yes | QMessageBox.No
                )
                if reply == QMessageBox.Yes:
                    interface = active
                    idx = self.control_panel.iface.findText(active)
                    if idx >= 0:
                        self.control_panel.iface.setCurrentIndex(idx)
                else:
                    return
            else:
                QMessageBox.warning(
                    self, "No Network",
                    f"The selected interface '{interface}' has no active connection, and no other active networks were found."
                )
                return

        self.capture_engine = LiveCaptureEngine(interface=interface, display_filter=protocol)
        self._wire_capture_engine()
        
    def _check_iface_drop(self):
        if not self.capture_engine or getattr(self.capture_engine, 'pcap_file', None):
            return
            
        current = self.capture_engine.interface
        if current and not is_interface_active(current):
            self._iface_timer.stop()
            
            if self.capture_engine:
                self.capture_engine.stop()
                self.capture_engine.wait(1000)
                if self.capture_engine.isRunning():
                    # Thread is hung waiting for packets on a dead interface. Kill it.
                    self.capture_engine.terminate()
                    self.capture_engine.wait(500)
                
            active = get_active_interface()
            if active:
                reply = QMessageBox.question(
                    self, "Connection Lost", 
                    f"Connection on '{current}' was lost.\nWould you like to switch to '{active}' and resume capture?",
                    QMessageBox.Yes | QMessageBox.No
                )
                if reply == QMessageBox.Yes:
                    idx = self.control_panel.iface.findText(active)
                    if idx >= 0:
                        self.control_panel.iface.setCurrentIndex(idx)
                    # Use a short singleShot to let the previous thread fully terminate
                    QTimer.singleShot(500, lambda: self.start_capture(active, self.control_panel.proto.currentText()))
            else:
                QMessageBox.warning(
                    self, "Connection Lost", 
                    f"Connection on '{current}' was lost and no fallback network is available.\nCapture stopped."
                )

    def _on_capture_started(self, iface):
        self.status_bar.showMessage(f"Capturing on {iface}...")
        if not getattr(self.capture_engine, 'pcap_file', None):
            self._iface_timer.start()

    def _on_capture_stopped(self):
        self.status_bar.showMessage("Capture stopped")
        self._iface_timer.stop()

    def _wire_capture_engine(self):
        # Batch signal carries list of (pkt, summary, alerts) — emitted ~4 Hz
        self.capture_engine.packet_batch.connect(
            self.packet_table.add_packet_batch
        )
        self.capture_engine.packet_batch.connect(self._process_batch)

        # Note: We rely purely on the batch processor to handle alerts
        # so they receive their correct `alert_type` metadata.
        self.capture_engine.capture_started.connect(self._on_capture_started)
        self.capture_engine.capture_stopped.connect(self._on_capture_stopped)

        self.capture_engine.error_occurred.connect(
            lambda msg: QMessageBox.critical(self, "Error", msg)
        )

        self.capture_engine.start()

    def stop_capture(self):

        if self.capture_engine:
            self.capture_engine.stop()
            
            # Non-blocking check to terminate if it gets stuck
            QTimer.singleShot(1500, self._force_kill_if_hung)
            
    def _force_kill_if_hung(self):
        if self.capture_engine and self.capture_engine.isRunning():
            self.capture_engine.terminate()
            self.capture_engine.wait(500)
    def _process_batch(self, batch: list):
        """Process a batch of (pkt, summary, alerts) for traffic map, etc.
        Designed to be lightweight: aggregates stats, samples for heavy widgets."""
        if not batch:
            return

        # ── Aggregate stats for security dashboard (very cheap) ──────
        total_bytes = 0
        for pkt, summary, alerts in batch:
            try:
                dst_port = int(summary.get("dst_port") or 0)
                length   = int(getattr(pkt, "length", 0) or 0)
                total_bytes += length
                if hasattr(self.status_panel, "record_packet"):
                    self.status_panel.record_packet(
                        summary.get("src"), summary.get("dst"), dst_port, length
                    )
            except Exception:
                pass

        # ── Sample for traffic map & attack graph (1-in-5 max) ───────
        step = max(1, len(batch) // 5)
        for i in range(0, len(batch), step):
            _, summary, alerts = batch[i]
            src   = summary.get("src")
            dst   = summary.get("dst")
            proto = summary.get("protocol", "")
            is_attack = bool(alerts) or summary.get("ml_label", "BENIGN") not in ("BENIGN", "UNKNOWN", "")

            if src and dst:
                try:
                    self.traffic_map.add_flow(src, dst, proto, is_attack=is_attack)
                except Exception:
                    pass
                try:
                    self.attack_graph.add_flow(src, dst, is_attack=is_attack)
                    if is_attack:
                        self.attack_graph.mark_attacker(src)
                except Exception:
                    pass

        # ── IDS + ML alerts for every item in batch ──────────────
        _toasted = False
        for _, summary, alerts in batch:
            for alert in alerts:
                a_msg  = alert.get("message", str(alert))
                a_type = alert.get("type", "")
                # Route through the full alert handler (GeoIP, IPS, etc.)
                self._handle_security_alert(a_msg, alert_type=a_type)

            # Show one ML toast per batch
            ml_label = summary.get("ml_label")
            ml_conf  = summary.get("ml_confidence", 0.0)
            if ml_label and ml_label not in ("BENIGN", "UNKNOWN") and not _toasted:
                try:
                    self._ml_toast.show_alert(
                        label=ml_label,
                        src_ip=summary.get("src", "?"),
                        confidence=ml_conf
                    )
                except Exception:
                    pass
                _toasted = True

        # ── Status bar heartbeat (last packet only) ──────────────────
        _, last_summary, _ = batch[-1]
        self._last_summary = last_summary
        ml_label = last_summary.get("ml_label")
        ml_conf  = last_summary.get("ml_confidence", 0.0)
        if ml_label:
            try:
                self.status_bar.showMessage(
                    f"🤖 ML Engine Active  │  Last: {ml_label} ({ml_conf:.0%})"
                )
            except Exception:
                pass

    def _handle_security_alert(self, message: str, alert_type: str = ""):

        # 🌍 GeoIP enrichment
        geo_info = ""
        attacker = ""
        victim   = ""
        if hasattr(self, "_last_summary"):
            attacker = self._last_summary.get("src", "") or ""
            victim   = self._last_summary.get("dst", "") or ""
            if attacker:
                try:
                    loc = format_location(attacker)
                    if loc:
                        geo_info = f" [{loc}]"
                except Exception:
                    pass

        enriched_message = message + geo_info

        # Show in Status panel (with explicit type so counter increments correctly)
        if hasattr(self.status_panel, "add_alert"):
            self.status_panel.add_alert(enriched_message, alert_type=alert_type)

        # Update mini-map alert ticker
        try:
            self.traffic_map.set_last_alert(enriched_message)
        except Exception:
            pass

        # 🔔 Non-blocking Toast alert
        try:
            self._ml_toast.show_custom_alert(
                "Security Alert",
                enriched_message,
                duration_ms=4500
            )
        except Exception:
            pass

        # 🛡️ Automatic Firewall Blocking (IPS) — runs in background thread
        if attacker:
            IPSController.evaluate_and_respond(message, attacker, self.status_panel)

        # Highlight attacker on traffic map
        if attacker:
            try:
                self.traffic_map.highlight_node(attacker, "attacker")
            except Exception:
                pass
        if victim:
            try:
                self.traffic_map.highlight_node(victim, "victim")
            except Exception:
                pass

    def _setup_nav_button(self, name: str, page_widget: QWidget, layout: QVBoxLayout):

        btn = QPushButton(name)

        btn.clicked.connect(lambda _, b=btn: Animations.bounce_button(b))
        btn.clicked.connect(lambda _, w=page_widget: self.switch_to_page(w))

        layout.addWidget(btn)

    def closeEvent(self, event):

        if self.capture_engine and self.capture_engine.isRunning():
            self.capture_engine.stop()
            self.capture_engine.wait(1000)
            if self.capture_engine.isRunning():
                self.capture_engine.terminate()
                self.capture_engine.wait(500)

        event.accept()
