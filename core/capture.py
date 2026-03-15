import asyncio
import threading
import logging
import time

import pyshark
from PySide6.QtCore import QThread, Signal

logger = logging.getLogger("Capture")


class LiveCaptureEngine(QThread):
    """Threaded live packet capture using pyshark.

    Performance notes
    -----------------
    * Every packet is analyzed (IDS + ML) in THIS background thread.
    * Results are batched and emitted to the GUI at a fixed interval
      (~4 Hz) to prevent signal-storm overhead.
    * Only a sample of packets get their full summary emitted to the GUI
      table for display. All packets are still counted for IDS/ML.
    """

    # Batch of (pkt, summary, alerts) tuples — emitted periodically
    packet_batch = Signal(list)

    # Individual security alert string (kept for compatibility)
    security_alert = Signal(str)

    capture_started = Signal(str)
    capture_stopped = Signal()
    error_occurred  = Signal(str)

    # How often (seconds) the batch is flushed to the GUI thread
    _FLUSH_INTERVAL = 0.30   # ~3 Hz — gentle on the GUI

    def __init__(self, interface: str = None, display_filter: str = "",
                 pcap_file: str = None) -> None:
        super().__init__()
        self.interface      = interface
        self.pcap_file      = pcap_file
        self.display_filter = display_filter
        self._stop_event    = threading.Event()
        self._capture       = None

    # ── background thread ────────────────────────────────────────────────

    def run(self) -> None:
        try:
            # Always create a fresh event loop for this thread
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)

            if self.pcap_file:
                kwargs = {"input_file": self.pcap_file}
                if self.display_filter:
                    kwargs["display_filter"] = self.display_filter
                capture = pyshark.FileCapture(**kwargs)
                self.capture_started.emit(self.pcap_file)
                packet_iter = capture
            else:
                kwargs = {
                    "interface": self.interface,
                    "use_json": True,
                    "include_raw": False,
                    # List form: supports bare flags like -n (no value)
                    "custom_parameters": ["-B", "8", "-n"],
                }
                kwargs["display_filter"] = (
                    self.display_filter if self.display_filter
                    else "tcp or udp or arp or icmp"
                )
                capture = pyshark.LiveCapture(**kwargs)
                self.capture_started.emit(self.interface)
                packet_iter = capture.sniff_continuously()

            self._capture = capture

            # Lazy import — safe if model files are absent
            from utils.packet_analyzer import PacketAnalyzer

            batch: list = []
            last_flush = time.monotonic()
            pkt_counter = 0

            for pkt in packet_iter:
                if self._stop_event.is_set():
                    break

                if self.pcap_file:
                    time.sleep(0.005)  # Throttle replay

                pkt_counter += 1

                # ── Analyze EVERY packet in BG thread for IDS/ML ─────
                try:
                    summary, alerts = PacketAnalyzer.summarize(pkt)
                except Exception:
                    logger.debug("Analyzer error", exc_info=True)
                    continue

                # Only send 1-in-10 packets to GUI for table display to sustain high capture rates,
                # but ALWAYS send packets that have alerts or ML labels
                has_detection = bool(alerts) or summary.get("ml_label") not in (None, "", "BENIGN", "UNKNOWN")
                if has_detection or pkt_counter % 10 == 0:
                    batch.append((pkt, summary, alerts))

                # ── Flush batch at fixed interval ────────────────────
                now = time.monotonic()
                if now - last_flush >= self._FLUSH_INTERVAL:
                    if batch:
                        self.packet_batch.emit(batch)
                        batch = []
                    last_flush = now

            # Flush remaining
            if batch:
                self.packet_batch.emit(batch)

        except Exception as e:
            logger.exception("Capture error")
            self.error_occurred.emit(str(e))

        finally:
            try:
                if self._capture:
                    if not loop.is_closed():
                        # Use apply_on_packets timeout trick if close_async is stubborn
                        try:
                            loop.run_until_complete(self._capture.close_async())
                        except Exception:
                            pass
                        
                        # Cancel all lingering tasks
                        pending = asyncio.all_tasks(loop)
                        for task in pending:
                            task.cancel()
                        if pending:
                            loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
                        
                        loop.close()
            except Exception:
                logger.debug("Capture close error", exc_info=True)
            self._capture = None
            self.capture_stopped.emit()

    def stop(self) -> None:
        """Stop capture safely."""
        self._stop_event.set()
        # Actual closure happens in the finally block of the run() thread
        # to ensure it executes in the same event loop that owns the capture.