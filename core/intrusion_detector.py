import time
from collections import defaultdict, deque


class IntrusionDetector:

    def __init__(self):

        # packet counters
        self.packet_count = defaultdict(int)

        # ports accessed
        self.port_attempts = defaultdict(set)

        # connection timestamps
        self.connection_times = defaultdict(lambda: deque())

        # ARP spoof tracking
        self.ip_mac_map = {}

        # reset window
        self.window_start = time.time()

        # thresholds
        self.PORT_SCAN_THRESHOLD = 5
        self.FLOOD_THRESHOLD = 30
        self.SCAN_RATE_THRESHOLD = 10

        self.TIME_WINDOW = 5

        # avoid repeating alerts
        self.alerted_scan = set()
        self.alerted_flood = set()
        self.alerted_rate = set()

    def analyze_packet(self, packet_info):

        alerts = []

        src_ip = packet_info.get("src_ip")
        dst_port = packet_info.get("dst_port")
        src_mac = packet_info.get("src_mac")

        if not src_ip:
            return alerts

        now = time.time()

        # reset counters periodically
        if now - self.window_start > self.TIME_WINDOW:

            self.packet_count.clear()
            self.port_attempts.clear()
            self.connection_times.clear()

            self.alerted_scan.clear()
            self.alerted_flood.clear()
            self.alerted_rate.clear()

            self.window_start = now

        # -------------------------
        # packet count
        # -------------------------

        self.packet_count[src_ip] += 1

        # -------------------------
        # port tracking
        # -------------------------

        if dst_port:

            try:
                dst_port = int(dst_port)
            except:
                pass

            self.port_attempts[src_ip].add(dst_port)

        # -------------------------
        # connection timing
        # -------------------------

        self.connection_times[src_ip].append(now)

        while self.connection_times[src_ip] and now - self.connection_times[src_ip][0] > 2:
            self.connection_times[src_ip].popleft()

        # -------------------------
        # PORT SCAN detection
        # -------------------------

        if (
            len(self.port_attempts[src_ip]) >= self.PORT_SCAN_THRESHOLD
            and src_ip not in self.alerted_scan
        ):

            alerts.append({
                "type": "PORT_SCAN",
                "message": f"⚠ Port scan detected from {src_ip}"
            })

            self.alerted_scan.add(src_ip)

        # -------------------------
        # SCAN RATE detection
        # -------------------------

        if (
            len(self.connection_times[src_ip]) >= self.SCAN_RATE_THRESHOLD
            and src_ip not in self.alerted_rate
        ):

            alerts.append({
                "type": "SCAN_RATE",
                "message": f"⚠ High connection rate from {src_ip} (possible scan)"
            })

            self.alerted_rate.add(src_ip)

        # -------------------------
        # FLOOD detection
        # -------------------------

        if (
            self.packet_count[src_ip] >= self.FLOOD_THRESHOLD
            and src_ip not in self.alerted_flood
        ):

            alerts.append({
                "type": "PACKET_FLOOD",
                "message": f"⚠ Packet flood detected from {src_ip}"
            })

            self.alerted_flood.add(src_ip)

        # -------------------------
        # ARP spoof detection
        # -------------------------

        if src_mac:

            if src_ip not in self.ip_mac_map:
                self.ip_mac_map[src_ip] = src_mac

            elif self.ip_mac_map[src_ip] != src_mac:

                alerts.append({
                    "type": "ARP_SPOOF",
                    "message": f"⚠ ARP spoof detected for {src_ip}"
                })

        if alerts:
            print("IDS ALERT:", alerts)

        return alerts