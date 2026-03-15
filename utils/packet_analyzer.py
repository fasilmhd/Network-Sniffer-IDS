# utils/packet_analyzer.py
import logging
from datetime import datetime
from collections import defaultdict, deque
import time

logger = logging.getLogger(__name__)

# ML-IDS integration (lazy — safe if model not trained yet)
try:
    from utils.ml_ids_engine import MLIDSEngine
    from utils.flow_feature_extractor import FlowFeatureExtractor
    _ML_AVAILABLE = True
except ImportError:
    _ML_AVAILABLE = False


def _parse_tcp_flags(raw_flags) -> set:
    """Convert pyshark TCP flags (hex string OR int) to a set of flag names.
    
    pyshark returns flags as a hex string like '0x00000002' (SYN).
    Bit positions: FIN=0, SYN=1, RST=2, PSH=3, ACK=4, URG=5
    """
    if not raw_flags:
        return set()
    try:
        val = int(str(raw_flags), 16) if isinstance(raw_flags, str) else int(raw_flags)
    except (ValueError, TypeError):
        return set()

    flags = set()
    if val & 0x001: flags.add("F")   # FIN
    if val & 0x002: flags.add("S")   # SYN
    if val & 0x004: flags.add("R")   # RST
    if val & 0x008: flags.add("P")   # PSH
    if val & 0x010: flags.add("A")   # ACK
    if val & 0x020: flags.add("U")   # URG
    return flags


class PacketAnalyzer:
    # ── IDS state (class-level, shared across calls) ──────────────────────────
    packet_count     = defaultdict(int)
    port_attempts    = defaultdict(set)
    connection_times = defaultdict(deque)
    ip_mac_map       = {}
    syn_count        = defaultdict(int)
    dns_requests     = defaultdict(int)
    icmp_count       = defaultdict(int)

    window_start = time.time()

    # ── Raised thresholds (avoid false positives on normal traffic) ───────────
    PORT_SCAN_THRESHOLD  = 10   # distinct ports to one dst before alert
    FLOOD_THRESHOLD      = 80   # packets in 5s window
    SCAN_RATE_THRESHOLD  = 20   # connections in 2s
    SYN_FLOOD_THRESHOLD  = 40   # pure-SYN packets in 5s window
    DNS_TUNNEL_THRESHOLD = 30   # DNS queries in 5s
    ICMP_FLOOD_THRESHOLD = 40   # ICMP packets in 5s

    @classmethod
    def reset_state(cls):
        """Clear all IDS/ML tracking history for a clean slate."""
        cls.packet_count.clear()
        cls.port_attempts.clear()
        cls.connection_times.clear()
        cls.ip_mac_map.clear()
        cls.syn_count.clear()
        cls.dns_requests.clear()
        cls.icmp_count.clear()
        cls._alert_last.clear()
        cls.window_start = time.time()
    # ── Alert cooldown: store last-alerted time per (type, src) ──────────────
    # Cooldown: re-alert every 15 s so repeat attacks keep showing
    _ALERT_COOLDOWN = 15.0
    _alert_last: dict = defaultdict(float)  # key=(type, src) → epoch

    @classmethod
    def _can_alert(cls, kind: str, src: str) -> bool:
        key = (kind, src)
        now = time.time()
        if now - cls._alert_last[key] >= cls._ALERT_COOLDOWN:
            cls._alert_last[key] = now
            return True
        return False

    @classmethod
    def analyze_ids(cls, info: dict) -> list:
        alerts = []
        now = time.time()

        # ── 5-second sliding window reset (counters only, NOT alert history) ─
        if now - cls.window_start > 5:
            cls.packet_count.clear()
            cls.port_attempts.clear()
            cls.connection_times.clear()
            cls.syn_count.clear()
            cls.dns_requests.clear()
            cls.icmp_count.clear()
            # ip_mac_map and _alert_last are intentionally NOT cleared
            cls.window_start = now

        src      = info.get("src", "")
        dst      = info.get("dst", "")
        dst_port = info.get("dst_port")
        src_mac  = info.get("src_mac")
        protocol = info.get("protocol", "")
        flags    = info.get("flags_set", set())   # pre-parsed set of flag chars

        if not src:
            return alerts

        cls.packet_count[src] += 1
        cls.connection_times[src].append(now)

        # Prune old connection times outside 2-second window
        while cls.connection_times[src] and now - cls.connection_times[src][0] > 2:
            cls.connection_times[src].popleft()

        if dst_port and isinstance(dst_port, int) and dst_port > 0:
            cls.port_attempts[src].add(dst_port)

        # ── 1. Port Scan ──────────────────────────────────────────────────────
        if len(cls.port_attempts[src]) >= cls.PORT_SCAN_THRESHOLD:
            if cls._can_alert("scan", src):
                alerts.append({
                    "type": "Port Scan",
                    "message": f"🔍 Port Scan detected from {src} ({len(cls.port_attempts[src])} ports)",
                    "severity": "high"
                })

        # ── 2. Packet Flood ───────────────────────────────────────────────────
        if cls.packet_count[src] >= cls.FLOOD_THRESHOLD:
            if cls._can_alert("flood", src):
                alerts.append({
                    "type": "DoS / SYN Flood",
                    "message": f"💥 Packet Flood from {src} ({cls.packet_count[src]} pkts/5s)",
                    "severity": "high"
                })

        # ── 3. Connection Rate ────────────────────────────────────────────────
        if len(cls.connection_times[src]) >= cls.SCAN_RATE_THRESHOLD:
            if cls._can_alert("rate", src):
                alerts.append({
                    "type": "Port Scan",
                    "message": f"⚡ High Connection Rate from {src} ({len(cls.connection_times[src])}/2s)",
                    "severity": "medium"
                })

        # ── 4. SYN Flood (uses parsed flag set) ──────────────────────────────
        if "S" in flags and "A" not in flags:
            cls.syn_count[src] += 1
            if cls.syn_count[src] >= cls.SYN_FLOOD_THRESHOLD:
                if cls._can_alert("syn", src):
                    alerts.append({
                        "type": "DoS / SYN Flood",
                        "message": f"🌊 SYN Flood from {src} ({cls.syn_count[src]} SYNs/5s)",
                        "severity": "critical"
                    })

        # ── 5. ICMP Flood ─────────────────────────────────────────────────────
        if protocol == "ICMP":
            cls.icmp_count[src] += 1
            if cls.icmp_count[src] >= cls.ICMP_FLOOD_THRESHOLD:
                if cls._can_alert("icmp", src):
                    alerts.append({
                        "type": "DoS / SYN Flood",
                        "message": f"🏓 ICMP Flood (Ping Flood) from {src} ({cls.icmp_count[src]} pkts/5s)",
                        "severity": "high"
                    })

        # ── 6. DNS Tunneling ──────────────────────────────────────────────────
        if protocol == "DNS":
            cls.dns_requests[src] += 1
            if cls.dns_requests[src] >= cls.DNS_TUNNEL_THRESHOLD:
                if cls._can_alert("dns", src):
                    alerts.append({
                        "type": "DNS Tunneling",
                        "message": f"🕳 Possible DNS Tunneling from {src} ({cls.dns_requests[src]} queries/5s)",
                        "severity": "high"
                    })

        # ── 7. ARP Spoofing ───────────────────────────────────────────────────
        if protocol == "ARP" and src_mac and src:
            if src not in cls.ip_mac_map:
                cls.ip_mac_map[src] = src_mac
            elif cls.ip_mac_map[src] != src_mac:
                if cls._can_alert("arp", src):
                    alerts.append({
                        "type": "ARP Spoofing",
                        "message": (
                            f"⚠ ARP Spoofing! {src} changed MAC: "
                            f"{cls.ip_mac_map[src]} → {src_mac}"
                        ),
                        "severity": "critical"
                    })

        return alerts

    @classmethod
    def summarize(cls, pkt) -> tuple:
        ts = getattr(pkt, "sniff_time", datetime.now())
        try:
            ts = ts.strftime("%H:%M:%S")
        except Exception:
            ts = str(ts)

        summary = {
            "timestamp": ts,
            "src": "",
            "dst": "",
            "protocol": "UNKNOWN",
            "info": "",
            "src_mac": None,
            "dst_port": None,
            "flags": "",
            "flags_set": set(),
        }
        alerts = []

        try:
            # ── MAC ────────────────────────────────────────────────────────────
            if hasattr(pkt, "eth"):
                summary["src_mac"] = pkt.eth.src

            # ── IP ─────────────────────────────────────────────────────────────
            if hasattr(pkt, "ip"):
                summary["src"] = pkt.ip.src
                summary["dst"] = pkt.ip.dst
            elif hasattr(pkt, "ipv6"):
                summary["src"] = pkt.ipv6.src
                summary["dst"] = pkt.ipv6.dst

            # ── TCP ────────────────────────────────────────────────────────────
            if hasattr(pkt, "tcp"):
                summary["protocol"] = "TCP"
                src_p = getattr(pkt.tcp, "srcport", "")
                dst_p = getattr(pkt.tcp, "dstport", "")
                try:
                    dst_p_int = int(dst_p)
                except (ValueError, TypeError):
                    dst_p_int = 0
                summary["dst_port"] = dst_p_int

                # Parse hex flags → set of letters
                raw_flags = getattr(pkt.tcp, "flags", "")
                summary["flags"] = str(raw_flags)
                summary["flags_set"] = _parse_tcp_flags(raw_flags)

                if hasattr(pkt, "http"):
                    summary["protocol"] = "HTTP"
                    host = getattr(pkt.http, "host", "")
                    uri  = getattr(pkt.http, "request_uri", "")
                    summary["info"] = f"{host}{uri} ({src_p} → {dst_p})"
                elif dst_p_int == 443 or src_p == "443":
                    summary["protocol"] = "TLS"
                    summary["info"] = f"Encrypted HTTPS ({src_p} → {dst_p})"
                else:
                    flag_str = "".join(sorted(summary["flags_set"])) or str(raw_flags)
                    summary["info"] = f"{src_p} → {dst_p} [Flags: {flag_str}]"

            # ── UDP ────────────────────────────────────────────────────────────
            elif hasattr(pkt, "udp"):
                summary["protocol"] = "UDP"
                src_p = getattr(pkt.udp, "srcport", "")
                dst_p = getattr(pkt.udp, "dstport", "")
                try:
                    summary["dst_port"] = int(dst_p)
                except (ValueError, TypeError):
                    summary["dst_port"] = 0

                if hasattr(pkt, "dns"):
                    summary["protocol"] = "DNS"
                    query = getattr(pkt.dns, "qry_name", "")
                    summary["info"] = f"Query {query}"
                elif hasattr(pkt, "dhcp"):
                    summary["protocol"] = "DHCP"
                    summary["info"] = f"DHCP {getattr(pkt.dhcp, 'option_dhcp', '')}"
                else:
                    summary["info"] = f"{src_p} → {dst_p}"

            # ── ICMP ───────────────────────────────────────────────────────────
            elif hasattr(pkt, "icmp"):
                summary["protocol"] = "ICMP"
                t = getattr(pkt.icmp, "type", "")
                summary["info"] = f"Type {t}"

            # ── ARP ────────────────────────────────────────────────────────────
            elif hasattr(pkt, "arp"):
                summary["protocol"] = "ARP"
                src_ip = getattr(pkt.arp, "src_proto_ipv4", "")
                dst_ip = getattr(pkt.arp, "dst_proto_ipv4", "")
                if src_ip:
                    summary["src"] = src_ip
                if dst_ip:
                    summary["dst"] = dst_ip
                arp_mac = getattr(pkt.arp, "src_hw_mac", None)
                if arp_mac and not summary["src_mac"]:
                    summary["src_mac"] = arp_mac
                opcode = getattr(pkt.arp, "opcode", "1")
                summary["info"] = (
                    f"Who has {dst_ip}? Tell {src_ip}" if opcode == "1"
                    else f"{src_ip} is at {arp_mac or summary['src_mac']}"
                )

            # ── Fallbacks ──────────────────────────────────────────────────────
            if not summary["src"] and hasattr(pkt, "eth"):
                summary["src"] = pkt.eth.src
            if not summary["dst"] and hasattr(pkt, "eth"):
                summary["dst"] = pkt.eth.dst
            if summary["protocol"] == "UNKNOWN":
                summary["protocol"] = getattr(pkt, "highest_layer", "UNKNOWN")
            if not summary["info"]:
                summary["info"] = f"{summary['protocol']} packet"

            # ── Rule-based IDS ─────────────────────────────────────────────────
            alerts = cls.analyze_ids(summary)

            # ── ML-IDS prediction ──────────────────────────────────────────────
            if _ML_AVAILABLE and MLIDSEngine.is_ready():
                try:
                    features = FlowFeatureExtractor.update(pkt, summary)
                    if features is not None:
                        label, confidence = MLIDSEngine.predict(features)
                        summary["ml_label"]      = label
                        summary["ml_confidence"] = round(confidence, 3)
                        if label not in ("BENIGN", "UNKNOWN"):
                            alerts.append({
                                "type": "ML Detection",
                                "message": (
                                    f"🤖 ML Detection: {label} from "
                                    f"{summary.get('src', '?')} (conf={confidence:.0%})"
                                ),
                                "severity": "high",
                                "ml": True,
                            })
                        elif label in ("BENIGN", "UNKNOWN"):
                            # Unsupervised anomaly (zero-day)
                            is_anomaly, iso_score = MLIDSEngine.predict_anomaly(features)
                            if is_anomaly:
                                summary["ml_label"]      = "ANOMALY"
                                summary["ml_confidence"] = iso_score
                                alerts.append({
                                    "type": "ML Detection",
                                    "message": (
                                        f"🤖 ML Anomaly: Unusual pattern from "
                                        f"{summary.get('src', '?')} (score={iso_score:.2f})"
                                    ),
                                    "severity": "critical",
                                    "ml": True,
                                })
                except Exception as ml_err:
                    logger.debug("ML prediction error: %s", ml_err)

        except Exception as e:
            logger.debug("Analyzer error: %s", e)

        return summary, alerts

    @staticmethod
    def details(packet) -> str:
        text = "─────────────────────────────────────────────────────────────\n"
        text += "                      PACKET INSPECTION                      \n"
        text += "─────────────────────────────────────────────────────────────\n\n"

        try:
            ts = getattr(packet, "sniff_time", "Unknown")
            length = getattr(packet, "length", "Unknown")
            highest_layer = getattr(packet, "highest_layer", "Unknown")
            text += f"Frame Info\n"
            text += f"  ├─ Sniff Time:    {ts}\n"
            text += f"  ├─ Frame Length:  {length} bytes\n"
            text += f"  └─ Highest Layer: {highest_layer}\n\n"
        except Exception:
            pass

        if hasattr(packet, "eth"):
            text += f"Ethernet Layer (L2)\n"
            text += f"  ├─ Source MAC: {packet.eth.src}\n"
            text += f"  └─ Dest MAC:   {packet.eth.dst}\n\n"

        if hasattr(packet, "ip"):
            text += f"IPv4 Layer (L3)\n"
            text += f"  ├─ Source IP:     {packet.ip.src}\n"
            text += f"  ├─ Dest IP:       {packet.ip.dst}\n"
            text += f"  ├─ Version:       {getattr(packet.ip, 'version', 'N/A')}\n"
            text += f"  ├─ TTL:           {getattr(packet.ip, 'ttl', 'N/A')}\n"
            text += f"  └─ Total Length:  {getattr(packet.ip, 'len', 'N/A')} bytes\n\n"
        elif hasattr(packet, "ipv6"):
            text += f"IPv6 Layer (L3)\n"
            text += f"  ├─ Source IP:  {packet.ipv6.src}\n"
            text += f"  ├─ Dest IP:    {packet.ipv6.dst}\n"
            text += f"  ├─ Hop Limit:  {getattr(packet.ipv6, 'hlim', 'N/A')}\n"
            text += f"  └─ Flow Label: {getattr(packet.ipv6, 'flow', 'N/A')}\n\n"

        if hasattr(packet, "tcp"):
            text += f"TCP Layer (L4)\n"
            text += f"  ├─ Source Port:      {packet.tcp.srcport}\n"
            text += f"  ├─ Destination Port: {packet.tcp.dstport}\n"
            raw_flags = getattr(packet.tcp, 'flags', 'N/A')
            parsed = _parse_tcp_flags(raw_flags)
            text += f"  ├─ Flags:            {raw_flags} ({' '.join(sorted(parsed)) or 'None'})\n"
            text += f"  ├─ Sequence Number:  {getattr(packet.tcp, 'seq', 'N/A')}\n"
            text += f"  ├─ Acknowledgment:   {getattr(packet.tcp, 'ack', 'N/A')}\n"
            text += f"  ├─ Window Size:      {getattr(packet.tcp, 'window_size', 'N/A')}\n"
            text += f"  └─ Payload Length:   {getattr(packet.tcp, 'len', 'N/A')} bytes\n\n"

        if hasattr(packet, "udp"):
            text += f"UDP Layer (L4)\n"
            text += f"  ├─ Source Port:      {packet.udp.srcport}\n"
            text += f"  ├─ Destination Port: {packet.udp.dstport}\n"
            text += f"  └─ Length:           {getattr(packet.udp, 'length', 'N/A')} bytes\n\n"

        if hasattr(packet, "icmp"):
            text += f"ICMP Layer (L3)\n"
            text += f"  ├─ Type:            {getattr(packet.icmp, 'type', 'N/A')}\n"
            text += f"  ├─ Code:            {getattr(packet.icmp, 'code', 'N/A')}\n"
            text += f"  └─ Checksum Status: {getattr(packet.icmp, 'checksum_status', 'N/A')}\n\n"

        if hasattr(packet, "arp"):
            text += f"ARP Layer (L2/L3)\n"
            text += f"  ├─ Hardware Type: {getattr(packet.arp, 'hw_type', 'N/A')}\n"
            text += f"  ├─ Protocol Type: {getattr(packet.arp, 'proto_type', 'N/A')}\n"
            text += f"  ├─ Sender IP:     {getattr(packet.arp, 'src_proto_ipv4', 'N/A')}\n"
            text += f"  ├─ Target IP:     {getattr(packet.arp, 'dst_proto_ipv4', 'N/A')}\n"
            text += f"  ├─ Sender MAC:    {getattr(packet.arp, 'src_hw_mac', 'N/A')}\n"
            text += f"  ├─ Target MAC:    {getattr(packet.arp, 'dst_hw_mac', 'N/A')}\n"
            text += f"  └─ Opcode:        {getattr(packet.arp, 'opcode', 'N/A')}\n\n"

        if hasattr(packet, "dns"):
            text += f"DNS Layer (L7)\n"
            text += f"  ├─ Transaction ID: {getattr(packet.dns, 'id', 'N/A')}\n"
            text += f"  ├─ Query:          {getattr(packet.dns, 'qry_name', 'N/A')}\n"
            text += f"  ├─ Query Type:     {getattr(packet.dns, 'qry_type', 'N/A')}\n"
            text += f"  ├─ Answers Count:  {getattr(packet.dns, 'count_answers', '0')}\n"
            text += f"  └─ Flags:          {getattr(packet.dns, 'flags', 'N/A')}\n\n"

        if hasattr(packet, "http"):
            text += f"HTTP Layer (L7)\n"
            text += f"  ├─ Host:           {getattr(packet.http, 'host', 'N/A')}\n"
            text += f"  ├─ Request URI:    {getattr(packet.http, 'request_uri', 'N/A')}\n"
            text += f"  ├─ Request Method: {getattr(packet.http, 'request_method', 'N/A')}\n"
            text += f"  ├─ User Agent:     {getattr(packet.http, 'user_agent', 'N/A')}\n"
            text += f"  └─ Response Code:  {getattr(packet.http, 'response_code', 'N/A')}\n\n"

        if hasattr(packet, "tls"):
            text += f"TLS Layer (L7)\n"
            text += f"  ├─ Version:        {getattr(packet.tls, 'record_version', 'N/A')}\n"
            text += f"  └─ Content Type:   {getattr(packet.tls, 'record_content_type', 'N/A')}\n\n"

        return text.strip()