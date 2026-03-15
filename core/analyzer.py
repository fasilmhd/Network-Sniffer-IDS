import logging
from datetime import datetime
from typing import Any, Dict, List, Tuple
from core.intrusion_detector import IntrusionDetector

logger = logging.getLogger("Analyzer")

# Single IDS instance
detector = IntrusionDetector()


class PacketAnalyzer:
    """Extract summary and detailed information from packets."""

    @staticmethod
    def summarize(packet: Any) -> Tuple[Dict[str, str], List[Dict[str, str]]]:

        ts = datetime.now().strftime("%H:%M:%S.%f")[:-3]

        info = {
            "timestamp": ts,
            "src": "",
            "dst": "",
            "protocol": getattr(packet, "highest_layer", "N/A"),
            "info": ""
        }

        alerts: List[Dict[str, str]] = []

        try:
            ip = getattr(packet, "ip", None)

            if ip:
                info["src"] = getattr(ip, "src", "") or ""
                info["dst"] = getattr(ip, "dst", "") or ""

            # -------- Protocol Detection --------

            if hasattr(packet, "tcp"):
                tcp = packet.tcp
                info["protocol"] = "TCP"
                info["info"] = f"{getattr(tcp,'srcport','')}→{getattr(tcp,'dstport','')}"

            elif hasattr(packet, "udp"):
                udp = packet.udp
                info["protocol"] = "UDP"
                info["info"] = f"{getattr(udp,'srcport','')}→{getattr(udp,'dstport','')}"

            elif hasattr(packet, "icmp"):
                icmp = packet.icmp
                info["protocol"] = "ICMP"
                info["info"] = f"Type {getattr(icmp,'type','')}"

            elif hasattr(packet, "arp"):
                arp = packet.arp
                info["protocol"] = "ARP"
                info["info"] = f"Who has {getattr(arp,'dst_proto_ipv4','')}?"

            # -------- IDS INPUT DATA --------

            packet_info = {
                "src_ip": info.get("src"),
                "dst_ip": info.get("dst"),
                "dst_port": None,
                "protocol": info.get("protocol"),
                "src_mac": getattr(packet.eth, "src", None) if hasattr(packet, "eth") else None
            }

            if hasattr(packet, "tcp"):
                packet_info["dst_port"] = getattr(packet.tcp, "dstport", None)

            elif hasattr(packet, "udp"):
                packet_info["dst_port"] = getattr(packet.udp, "dstport", None)

            # -------- Run IDS --------

            try:
                alerts = detector.analyze_packet(packet_info) or []
            except Exception as e:
                logger.exception("Detector error: %s", e)
                alerts = []

            # Log alerts
            for alert in alerts:
                try:
                    msg = alert.get("message") if isinstance(alert, dict) else str(alert)
                    logger.warning(f"[SECURITY ALERT] {msg}")
                except Exception:
                    logger.warning("[SECURITY ALERT] malformed alert")

        except Exception as e:
            logger.exception("Summarize error: %s", e)
            return info, alerts

        return info, alerts

    @staticmethod
    def details(packet: Any) -> str:

        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]

        lines = [
            f"=== PACKET DETAILS ({ts}) ===",
            f"Highest Layer: {getattr(packet,'highest_layer','N/A')}",
            f"Length: {getattr(packet,'length','N/A')} bytes",
            ""
        ]

        try:

            eth = getattr(packet, "eth", None)
            if eth:
                lines += [
                    "--- Ethernet Layer ---",
                    f"Source MAC: {getattr(eth,'src','N/A')}",
                    f"Destination MAC: {getattr(eth,'dst','N/A')}",
                    ""
                ]

            ip = getattr(packet, "ip", None)
            if ip:
                lines += [
                    "--- IP Layer ---",
                    f"Version: {getattr(ip,'version','N/A')}",
                    f"Source IP: {getattr(ip,'src','N/A')}",
                    f"Destination IP: {getattr(ip,'dst','N/A')}",
                    ""
                ]

            tcp = getattr(packet, "tcp", None)
            if tcp:
                lines += [
                    "--- TCP Layer ---",
                    f"Source Port: {getattr(tcp,'srcport','N/A')}",
                    f"Destination Port: {getattr(tcp,'dstport','N/A')}",
                    f"Flags: {getattr(tcp,'flags','N/A')}",
                    ""
                ]

            udp = getattr(packet, "udp", None)
            if udp:
                lines += [
                    "--- UDP Layer ---",
                    f"Source Port: {getattr(udp,'srcport','N/A')}",
                    f"Destination Port: {getattr(udp,'dstport','N/A')}",
                    ""
                ]

            icmp = getattr(packet, "icmp", None)
            if icmp:
                lines += [
                    "--- ICMP Layer ---",
                    f"Type: {getattr(icmp,'type','N/A')}",
                    f"Code: {getattr(icmp,'code','N/A')}",
                    ""
                ]

            arp = getattr(packet, "arp", None)
            if arp:
                lines += [
                    "--- ARP Layer ---",
                    f"Src IP: {getattr(arp,'src_proto_ipv4','N/A')}",
                    f"Dst IP: {getattr(arp,'dst_proto_ipv4','N/A')}",
                    ""
                ]

            raw = str(packet)

            lines += [
                "--- Raw Data ---",
                raw[:500]
            ]

        except Exception as e:
            logger.exception("Details error: %s", e)
            return f"Error generating details: {e}"

        return "\n".join(lines)