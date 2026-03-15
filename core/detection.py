import logging
from typing import Any, List, Tuple

logger = logging.getLogger("Detection")


class ThreatDetector:
    """Detect malicious packets based on IP and keyword matches."""

    BLOCKED_IPS: List[str] = ["203.0.113.99", "198.51.100.23"]
    SUSPICIOUS_KEYWORDS: List[str] = [
        "malware", "spy", "exploit", "ransom", "tracker"
    ]

    @classmethod
    def scan(cls, packet: Any) -> Tuple[bool, str]:
        detected = False
        details = []
        try:
            ip = getattr(packet, "ip", None)
            if ip:
                src, dst = ip.src, ip.dst
                if src in cls.BLOCKED_IPS:
                    detected = True
                    details.append(f"Blocked src IP {src}")
                if dst in cls.BLOCKED_IPS:
                    detected = True
                    details.append(f"Blocked dst IP {dst}")

            text = str(packet).lower()
            for kw in cls.SUSPICIOUS_KEYWORDS:
                if kw in text:
                    detected = True
                    details.append(f"Keyword '{kw}'")
        except Exception as e:
            logger.error("Threat scan error: %s", e)

        return detected, "; ".join(details)


class AdBlocker:
    """Detect ad/tracker traffic in HTTP Host or DNS queries."""

    AD_KEYWORDS: List[str] = [
        "ads", "doubleclick", "googlesyndication", "tracker", "pixel"
    ]

    @classmethod
    def scan(cls, packet: Any) -> Tuple[bool, str]:
        detected = False
        details = []
        try:
            http = getattr(packet, "http", None)
            if http and hasattr(http, "host"):
                host = http.host.lower()
                for kw in cls.AD_KEYWORDS:
                    if kw in host:
                        detected = True
                        details.append(f"HTTP host '{host}'")
                        break

            dns = getattr(packet, "dns", None)
            if dns and hasattr(dns, "qry_name"):
                qn = dns.qry_name.lower()
                for kw in cls.AD_KEYWORDS:
                    if kw in qn:
                        detected = True
                        details.append(f"DNS query '{qn}'")
                        break

        except Exception as e:
            logger.error("Ad detection error: %s", e)

        return detected, "; ".join(details)