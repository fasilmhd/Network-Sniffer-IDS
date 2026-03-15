import logging
import os
import scapy.all as scapy

logger = logging.getLogger("AntiSniff")


class AntiSniffEngine:
    """Detect ARP spoofing and promiscuous-mode sniffing."""

    @staticmethod
    def detect_arp_spoof(gateway_ip: str = "192.168.1.1") -> bool:
        try:
            arp = scapy.ARP(pdst=gateway_ip)
            ether = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
            ans = scapy.srp(ether/arp, timeout=2, verbose=False)[0]
            if ans:
                real_mac = ans[0][1].hwsrc
                if real_mac not in os.popen("arp -a").read():
                    logger.warning("ARP spoof suspected: %s", real_mac)
                    return True
        except Exception as e:
            logger.error("ARP spoof detection error: %s", e)
        return False

    @staticmethod
    def detect_promiscuous() -> bool:
        try:
            fake_mac = "00:11:22:33:44:55"
            pkt = scapy.Ether(dst=fake_mac)/scapy.IP(dst="127.0.0.1")/scapy.ICMP()
            ans = scapy.srp(pkt, timeout=2, verbose=False)[0]
            if ans:
                logger.warning("Promiscuous mode suspected")
                return True
        except Exception as e:
            logger.error("Promiscuous detection error: %s", e)
        return False