import logging
import scapy.all as scapy
from typing import List, Dict



logger = logging.getLogger("PortScanner")


class ArpHostScanner:
    """ARP-based LAN host discovery."""

    def discover_hosts(self, ip_range: str) -> List[Dict[str, str]]:
        """
        Discovers active hosts within a given IP range using ARP requests.

        Sends ARP requests to each IP address in the specified range and listens for responses
        to identify active hosts.

        Args:
            ip_range (str): The IP address range to scan (e.g., "192.168.1.1/24").

        Returns:
            List[Dict[str, str]]: A list of dictionaries, where each dictionary represents an active host
                                    found on the network. Each dictionary contains the 'ip' and 'mac'
                                    address of the host. Returns an empty list if no hosts are found or if an
                                    error occurs during the scan.
        """
        try:
            arp = scapy.ARP(pdst=ip_range)
            ether = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
            ans = scapy.srp(ether/arp, timeout=2, verbose=False)[0]
            return [{"ip": r[1].psrc, "mac": r[1].hwsrc} for r in ans]
        except Exception as e:
            logger.error("ARP scan error: %s", e)
            return []