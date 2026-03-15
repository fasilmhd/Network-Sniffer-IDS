
import nmap
import logging

logger = logging.getLogger("NmapService")


class NmapService:
    """
    Wrapper around python-nmap's PortScanner.
    Provides port and vulnerability scanning methods.
    """

    
    def scan_ports(self, target: str, ports: str, arguments: str = "-sV -O") -> nmap.PortScanner:
        """
        Scan specified ports on target.
        :param target: IP address or hostname
        :param ports: port range string, e.g. "1-1000"
        :param arguments: nmap arguments for service/version detection
        :return: the populated PortScanner object
        """
        try:
            self.scanner = nmap.PortScanner()
            self.scanner.scan(target, ports, arguments=arguments)
        except Exception as e:
            logger.error("Port scan error on %s ports %s: %s", target, ports, e)
        return self.scanner

    def scan_vulnerabilities(self, target: str, mode: str = "quick") -> nmap.PortScanner:
        """
        Run NSE vulnerability scripts against target.
        :param target: IP or hostname
        :param mode: one of "quick", "advanced", "full"
        """
        mode_args = {
            "quick": "--script vuln",
            "advanced": "-sS -sV -O --script vuln",
            "full": "-p- -sS -sV -O --script vuln",
        }
        args = mode_args.get(mode, "--script vuln")
        try:
            self.scanner.scan(target, arguments=args)
        except Exception as e:
            logger.error("Vuln scan error on %s mode %s: %s", target, mode, e)
        return self.scanner