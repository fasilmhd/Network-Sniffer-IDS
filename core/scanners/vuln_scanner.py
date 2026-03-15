import logging
import nmap
from typing import Any, Dict

logger = logging.getLogger("VulnScanner")


class VulnScanner:
    """Nmap-based vulnerability scanning via NSE scripts."""

    def __init__(self) -> None:
        self.scanner = nmap.PortScanner()

    def scan(self, target: str, mode: str) -> Dict[str, Any]:
        args_map = {
            "quick": "--script vuln",
            "advanced": "-sS -sV -O --script vuln",
            "full": "-p- -sS -sV -O --script vuln",
        }
        args = args_map.get(mode, "--script vuln")

        try:
            self.scanner.scan(target, arguments=args)
            result = {}
            for host in self.scanner.all_hosts():
                result[host] = self.scanner[host]
            return result
        except Exception as e:
            logger.error("Vuln scan error: %s", e)
            return {"error": str(e)}