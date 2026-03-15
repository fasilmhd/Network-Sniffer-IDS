import subprocess
import logging
from PySide6.QtWidgets import QMessageBox

logger = logging.getLogger(__name__)

def block_ip(ip: str) -> bool:
    """
    Blocks an IP address using Windows Defender Firewall.
    Returns True if successful, False otherwise.
    """
    try:
        rule_name = f"NetworkSniffer_Block_{ip}"

        # Delete existing rule if it exists to avoid duplicates
        delete_cmd = [
            "netsh", "advfirewall", "firewall", "delete", "rule", 
            f"name={rule_name}"
        ]
        subprocess.run(delete_cmd, capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW)

        # Add the block rule
        cmd = [
            "netsh",
            "advfirewall",
            "firewall",
            "add",
            "rule",
            f"name={rule_name}",
            "dir=in",
            "action=block",
            f"remoteip={ip}"
        ]

        result = subprocess.run(cmd, capture_output=True, text=True, creationflags=subprocess.CREATE_NO_WINDOW)
        
        if result.returncode == 0:
            logger.info(f"Successfully blocked IP: {ip}")
            return True
        else:
            logger.error(f"Failed to block IP {ip}: {result.stderr}")
            return False

    except Exception as e:
        logger.exception(f"Firewall block error: {e}")
        return False
