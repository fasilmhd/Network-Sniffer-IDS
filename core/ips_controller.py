import threading
from utils.firewall_blocker import block_ip

class IPSController:
    """Smart Tiered Defense Controller."""

    @staticmethod
    def evaluate_and_respond(message: str, attacker_ip: str, panel: object):
        if not attacker_ip:
            return

        msg_lower = message.lower()

        # Level 3: Isolate (Critical)
        if "arp spoofing" in msg_lower or "zero-day" in msg_lower or "anomaly" in msg_lower or "critical" in msg_lower:
            if panel and hasattr(panel, "add_alert"):
                panel.add_alert(f"🛡️ Smart Defense (Level 3): Isolating {attacker_ip} from network")

            def _block():
                success = block_ip(attacker_ip)
                if success and panel:
                    if hasattr(panel, "record_blocked_ip"):
                        panel.record_blocked_ip(attacker_ip)

            threading.Thread(target=_block, daemon=True).start()

        # Level 2: Defend (High)
        elif "syn flood" in msg_lower or "dos" in msg_lower or ("ml:" in msg_lower and "high" in message.lower()):
            if panel and hasattr(panel, "add_alert"):
                panel.add_alert(f"🛡️ Smart Defense (Level 2): Blocking {attacker_ip} immediately")

            def _block():
                success = block_ip(attacker_ip)
                if success and panel:
                    if hasattr(panel, "record_blocked_ip"):
                        panel.record_blocked_ip(attacker_ip)

            threading.Thread(target=_block, daemon=True).start()

        # Level 1: Monitor
        elif "scan" in msg_lower or "unknown" in msg_lower:
            if panel and hasattr(panel, "add_alert"):
                panel.add_alert(f"🛡️ Smart Defense (Level 1): Monitoring suspicious behaviour from {attacker_ip}")
