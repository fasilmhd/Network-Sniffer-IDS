import os

class AppConstants:
    APP_NAME            = "AegisNet AI"
    VERSION             = "2.14.0"
    AUTHOR              = "FAVS Team"
    ORGANIZATION_NAME   = "Favorable AI Solutions"
    ORGANIZATION_DOMAIN = "fasilmhd.com"

    # File paths
    APP_ICON    = "resources/icons/major_icon.png"
    LOG_FILE    = "logs/app.log"
    CONFIG_FILE = "config/settings.yaml"
    DB_FILE     = "db/malware.db"
    THEME_FILE = "resources/styles/dark.qss"

    # Default scan parameters
    DEFAULT_IP_RANGE   = "192.168.1.0/24"
    DEFAULT_PORT_RANGE = "1-1000"


class ProtocolFilters:
    """Map display names to pyshark display_filter strings."""
    FILTERS = {
        "All": "",
        "TCP": "tcp",
        "UDP": "udp",
        "ICMP": "icmp",
        "ARP": "arp",
        "DNS": "dns",
        "HTTP": "http",
        "HTTPS": "tcp.port == 443",
        "FTP": "ftp",
        "SSH": "ssh",
        "TELNET": "telnet",
        "SMTP": "smtp",
        "POP3": "pop",
        "IMAP": "imap",
    }

    @classmethod
    def list(cls) -> list[str]:
        return list(cls.FILTERS.keys())

    @classmethod
    def get(cls, name: str) -> str:
        return cls.FILTERS.get(name, "")


class Colors:
    """UI color palette."""
    PRIMARY   = "#2196F3"
    SECONDARY = "#FFC107"
    SUCCESS   = "#4CAF50"
    DANGER    = "#F44336"
    WARNING   = "#FF9800"
    INFO      = "#00BCD4"
    LIGHT     = "#F5F5F5"
    DARK      = "#212121"