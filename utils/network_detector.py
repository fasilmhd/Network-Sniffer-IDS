# utils/network_detector.py
import socket
import psutil

def get_local_ip() -> str:
    """Detects the active local IP address."""
    try:
        # Connect to a public DNS server just to figure out which local interface is used
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(2.0)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        # Fallback to local hostname resolution
        try:
            return socket.gethostbyname(socket.gethostname())
        except Exception:
            return "127.0.0.1"

def get_network_range() -> str:
    """Calculates the /24 subnet for the local IP."""
    ip = get_local_ip()
    if ip == "127.0.0.1":
        return "127.0.0.1/32"
    
    parts = ip.split(".")
    if len(parts) == 4:
        return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
    return "0.0.0.0/0"
