import psutil
import socket

def get_active_interface():
    interfaces = psutil.net_if_addrs()
    stats = psutil.net_if_stats()

    for name, addrs in interfaces.items():
        # Skip loopback
        if name.lower().startswith("lo"):
            continue

        # Check if interface is up
        if name in stats and stats[name].isup:
            for addr in addrs:
                # Look for IPv4 address
                if addr.family == socket.AF_INET and not addr.address.startswith("127."):
                    return name

    return None

def is_interface_active(iface_name: str) -> bool:
    """Check if a specific interface exists, is up, and has an IPv4 address."""
    if not iface_name:
        return False
        
    interfaces = psutil.net_if_addrs()
    stats = psutil.net_if_stats()
    
    if iface_name not in interfaces or iface_name not in stats:
        return False
        
    if not stats[iface_name].isup:
        return False
        
    for addr in interfaces[iface_name]:
        if addr.family == socket.AF_INET and not addr.address.startswith("127."):
            return True
            
    return False
