"""Network utility functions.

Cross-platform network interface detection and helpers.
"""

import socket
import sys
import platform
from typing import Optional


def get_default_interface_ipv4(dest: str = "8.8.8.8") -> Optional[str]:
    """Get the IPv4 address of the default network interface.

    Creates a UDP socket and connects to a public address to determine
    which local IP would be used for outgoing connections.

    Args:
        dest: Destination IP to determine route (not actually contacted)

    Returns:
        Local IPv4 address string, or None on failure
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect((dest, 53))
        addr = s.getsockname()[0]
        s.close()
        return addr
    except OSError:
        return None


def get_default_interface_ipv6(dest: str = "2001:4860:4860::8888") -> Optional[str]:
    """Get the IPv6 address of the default network interface.

    Args:
        dest: Destination IPv6 to determine route

    Returns:
        Local IPv6 address string, or None on failure
    """
    try:
        s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        s.connect((dest, 53))
        addr = s.getsockname()[0]
        s.close()
        return addr
    except OSError:
        return None


def check_platform_capabilities() -> dict:
    """Check what DPI bypass capabilities are available on this platform.

    Returns:
        Dictionary of available features
    """
    caps = {
        "platform": platform.system(),
        "python_version": sys.version,
        "fragment_support": True,  # Always available (userspace TCP)
        "tls_record_frag": True,   # Always available (application layer)
        "fake_sni": True,          # Always available (application layer)
        "tcp_nodelay": True,       # Always available
        "raw_socket": False,       # Platform-dependent
        "ip_ttl_trick": False,     # Platform-dependent
    }

    # Check raw socket support (needed for advanced tricks)
    try:
        if platform.system() != "Windows":
            s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
            s.close()
            caps["raw_socket"] = True
            caps["ip_ttl_trick"] = True
        else:
            # Windows raw sockets are limited
            caps["raw_socket"] = False
    except (PermissionError, OSError):
        pass

    # Check AF_PACKET support (Linux only, needed for seq_id injection)
    try:
        if platform.system() == "Linux":
            s = socket.socket(
                socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003)
            )
            s.close()
            caps["af_packet"] = True
            caps["raw_injection"] = True
        else:
            caps["af_packet"] = False
            caps["raw_injection"] = False
    except (PermissionError, OSError, AttributeError):
        caps["af_packet"] = False
        caps["raw_injection"] = False

    return caps


def resolve_host(host: str) -> str:
    """Resolve hostname to IP address.

    Args:
        host: Hostname or IP address

    Returns:
        IP address string
    """
    try:
        return socket.gethostbyname(host)
    except socket.gaierror:
        return host


def is_valid_ip(addr: str) -> bool:
    """Check if string is a valid IPv4 or IPv6 address."""
    for family in (socket.AF_INET, socket.AF_INET6):
        try:
            socket.inet_pton(family, addr)
            return True
        except (socket.error, OSError):
            continue
    return False


def is_valid_port(port: int) -> bool:
    """Check if port number is valid."""
    return isinstance(port, int) and 1 <= port <= 65535
