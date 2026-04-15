"""Cloudflare IP range management and random IP selection.

Maintains the official Cloudflare IPv4 CIDR blocks and provides
efficient random IP sampling from them, weighted by subnet size.
The list can be refreshed at runtime from https://www.cloudflare.com/ips-v4/
or extended with user-supplied ranges.
"""

import ipaddress
import random
import socket
import logging
from typing import List, Optional, Set

logger = logging.getLogger("snispf")

# Official Cloudflare IPv4 ranges (as of 2026-04)
# Source: https://www.cloudflare.com/ips-v4/
CLOUDFLARE_IPV4_RANGES = [
    "173.245.48.0/20",
    "103.21.244.0/22",
    "103.22.200.0/22",
    "103.31.4.0/22",
    "141.101.64.0/18",
    "108.162.192.0/18",
    "190.93.240.0/20",
    "188.114.96.0/20",
    "197.234.240.0/22",
    "198.41.128.0/17",
    "162.158.0.0/15",
    "104.16.0.0/13",
    "104.24.0.0/14",
    "172.64.0.0/13",
    "131.0.72.0/22",
]


class CloudflareIPPool:
    """Manages Cloudflare IP ranges and generates random candidate IPs.

    The pool stores parsed CIDR networks and can produce random IPs
    from them, weighted by the size of each subnet.  Network and
    broadcast addresses are excluded to avoid hitting reserved entries.

    Usage::

        pool = CloudflareIPPool()
        pool.load_defaults()
        ips = pool.sample(50)  # 50 random Cloudflare IPs
    """

    def __init__(self):
        self._networks: List[ipaddress.IPv4Network] = []
        self._weights: List[int] = []
        self._total_hosts: int = 0
        self._blacklist: Set[str] = set()

    # ── Loading ───────────────────────────────────────────────────────

    def load_defaults(self):
        """Load the built-in Cloudflare IPv4 ranges."""
        self.add_ranges(CLOUDFLARE_IPV4_RANGES)

    def add_ranges(self, cidrs: List[str]):
        """Add CIDR ranges to the pool.

        Args:
            cidrs: List of CIDR strings like ``"104.16.0.0/13"``.
        """
        for cidr in cidrs:
            try:
                net = ipaddress.IPv4Network(cidr, strict=False)
                self._networks.append(net)
                host_count = max(net.num_addresses - 2, 1)
                self._weights.append(host_count)
                self._total_hosts += host_count
            except (ipaddress.AddressValueError, ValueError) as exc:
                logger.warning("Skipping invalid CIDR %r: %s", cidr, exc)

    def load_from_url(self, url: str = "https://www.cloudflare.com/ips-v4/",
                      timeout: float = 10.0) -> bool:
        """Fetch current Cloudflare ranges from their public endpoint.

        Returns ``True`` on success.
        """
        try:
            import urllib.request
            req = urllib.request.Request(url, headers={"User-Agent": "SNISPF"})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                body = resp.read().decode().strip()
            lines = [ln.strip() for ln in body.splitlines() if ln.strip()]
            if lines:
                self._networks.clear()
                self._weights.clear()
                self._total_hosts = 0
                self.add_ranges(lines)
                logger.info("Loaded %d Cloudflare ranges from %s",
                            len(self._networks), url)
                return True
        except Exception as exc:
            logger.warning("Could not fetch Cloudflare ranges: %s", exc)
        return False

    # ── Blacklist ─────────────────────────────────────────────────────

    def blacklist_ip(self, ip: str):
        """Mark an IP as blocked so it won't be returned again."""
        self._blacklist.add(ip)

    def clear_blacklist(self):
        self._blacklist.clear()

    # ── Sampling ──────────────────────────────────────────────────────

    @property
    def total_hosts(self) -> int:
        return self._total_hosts

    @property
    def network_count(self) -> int:
        return len(self._networks)

    def random_ip(self) -> str:
        """Return a single random Cloudflare IP, avoiding blacklisted ones."""
        if not self._networks:
            raise RuntimeError("IP pool is empty -- call load_defaults() first")

        for _ in range(200):
            net = random.choices(self._networks, weights=self._weights, k=1)[0]
            first = int(net.network_address) + 1
            last = int(net.broadcast_address) - 1
            if first > last:
                first = int(net.network_address)
                last = int(net.broadcast_address)
            addr = str(ipaddress.IPv4Address(random.randint(first, last)))
            if addr not in self._blacklist:
                return addr

        # If we somehow can't avoid the blacklist, return any address
        net = random.choice(self._networks)
        first = int(net.network_address) + 1
        last = int(net.broadcast_address) - 1
        return str(ipaddress.IPv4Address(random.randint(first, last)))

    def sample(self, count: int) -> List[str]:
        """Return *count* unique random Cloudflare IPs."""
        seen: Set[str] = set()
        results: List[str] = []
        max_attempts = count * 5
        attempts = 0
        while len(results) < count and attempts < max_attempts:
            ip = self.random_ip()
            if ip not in seen:
                seen.add(ip)
                results.append(ip)
            attempts += 1
        return results

    # ── Specific IPs ──────────────────────────────────────────────────

    def contains(self, ip: str) -> bool:
        """Check whether *ip* belongs to a Cloudflare range."""
        try:
            addr = ipaddress.IPv4Address(ip)
        except (ipaddress.AddressValueError, ValueError):
            return False
        return any(addr in net for net in self._networks)
