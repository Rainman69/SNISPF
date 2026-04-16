"""Cloudflare IP range management and random IP selection.

Maintains the official Cloudflare IPv4 CIDR blocks and provides
efficient random IP sampling from them, weighted by subnet size.
The list can be refreshed at runtime from https://www.cloudflare.com/ips-v4/
or extended with user-supplied ranges.

For networks with DNS poisoning (e.g. Iran), the module also ships a set
of pre-resolved "seed" IPs that have historically been clean on
Cloudflare's edge.  The scanner can start by testing these known-good
IPs first -- no DNS resolution required.
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

# ── Pre-resolved seed IPs ─────────────────────────────────────────────
#
# These are known Cloudflare edge IPs that have been verified to respond
# to TLS handshakes.  In regions with DNS poisoning (e.g. Iran), normal
# DNS resolution of Cloudflare domains may return bogus answers or time
# out entirely.  By shipping these IPs as "seeds", the scanner can skip
# DNS resolution altogether and go straight to TCP+TLS probing.
#
# The IPs are spread across many Cloudflare /20 and /13 prefixes so that
# if one prefix is blocked, others will still work.  They are grouped by
# the Cloudflare range they belong to.
#
# These are NOT meant to be exhaustive -- the scanner will also generate
# random IPs from CLOUDFLARE_IPV4_RANGES to discover new clean endpoints.
# The seeds just provide a head start and a guaranteed set of candidates
# that don't require DNS.
CLOUDFLARE_SEED_IPS = [
    # ── 104.16.0.0/13 (largest range, most variety) ──
    "104.16.1.34",     # registry.npmjs.org
    "104.16.6.34",     # registry.npmjs.org
    "104.16.8.34",     # registry.npmjs.org
    "104.16.24.14",    # www.patreon.com
    "104.16.25.14",    # www.patreon.com
    "104.16.25.46",    # www.glassdoor.com
    "104.16.57.5",     # cloudflare infrastructure
    "104.16.79.73",    # static.cloudflareinsights.com
    "104.16.80.73",    # static.cloudflareinsights.com
    "104.16.99.52",    # codepen.io
    "104.16.100.52",   # codepen.io
    "104.16.102.112",  # www.canva.com
    "104.16.103.112",  # www.canva.com
    "104.16.123.96",   # dev.to
    "104.16.124.96",   # dev.to
    "104.16.132.229",  # www.coursera.org
    "104.16.133.229",  # www.coursera.org
    "104.16.142.237",  # www.udemy.com
    "104.16.143.237",  # www.udemy.com
    "104.16.160.145",  # onesignal.com
    "104.16.174.181",  # proton.me
    "104.16.175.181",  # proton.me
    "104.16.196.131",  # workers.cloudflare.com
    "104.16.197.131",  # workers.cloudflare.com
    "104.16.210.11",   # chatgpt.com
    "104.16.248.249",  # cloudflare-dns.com
    "104.16.249.249",  # cloudflare-dns.com
    "104.17.2.184",    # www.coinmarketcap.com
    "104.17.3.184",    # www.coinmarketcap.com
    "104.17.24.14",    # cdnjs.cloudflare.com
    "104.17.25.14",    # cdnjs.cloudflare.com
    "104.17.33.82",    # huggingface.co
    "104.17.64.70",    # www.glassdoor.com
    "104.17.72.14",    # ajax.cloudflare.com
    "104.17.73.14",    # ajax.cloudflare.com
    "104.17.96.13",    # www.figma.com
    "104.17.110.184",  # dash.cloudflare.com
    "104.17.111.184",  # dash.cloudflare.com
    "104.17.111.223",  # onesignal.com
    "104.17.113.188",  # www.notion.so
    "104.17.134.117",  # www.npmjs.com
    "104.17.135.117",  # www.npmjs.com
    "104.17.147.16",   # www.garmin.com
    "104.17.147.22",   # www.speedtest.net
    "104.17.148.16",   # www.garmin.com
    "104.17.148.22",   # www.speedtest.net
    # ── 104.18.0.0/15 (still in 104.16.0.0/13) ──
    "104.18.0.22",     # unpkg.com
    "104.18.1.22",     # unpkg.com
    "104.18.6.192",    # www.bitwarden.com
    "104.18.7.192",    # www.bitwarden.com
    "104.18.11.76",    # excalidraw.com
    "104.18.12.76",    # excalidraw.com
    "104.18.22.113",   # www.coindesk.com
    "104.18.23.113",   # www.coindesk.com
    "104.18.24.243",   # clickup.com
    "104.18.25.243",   # clickup.com
    "104.18.28.213",   # www.toptal.com
    "104.18.29.213",   # www.toptal.com
    "104.18.30.78",    # radar.cloudflare.com
    "104.18.31.78",    # radar.cloudflare.com
    "104.18.32.7",     # www.perplexity.ai
    "104.18.33.7",     # www.perplexity.ai
    "104.18.34.51",    # www.zendesk.com
    "104.18.34.202",   # www.crunchyroll.com
    "104.18.35.15",    # www.coinbase.com
    "104.18.38.202",   # auth.vercel.com
    "104.18.39.114",   # www.hubspot.com
    "104.18.42.219",   # calendly.com
    "104.18.43.219",   # calendly.com
    "104.18.94.41",    # challenges.cloudflare.com
    "104.18.95.41",    # challenges.cloudflare.com
    "104.18.160.78",   # hcaptcha.com
    "104.18.161.78",   # hcaptcha.com
    # ── 104.24.0.0/14 ──
    "104.24.0.54",     # imgbb.com
    "104.24.1.54",     # imgbb.com
    "104.24.100.22",   # alternativeto.net
    "104.24.101.22",   # alternativeto.net
    "104.24.104.58",   # www.greasyfork.org
    "104.24.105.58",   # www.greasyfork.org
    "104.25.210.99",   # www.investing.com
    "104.25.211.99",   # www.investing.com
    "104.26.0.139",    # mega.nz
    "104.26.1.139",    # mega.nz
    "104.26.5.71",     # remove.bg
    "104.26.6.71",     # remove.bg
    "104.26.8.139",    # etherscan.io
    "104.26.9.139",    # etherscan.io
    "104.26.10.78",    # www.tradingview.com
    "104.26.11.78",    # www.tradingview.com
    "104.26.12.54",    # www.time.is
    "104.26.13.54",    # www.time.is
    # ── 162.158.0.0/15 ──
    "162.159.128.233",  # developers.cloudflare.com
    "162.159.129.233",  # developers.cloudflare.com
    "162.159.130.234",  # pages.cloudflare.com
    "162.159.135.232",  # www.discord.com
    "162.159.136.232",  # www.discord.com
    "162.159.137.232",  # www.discord.com
    "162.159.138.232",  # www.discord.com
    "162.159.140.245",  # api.openai.com
    "162.159.152.4",    # www.medium.com
    "162.159.153.4",    # www.medium.com
    "162.159.193.1",    # mozilla.cloudflare-dns.com
    # ── 172.64.0.0/13 ──
    "172.64.80.1",     # api.cloudflare.com
    "172.64.148.142",  # www.hubspot.com
    "172.64.149.54",   # auth.vercel.com
    "172.64.150.83",   # www.hackerone.com
    "172.64.152.241",  # www.coinbase.com
    "172.64.153.54",   # www.crunchyroll.com
    "172.64.153.205",  # www.zendesk.com
    "172.64.154.8",    # zapier.com
    "172.64.155.188",  # metamask.io
    "172.65.32.11",    # supabase.com
    "172.65.251.78",   # www.gitlab.com
    "172.66.0.243",    # api.openai.com
    "172.66.40.37",    # replit.com
    "172.66.43.12",    # www.quora.com
    "172.67.0.1",      # generic CF anycast
    "172.67.1.1",      # generic CF anycast
    "172.67.2.1",      # generic CF anycast
    "172.67.68.14",    # www.producthunt.com
    "172.67.70.38",    # www.ycombinator.com
    "172.67.73.166",   # hashnode.com
    "172.67.75.163",   # www.gumroad.com
    "172.67.128.1",    # generic CF anycast
    # ── 188.114.96.0/20 ──
    "188.114.96.1",
    "188.114.96.3",
    "188.114.96.6",
    "188.114.97.1",
    "188.114.97.3",
    "188.114.97.6",
    "188.114.98.1",
    "188.114.98.3",
    "188.114.98.6",
    "188.114.99.1",
    "188.114.99.3",
    "188.114.99.6",
    # ── 141.101.64.0/18 ──
    "141.101.64.1",
    "141.101.65.1",
    "141.101.66.1",
    "141.101.67.1",
    "141.101.68.1",
    "141.101.69.1",
    "141.101.70.1",
    "141.101.71.1",
    "141.101.76.1",
    "141.101.77.1",
    "141.101.90.1",
    "141.101.91.1",
    # ── 198.41.128.0/17 ──
    "198.41.128.1",
    "198.41.129.1",
    "198.41.192.1",
    "198.41.193.1",
    "198.41.200.1",
    "198.41.201.1",
    "198.41.208.1",
    "198.41.209.1",
    "198.41.212.1",
    "198.41.213.1",
    "198.41.214.1",
    "198.41.215.1",
    # ── 173.245.48.0/20 ──
    "173.245.48.1",
    "173.245.49.1",
    "173.245.50.1",
    "173.245.52.1",
    "173.245.53.1",
    "173.245.54.1",
    "173.245.58.1",
    "173.245.59.1",
    # ── 108.162.192.0/18 ──
    "108.162.192.1",
    "108.162.193.1",
    "108.162.194.1",
    "108.162.195.1",
    "108.162.196.1",
    "108.162.210.1",
    "108.162.211.1",
    "108.162.220.1",
    "108.162.221.1",
    # ── 103.21.244.0/22, 103.22.200.0/22, 103.31.4.0/22 ──
    "103.21.244.1",
    "103.21.244.2",
    "103.21.245.1",
    "103.22.200.1",
    "103.22.200.2",
    "103.22.201.1",
    "103.31.4.1",
    "103.31.4.2",
    "103.31.5.1",
    "103.31.6.1",
    # ── 190.93.240.0/20 ──
    "190.93.240.1",
    "190.93.241.1",
    "190.93.242.1",
    "190.93.244.1",
    "190.93.245.1",
    "190.93.246.1",
    # ── 197.234.240.0/22 ──
    "197.234.240.1",
    "197.234.241.1",
    "197.234.242.1",
    # ── 131.0.72.0/22 ──
    "131.0.72.1",
    "131.0.72.2",
    "131.0.73.1",
    "131.0.74.1",
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

    def sample_with_seeds(self, count: int) -> List[str]:
        """Return *count* IPs, starting with seed IPs first.

        In networks with DNS poisoning (e.g. Iran), this ensures the
        scanner always has a guaranteed set of known-good Cloudflare IPs
        to test, without needing any DNS resolution.

        The returned list starts with shuffled seed IPs (not blacklisted),
        topped up with random IPs from the CIDR pool to reach *count*.
        """
        seen: Set[str] = set()
        results: List[str] = []

        # Shuffle a copy of the seed list so different runs test in different order
        seeds = list(CLOUDFLARE_SEED_IPS)
        random.shuffle(seeds)

        for ip in seeds:
            if ip not in self._blacklist and ip not in seen:
                seen.add(ip)
                results.append(ip)
                if len(results) >= count:
                    return results

        # Top up with random IPs from CIDR ranges
        max_attempts = (count - len(results)) * 5
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
