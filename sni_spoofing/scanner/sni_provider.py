"""SNI domain list management and rotation.

Maintains an ordered list of SNI domains (Cloudflare-fronted sites)
that can be used as the fake SNI for DPI bypass.  Domains are tested
periodically and rotated when they become blocked.

Users can supply their own list via config or CLI.  A sensible set of
defaults is built in -- these are high-traffic Cloudflare-fronted
domains that are rarely blocked.
"""

import logging
import random
import socket
import ssl
import time
from dataclasses import dataclass
from typing import Dict, List, Optional

logger = logging.getLogger("snispf")

# Default SNI domains -- ALL verified to be behind Cloudflare's CDN.
#
# IMPORTANT: Every domain on this list has been verified to resolve to
# Cloudflare IP ranges. Non-Cloudflare domains (e.g. dl.google.com,
# cdn.shopify.com, fonts.googleapis.com, cdn.jsdelivr.net, www.zoom.us)
# must NOT be listed here because they will fail TLS handshake when
# connected through Cloudflare IPs.
#
# The list is ordered by priority: domains that are least likely to be
# blocked in restrictive networks (like Iran) come first. Cloudflare's
# own infrastructure domains are prioritised because they are critical
# for many services and rarely blocked completely.
DEFAULT_SNI_DOMAINS = [
    # ── Cloudflare infrastructure (highest priority, almost never blocked) ──
    "cdnjs.cloudflare.com",
    "ajax.cloudflare.com",
    "static.cloudflareinsights.com",
    "challenges.cloudflare.com",
    "workers.cloudflare.com",
    "cloudflare-dns.com",
    "radar.cloudflare.com",
    "dash.cloudflare.com",
    # ── High-traffic sites behind Cloudflare (commonly whitelisted) ──
    "www.speedtest.net",
    "www.canva.com",
    "www.udemy.com",
    "www.medium.com",
    "www.discord.com",
    "registry.npmjs.org",
    "www.npmjs.com",
    "api.openai.com",
    "auth.vercel.com",
    "unpkg.com",
    # ── Large services on Cloudflare (good fallbacks) ──
    "www.crunchyroll.com",
    "www.zendesk.com",
    "www.hubspot.com",
    "www.glassdoor.com",
    "www.garmin.com",
    "www.patreon.com",
    "www.toptal.com",
    "www.gitlab.com",
    "www.coindesk.com",
    "www.time.is",
    "onesignal.com",
]


@dataclass
class SNIDomainState:
    """Tracks the health state of a single SNI domain."""
    domain: str
    alive: bool = True
    last_check: float = 0.0
    latency_ms: float = 0.0
    fail_count: int = 0
    # How many consecutive successes after a failure
    recovery_count: int = 0


class SNIProvider:
    """Manages a pool of SNI domains with health checking and rotation.

    Usage::

        provider = SNIProvider()
        sni = provider.get_best()       # Returns the fastest healthy SNI
        provider.mark_failed("x.com")   # Mark a domain as blocked
        sni = provider.get_best()       # Automatically skips the failed one
    """

    def __init__(
        self,
        domains: Optional[List[str]] = None,
        check_timeout: float = 5.0,
        recheck_interval: float = 300.0,
        max_failures: int = 3,
    ):
        """
        Args:
            domains: SNI domain list.  Uses built-in defaults if ``None``.
            check_timeout: Timeout for each TLS health check (seconds).
            recheck_interval: Seconds before re-testing a failed domain.
            max_failures: Consecutive failures before a domain is skipped.
        """
        self.check_timeout = check_timeout
        self.recheck_interval = recheck_interval
        self.max_failures = max_failures

        self._states: Dict[str, SNIDomainState] = {}
        raw = domains if domains else list(DEFAULT_SNI_DOMAINS)
        for d in raw:
            self._states[d] = SNIDomainState(domain=d)

    @property
    def domains(self) -> List[str]:
        return list(self._states.keys())

    @property
    def alive_domains(self) -> List[str]:
        return [d for d, s in self._states.items() if s.alive]

    # ── Selection ─────────────────────────────────────────────────────

    def get_best(self) -> str:
        """Return the healthiest, lowest-latency SNI domain.

        Falls back to a random alive domain if none have been tested yet.
        """
        alive = [
            s for s in self._states.values()
            if s.alive and s.fail_count < self.max_failures
        ]
        if not alive:
            # Everything is marked failed -- reset and try the defaults
            logger.warning(
                "All SNI domains are marked failed.  Resetting states."
            )
            self._reset_all()
            alive = list(self._states.values())

        # Prefer domains that have been tested (latency > 0)
        tested = [s for s in alive if s.latency_ms > 0]
        if tested:
            tested.sort(key=lambda s: s.latency_ms)
            return tested[0].domain

        return random.choice(alive).domain

    def get_next(self, exclude: str = "") -> str:
        """Return the next-best SNI, excluding *exclude*."""
        alive = [
            s for s in self._states.values()
            if s.alive and s.fail_count < self.max_failures
            and s.domain != exclude
        ]
        if not alive:
            return self.get_best()

        tested = [s for s in alive if s.latency_ms > 0]
        if tested:
            tested.sort(key=lambda s: s.latency_ms)
            return tested[0].domain
        return random.choice(alive).domain

    # ── Health tracking ───────────────────────────────────────────────

    def mark_failed(self, domain: str):
        """Mark a domain as having failed a connection attempt."""
        state = self._states.get(domain)
        if state is None:
            return
        state.fail_count += 1
        state.recovery_count = 0
        if state.fail_count >= self.max_failures:
            state.alive = False
            logger.info(
                "SNI domain %r marked dead after %d failures",
                domain, state.fail_count,
            )

    def mark_success(self, domain: str, latency_ms: float = 0.0):
        """Record a successful connection through *domain*."""
        state = self._states.get(domain)
        if state is None:
            return
        state.alive = True
        state.fail_count = 0
        state.recovery_count += 1
        if latency_ms > 0:
            state.latency_ms = latency_ms
        state.last_check = time.monotonic()

    def add_domain(self, domain: str):
        """Add a new SNI domain to the pool."""
        if domain not in self._states:
            self._states[domain] = SNIDomainState(domain=domain)

    def remove_domain(self, domain: str):
        """Remove an SNI domain from the pool."""
        self._states.pop(domain, None)

    # ── Health checking ───────────────────────────────────────────────

    def check_domain(self, domain: str, target_ip: str = "",
                     port: int = 443) -> bool:
        """Perform a TLS handshake to verify the SNI is reachable.

        If *target_ip* is given, the handshake is done against that IP
        with the domain as SNI (simulating a Cloudflare CDN connection).
        Otherwise the domain is resolved normally.
        """
        host = target_ip if target_ip else domain
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.set_alpn_protocols(["h2", "http/1.1"])

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.check_timeout)
            t0 = time.monotonic()
            sock.connect((host, port))
            ssl_sock = ctx.wrap_socket(sock, server_hostname=domain)
            latency = (time.monotonic() - t0) * 1000

            ssl_sock.close()
            self.mark_success(domain, latency_ms=latency)
            return True
        except Exception:
            self.mark_failed(domain)
            return False

    def check_all(self, target_ip: str = "", port: int = 443):
        """Health-check every domain in the pool."""
        for domain in list(self._states.keys()):
            self.check_domain(domain, target_ip=target_ip, port=port)

    # ── Internal ──────────────────────────────────────────────────────

    def _reset_all(self):
        for state in self._states.values():
            state.alive = True
            state.fail_count = 0
            state.recovery_count = 0

    def status_table(self) -> str:
        """Return a human-readable status table."""
        lines = [
            f"{'Domain':<40} {'Alive':>5} {'Latency':>10} {'Fails':>5}"
        ]
        lines.append("-" * 65)
        for s in sorted(self._states.values(), key=lambda x: x.latency_ms or 9999):
            alive_str = "yes" if s.alive else "NO"
            lat_str = f"{s.latency_ms:.0f}ms" if s.latency_ms > 0 else "-"
            lines.append(
                f"{s.domain:<40} {alive_str:>5} {lat_str:>10} {s.fail_count:>5}"
            )
        return "\n".join(lines)
