"""Cloudflare clean IP scanner and SNI provider.

This module provides:
- Cloudflare IP range management and random IP selection
- Pre-resolved seed IPs for DNS-poisoned networks (e.g. Iran)
- TCP connect, TLS handshake, and download speed testing
- Automatic best-IP discovery with latency/speed ranking
- SNI domain list management and rotation
- Real-time failover when an IP becomes blocked
"""

from .ip_ranges import CloudflareIPPool, CLOUDFLARE_SEED_IPS
from .probe import IPProbe, ProbeResult
from .engine import ScanEngine, ScanConfig
from .sni_provider import SNIProvider

__all__ = [
    "CloudflareIPPool",
    "CLOUDFLARE_SEED_IPS",
    "IPProbe",
    "ProbeResult",
    "ScanEngine",
    "ScanConfig",
    "SNIProvider",
]
