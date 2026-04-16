"""Cloudflare clean IP scanner, SNI provider, and domain checker.

This module provides:
- Cloudflare IP range management and random IP selection
- Pre-resolved seed IPs for DNS-poisoned networks (e.g. Iran)
- TCP connect, TLS handshake, and download speed testing
- Automatic best-IP discovery with latency/speed ranking
- SNI domain list management and rotation (150+ verified domains)
- Bulk domain checker for verifying Cloudflare CDN backing
- Real-time failover when an IP becomes blocked
"""

from .ip_ranges import CloudflareIPPool, CLOUDFLARE_SEED_IPS
from .probe import IPProbe, ProbeResult
from .engine import ScanEngine, ScanConfig
from .sni_provider import SNIProvider
from .domain_checker import DomainChecker, DomainResult, is_cloudflare_ip

__all__ = [
    "CloudflareIPPool",
    "CLOUDFLARE_SEED_IPS",
    "IPProbe",
    "ProbeResult",
    "ScanEngine",
    "ScanConfig",
    "SNIProvider",
    "DomainChecker",
    "DomainResult",
    "is_cloudflare_ip",
]
