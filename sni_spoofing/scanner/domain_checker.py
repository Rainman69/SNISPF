"""Bulk SNI domain checker and verifier.

Checks a list of domains to determine which ones are behind Cloudflare's
CDN and suitable for use as SNI spoof targets. Performs DNS resolution,
ASN lookup, TLS handshake, and HTTP validation to verify each domain.

Inspired by community scanner tools that identify Cloudflare-fronted
domains for censorship bypass. The goal is to maintain a large,
verified list of domains that can be used as fake SNI values when
connecting through Cloudflare IPs.

Usage (standalone)::

    checker = DomainChecker(concurrency=50, timeout=3.0)
    results = checker.check_domains(["example.com", "test.org"])
    for r in results:
        if r.is_cloudflare:
            print(f"{r.domain} -> {r.ip} (CF)")

Usage (from CLI)::

    snispf --check-domains domains.txt
    snispf --check-domains domains.txt --output verified.txt
"""

import asyncio
import concurrent.futures
import ipaddress
import logging
import socket
import ssl
import time
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Set

from .ip_ranges import CLOUDFLARE_IPV4_RANGES

logger = logging.getLogger("snispf")

# Known Cloudflare ASN numbers
CLOUDFLARE_ASNS = {13335, 209242}

# Cloudflare IP networks (parsed once for fast lookups)
_CF_NETWORKS = None


def _get_cf_networks():
    """Lazily parse Cloudflare CIDR ranges into network objects."""
    global _CF_NETWORKS
    if _CF_NETWORKS is None:
        _CF_NETWORKS = []
        for cidr in CLOUDFLARE_IPV4_RANGES:
            try:
                _CF_NETWORKS.append(ipaddress.IPv4Network(cidr, strict=False))
            except (ipaddress.AddressValueError, ValueError):
                pass
    return _CF_NETWORKS


def is_cloudflare_ip(ip: str) -> bool:
    """Check whether an IP belongs to a known Cloudflare range.

    This is the primary detection method -- it doesn't require any
    external databases or network requests.  The IP ranges are from
    Cloudflare's official published list.
    """
    try:
        addr = ipaddress.IPv4Address(ip)
    except (ipaddress.AddressValueError, ValueError):
        return False
    return any(addr in net for net in _get_cf_networks())


@dataclass
class DomainResult:
    """Result of checking a single domain."""

    domain: str
    ip: str = ""
    is_cloudflare: bool = False
    tcp_ok: bool = False
    tls_ok: bool = False
    http_ok: bool = False
    http_status: int = 0
    tls_ms: float = 0.0
    error: str = ""

    @property
    def usable_as_sni(self) -> bool:
        """Domain is usable as a fake SNI for Cloudflare IP spoofing.

        Must be:
        1. Resolved to a Cloudflare IP (so TLS handshake works through CF)
        2. TCP port 443 reachable
        3. TLS handshake succeeds
        """
        return self.is_cloudflare and self.tcp_ok and self.tls_ok

    def summary(self) -> str:
        parts = [self.domain]
        if self.ip:
            parts.append(self.ip)
        if self.is_cloudflare:
            parts.append("CF")
        parts.append("TCP:OK" if self.tcp_ok else "TCP:FAIL")
        parts.append("TLS:OK" if self.tls_ok else "TLS:FAIL")
        if self.http_ok:
            parts.append(f"HTTP:{self.http_status}")
        if self.error:
            parts.append(f"ERR:{self.error}")
        return " | ".join(parts)


class DomainChecker:
    """Bulk domain checker for Cloudflare CDN detection.

    Resolves domains, checks if they're behind Cloudflare, and
    verifies TLS connectivity. Results can be filtered to produce
    a verified list of domains suitable for SNI spoofing.
    """

    def __init__(
        self,
        concurrency: int = 50,
        timeout: float = 3.0,
        verify_tls: bool = True,
        verify_http: bool = False,
    ):
        """
        Args:
            concurrency: Maximum parallel checks.
            timeout: Per-check timeout in seconds.
            verify_tls: Also perform TLS handshake (not just DNS+IP check).
            verify_http: Also perform HTTP request for deeper validation.
        """
        self.concurrency = concurrency
        self.timeout = timeout
        self.verify_tls = verify_tls
        self.verify_http = verify_http

    def check_domains(
        self,
        domains: List[str],
        progress_cb: Optional[Callable] = None,
    ) -> List[DomainResult]:
        """Check a list of domains in parallel.

        Returns results sorted with Cloudflare-backed domains first,
        then by TLS latency.
        """
        results: List[DomainResult] = []
        done_count = 0
        total = len(domains)

        logger.info(
            "Checking %d domains (workers=%d, timeout=%.1fs, tls=%s, http=%s)",
            total, self.concurrency, self.timeout,
            self.verify_tls, self.verify_http,
        )

        t_start = time.monotonic()

        with concurrent.futures.ThreadPoolExecutor(
            max_workers=self.concurrency
        ) as executor:
            futures = {
                executor.submit(self._check_one, domain): domain
                for domain in domains
            }
            for future in concurrent.futures.as_completed(futures):
                done_count += 1
                try:
                    result = future.result()
                    results.append(result)
                except Exception as exc:
                    domain = futures[future]
                    results.append(DomainResult(
                        domain=domain, error=str(exc)
                    ))

                if progress_cb:
                    try:
                        progress_cb(done_count, total)
                    except Exception:
                        pass

        elapsed = time.monotonic() - t_start
        cf_count = sum(1 for r in results if r.is_cloudflare)
        usable_count = sum(1 for r in results if r.usable_as_sni)

        logger.info(
            "Domain check complete: %d/%d Cloudflare, %d usable (%.1fs)",
            cf_count, total, usable_count, elapsed,
        )

        # Sort: Cloudflare + usable first, then by TLS latency
        results.sort(
            key=lambda r: (
                not r.usable_as_sni,
                not r.is_cloudflare,
                r.tls_ms if r.tls_ms > 0 else 9999,
            )
        )

        return results

    def _check_one(self, domain: str) -> DomainResult:
        """Check a single domain."""
        result = DomainResult(domain=domain)

        # Step 1: DNS resolution
        try:
            ip = socket.gethostbyname(domain)
            result.ip = ip
        except (socket.gaierror, socket.herror, OSError):
            result.error = "dns_fail"
            return result

        # Step 2: Check if IP is in Cloudflare ranges
        result.is_cloudflare = is_cloudflare_ip(ip)

        # Step 3: TCP connect test
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((ip, 443))
            result.tcp_ok = True
        except (socket.timeout, TimeoutError):
            result.error = "tcp_timeout"
            try:
                sock.close()
            except Exception:
                pass
            return result
        except (ConnectionRefusedError, OSError) as exc:
            result.error = f"tcp_{getattr(exc, 'errno', 'error')}"
            try:
                sock.close()
            except Exception:
                pass
            return result

        # Step 4: TLS handshake (optional but recommended)
        if self.verify_tls:
            try:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                ctx.set_alpn_protocols(["h2", "http/1.1"])
                ctx.minimum_version = ssl.TLSVersion.TLSv1_2

                t0 = time.monotonic()
                ssl_sock = ctx.wrap_socket(sock, server_hostname=domain)
                result.tls_ms = (time.monotonic() - t0) * 1000
                result.tls_ok = True

                # Step 5: HTTP check (optional)
                if self.verify_http and result.tls_ok:
                    self._http_check(ssl_sock, domain, result)

                try:
                    ssl_sock.close()
                except Exception:
                    pass
            except ssl.SSLError as exc:
                result.error = f"tls_{exc.reason}"
                try:
                    sock.close()
                except Exception:
                    pass
            except (socket.timeout, TimeoutError):
                result.error = "tls_timeout"
                try:
                    sock.close()
                except Exception:
                    pass
            except OSError:
                result.error = "tls_error"
                try:
                    sock.close()
                except Exception:
                    pass
        else:
            try:
                sock.close()
            except Exception:
                pass

        return result

    def _http_check(
        self, ssl_sock: ssl.SSLSocket, domain: str, result: DomainResult
    ):
        """Send a lightweight HTTP request and check the status code."""
        try:
            req = (
                f"GET / HTTP/1.1\r\n"
                f"Host: {domain}\r\n"
                f"User-Agent: Mozilla/5.0\r\n"
                f"Accept: */*\r\n"
                f"Connection: close\r\n\r\n"
            ).encode()
            ssl_sock.settimeout(self.timeout)
            ssl_sock.sendall(req)

            response = b""
            while len(response) < 4096:
                try:
                    chunk = ssl_sock.recv(4096)
                    if not chunk:
                        break
                    response += chunk
                    if b"\r\n\r\n" in response:
                        break
                except (socket.timeout, TimeoutError):
                    break

            if response:
                first_line = response.decode("utf-8", errors="replace").split("\r\n", 1)[0]
                # Parse HTTP status code
                parts = first_line.split(" ", 2)
                if len(parts) >= 2:
                    try:
                        result.http_status = int(parts[1])
                        if 200 <= result.http_status < 400:
                            result.http_ok = True
                    except ValueError:
                        pass
        except Exception:
            pass

    # ── Utility methods ──────────────────────────────────────────────

    @staticmethod
    def load_domains_from_file(filepath: str) -> List[str]:
        """Load domain list from a text file (one per line).

        Supports comments (#) and empty lines.
        """
        domains = []
        with open(filepath, "r") as f:
            for line in f:
                line = line.strip()
                # Skip empty lines and comments
                if not line or line.startswith("#"):
                    continue
                # Strip protocol prefixes if present
                if line.startswith("http://"):
                    line = line[7:]
                if line.startswith("https://"):
                    line = line[8:]
                # Strip paths
                line = line.split("/")[0]
                # Strip port numbers
                line = line.split(":")[0]
                if line:
                    domains.append(line)
        return domains

    @staticmethod
    def results_table(results: List[DomainResult], cloudflare_only: bool = False) -> str:
        """Format results as a human-readable table."""
        lines = [
            f"{'#':>4}  {'Domain':<40} {'IP':<16} {'CDN':>4} "
            f"{'TCP':>4} {'TLS':>4} {'TLS ms':>7} {'Status':<6}"
        ]
        lines.append("-" * 90)

        filtered = results
        if cloudflare_only:
            filtered = [r for r in results if r.is_cloudflare]

        for i, r in enumerate(filtered, 1):
            cdn = "CF" if r.is_cloudflare else "-"
            tcp = "OK" if r.tcp_ok else "-"
            tls = "OK" if r.tls_ok else "-"
            tls_ms = f"{r.tls_ms:.0f}ms" if r.tls_ms > 0 else "-"
            status = "SNI" if r.usable_as_sni else ("CF" if r.is_cloudflare else "skip")
            lines.append(
                f"{i:>4}  {r.domain:<40} {r.ip:<16} {cdn:>4} "
                f"{tcp:>4} {tls:>4} {tls_ms:>7} {status:<6}"
            )

        return "\n".join(lines)

    @staticmethod
    def export_sni_list(
        results: List[DomainResult],
        filepath: str,
        usable_only: bool = True,
    ) -> int:
        """Export verified domains to a text file.

        Returns the number of domains written.
        """
        domains = []
        for r in results:
            if usable_only and not r.usable_as_sni:
                continue
            elif not usable_only and not r.is_cloudflare:
                continue
            domains.append(r.domain)

        with open(filepath, "w") as f:
            f.write("# Verified Cloudflare-backed SNI domains\n")
            f.write(f"# Generated by SNISPF domain checker\n")
            f.write(f"# Total: {len(domains)} domains\n\n")
            for d in domains:
                f.write(d + "\n")

        return len(domains)
