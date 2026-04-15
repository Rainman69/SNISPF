"""Low-level probing routines for a single IP.

Each probe performs up to four stages:
1. **TCP connect** -- measures raw TCP handshake latency.
2. **TLS handshake** -- performs a real TLS 1.2/1.3 handshake with a
   given SNI and records the time.  Also checks that the TLS
   certificate is issued by a legitimate Cloudflare-associated CA
   (not a MITM/censorship proxy certificate).
3. **HTTP validation** -- sends a small HTTP request to /cdn-cgi/trace
   and verifies the response contains Cloudflare markers.  This
   catches cases where DPI allows the handshake but injects a block
   page, or a transparent MITM proxy terminates TLS.
4. **Download speed** (optional) -- measures throughput using the
   validated /cdn-cgi/trace response.

All stages use non-blocking sockets with strict timeouts so that
blocked / unresponsive IPs fail fast.
"""

import logging
import socket
import ssl
import struct
import time
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger("snispf")


# Known legitimate TLS certificate issuers for Cloudflare.
# If a MITM proxy intercepts TLS, its certificate issuer will NOT match
# any of these, which lets us detect transparent interception.
CLOUDFLARE_CERT_ISSUERS = [
    "cloudflare",
    "digicert",
    "google trust services",
    "globalsign",
    "baltimore cybertrust",
    "comodo",
    "sectigo",
    "usertrust",
    "letsencrypt",
    "let's encrypt",
    "isrg",
    "e1",  # Cloudflare's short issuer CN
    "e5",
    "e6",
    "r3",
    "r4",
    "r10",
    "r11",
]

# Markers expected in a genuine Cloudflare /cdn-cgi/trace response.
# A censorship block page or MITM proxy response will NOT contain these.
CLOUDFLARE_TRACE_MARKERS = ["fl=", "h=", "colo="]


@dataclass
class ProbeResult:
    """Result of probing a single IP address."""

    ip: str
    port: int = 443
    sni: str = ""

    # Stage results
    tcp_ms: float = -1.0         # TCP connect latency in ms
    tls_ms: float = -1.0         # TLS handshake latency in ms
    http_ms: float = -1.0        # HTTP validation latency in ms
    download_ms: float = -1.0    # Download time in ms
    download_speed: float = 0.0  # Bytes per second

    # Status
    tcp_ok: bool = False
    tls_ok: bool = False
    http_ok: bool = False         # True only if HTTP response is verified Cloudflare
    download_ok: bool = False
    tls_version: str = ""
    tls_issuer: str = ""          # Certificate issuer for MITM detection
    error: str = ""

    @property
    def alive(self) -> bool:
        """IP is alive only if TCP + TLS + HTTP validation all pass.

        Changed from v1.3.0: Previously only checked TCP + TLS.
        A TLS handshake alone does NOT prove the connection is usable:
        - DPI may allow the handshake but inject a block page
        - A transparent MITM proxy may terminate TLS with its own cert
        - The censorship system may RST after application data is sent

        By requiring HTTP validation (/cdn-cgi/trace with Cloudflare
        markers), we ensure the connection actually reaches Cloudflare
        and is not intercepted.
        """
        return self.tcp_ok and self.tls_ok and self.http_ok

    @property
    def score(self) -> float:
        """Lower is better.  Combines latency and penalises failures."""
        if not self.alive:
            return float("inf")
        s = self.tcp_ms + self.tls_ms
        # Include HTTP validation time in score
        if self.http_ms > 0:
            s += self.http_ms * 0.5  # Weight HTTP latency less than handshake
        if self.download_ok and self.download_speed > 0:
            # Reward faster downloads (inverse, scaled to ms-like range)
            s -= min(self.download_speed / 5000.0, 200.0)
        return s

    def summary(self) -> str:
        parts = [self.ip]
        if self.tcp_ok:
            parts.append(f"tcp={self.tcp_ms:.0f}ms")
        if self.tls_ok:
            parts.append(f"tls={self.tls_ms:.0f}ms")
        if self.http_ok:
            parts.append(f"http={self.http_ms:.0f}ms")
        if self.download_ok:
            speed_kb = self.download_speed / 1024
            parts.append(f"dl={speed_kb:.1f}KB/s")
        if not self.alive:
            parts.append(f"FAIL({self.error})")
        return " | ".join(parts)


class IPProbe:
    """Probes a single IP for reachability and performance.

    Usage::

        probe = IPProbe(timeout=3.0, test_download=True)
        result = probe.check("104.16.132.229", 443, "auth.vercel.com")
        if result.alive:
            print(result.summary())
    """

    def __init__(
        self,
        timeout: float = 4.0,
        test_download: bool = False,
        download_url: str = "/cdn-cgi/trace",
        download_size: int = 2048,
    ):
        self.timeout = timeout
        self.test_download = test_download
        self.download_url = download_url
        self.download_size = download_size

    def check(self, ip: str, port: int = 443, sni: str = "") -> ProbeResult:
        """Run all probe stages against *ip*:*port*."""
        result = ProbeResult(ip=ip, port=port, sni=sni)

        # Stage 1: TCP connect
        sock = self._tcp_connect(ip, port, result)
        if sock is None:
            return result

        # Stage 2: TLS handshake + certificate check
        ssl_sock = self._tls_handshake(sock, ip, port, sni, result)
        if ssl_sock is None:
            return result

        # Stage 3: HTTP validation (always, not just in download mode)
        # This is CRITICAL: a successful TLS handshake does NOT prove
        # the connection is actually working.  DPI may allow the
        # handshake but inject a block page, or a MITM proxy may
        # terminate TLS with its own certificate.
        self._http_validate(ssl_sock, sni or ip, result)

        # Stage 4: Optional detailed download speed test
        # (only if HTTP validation passed and download mode is on)
        if self.test_download and result.http_ok:
            self._download_test(ssl_sock, sni or ip, result)

        try:
            ssl_sock.close()
        except Exception:
            pass

        return result

    # ── Internal stages ───────────────────────────────────────────────

    def _tcp_connect(
        self, ip: str, port: int, result: ProbeResult
    ) -> Optional[socket.socket]:
        """Raw TCP SYN/ACK handshake."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        try:
            t0 = time.monotonic()
            sock.connect((ip, port))
            result.tcp_ms = (time.monotonic() - t0) * 1000
            result.tcp_ok = True
            return sock
        except (socket.timeout, TimeoutError):
            result.error = "tcp_timeout"
        except ConnectionRefusedError:
            result.error = "tcp_refused"
        except OSError as exc:
            result.error = f"tcp_{exc.errno}"
        try:
            sock.close()
        except Exception:
            pass
        return None

    def _tls_handshake(
        self,
        sock: socket.socket,
        ip: str,
        port: int,
        sni: str,
        result: ProbeResult,
    ) -> Optional[ssl.SSLSocket]:
        """Perform a real TLS handshake with the given SNI.

        Also checks the server certificate issuer against known Cloudflare
        CA issuers.  A MITM/censorship proxy will present its own cert
        with a different issuer, which we detect and flag.
        """
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.set_alpn_protocols(["h2", "http/1.1"])
        # Allow both TLS 1.2 and 1.3
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2

        server_hostname = sni if sni else ip
        try:
            t0 = time.monotonic()
            ssl_sock = ctx.wrap_socket(sock, server_hostname=server_hostname)
            result.tls_ms = (time.monotonic() - t0) * 1000
            result.tls_ok = True
            result.tls_version = ssl_sock.version() or ""

            # Check certificate issuer for MITM detection
            try:
                cert = ssl_sock.getpeercert(binary_form=True)
                if cert:
                    issuer_str = self._extract_cert_issuer(cert)
                    result.tls_issuer = issuer_str
                    if issuer_str and not self._is_legitimate_issuer(issuer_str):
                        # Certificate is from an unknown issuer --
                        # likely a MITM/censorship proxy
                        result.tls_ok = False
                        result.error = "tls_mitm_cert"
                        logger.debug(
                            "MITM detected for %s: issuer=%r",
                            ip, issuer_str,
                        )
                        try:
                            ssl_sock.close()
                        except Exception:
                            pass
                        return None
            except Exception:
                # If we can't check the cert, continue anyway --
                # the HTTP validation stage will catch MITM.
                pass

            return ssl_sock
        except ssl.SSLError as exc:
            result.error = f"tls_{exc.reason}"
        except (socket.timeout, TimeoutError):
            result.error = "tls_timeout"
        except ConnectionResetError:
            result.error = "tls_reset"
        except OSError as exc:
            result.error = f"tls_{exc.errno}"
        try:
            sock.close()
        except Exception:
            pass
        return None

    @staticmethod
    def _extract_cert_issuer(cert_der: bytes) -> str:
        """Extract issuer organization from a DER-encoded certificate.

        Uses a simple scan for common OID patterns to avoid requiring
        an external ASN.1 library.  Returns a lowercase string of the
        issuer fields found, or empty string on failure.
        """
        try:
            # OID 2.5.4.10 = Organization (06 03 55 04 0a)
            # OID 2.5.4.3  = CommonName  (06 03 55 04 03)
            parts = []
            for oid_bytes in [b"\x06\x03\x55\x04\x0a", b"\x06\x03\x55\x04\x03"]:
                idx = 0
                while True:
                    idx = cert_der.find(oid_bytes, idx)
                    if idx < 0:
                        break
                    # The value follows: tag + length + string
                    val_start = idx + len(oid_bytes)
                    if val_start + 2 > len(cert_der):
                        break
                    val_tag = cert_der[val_start]
                    val_len = cert_der[val_start + 1]
                    if val_tag in (0x0c, 0x13, 0x16) and val_len > 0:  # UTF8, PrintableString, IA5
                        val = cert_der[val_start + 2 : val_start + 2 + val_len]
                        try:
                            parts.append(val.decode("utf-8", errors="replace"))
                        except Exception:
                            pass
                    idx = val_start + 2
            return " ".join(parts).lower().strip()
        except Exception:
            return ""

    @staticmethod
    def _is_legitimate_issuer(issuer: str) -> bool:
        """Check if the certificate issuer matches a known Cloudflare CA."""
        issuer_lower = issuer.lower()
        return any(known in issuer_lower for known in CLOUDFLARE_CERT_ISSUERS)

    def _http_validate(
        self, ssl_sock: ssl.SSLSocket, host: str, result: ProbeResult
    ):
        """Send a lightweight HTTP request and verify the response is from Cloudflare.

        This is the critical check that prevents false positives:
        - A censorship block page will NOT contain Cloudflare trace markers
        - A MITM proxy response will NOT match the expected format
        - A connection that gets RST after data is sent will fail here

        The /cdn-cgi/trace endpoint is a lightweight Cloudflare debug page
        that returns plaintext with fields like fl=, h=, colo=, etc.
        It exists on every Cloudflare IP and does not depend on the
        specific domain being hosted.
        """
        try:
            req = (
                f"GET /cdn-cgi/trace HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                f"User-Agent: Mozilla/5.0\r\n"
                f"Accept: */*\r\n"
                f"Connection: keep-alive\r\n\r\n"
            ).encode()
            ssl_sock.settimeout(self.timeout)

            t0 = time.monotonic()
            ssl_sock.sendall(req)

            # Read the response (should be small, < 2KB)
            chunks = []
            total = 0
            while total < 4096:
                try:
                    chunk = ssl_sock.recv(4096)
                    if not chunk:
                        break
                    chunks.append(chunk)
                    total += len(chunk)
                    # Check if we've received a complete HTTP response
                    data = b"".join(chunks)
                    if b"\r\n\r\n" in data and total > 50:
                        # Look for the end of the body
                        body_start = data.find(b"\r\n\r\n") + 4
                        if body_start < len(data):
                            break
                except (socket.timeout, TimeoutError):
                    break

            elapsed = time.monotonic() - t0
            result.http_ms = elapsed * 1000

            if not chunks:
                result.error = "http_no_response"
                return

            response = b"".join(chunks)
            response_text = response.decode("utf-8", errors="replace")

            # Check HTTP status -- must be 200
            first_line = response_text.split("\r\n", 1)[0]
            if "200" not in first_line:
                result.error = "http_not_200"
                return

            # Extract body (after headers)
            body = ""
            if "\r\n\r\n" in response_text:
                body = response_text.split("\r\n\r\n", 1)[1]

            # Verify Cloudflare trace markers
            # A genuine Cloudflare response contains: fl=, h=, colo=
            markers_found = sum(
                1 for marker in CLOUDFLARE_TRACE_MARKERS
                if marker in body
            )

            if markers_found >= 2:
                # At least 2 of 3 markers found -- genuine Cloudflare
                result.http_ok = True
            else:
                # Response doesn't look like Cloudflare --
                # likely a block page or MITM response
                result.error = "http_not_cloudflare"
                logger.debug(
                    "HTTP validation failed for %s: body does not contain "
                    "Cloudflare markers (found %d/%d)",
                    result.ip, markers_found, len(CLOUDFLARE_TRACE_MARKERS),
                )
        except ConnectionResetError:
            result.error = "http_reset"
        except (socket.timeout, TimeoutError):
            result.error = "http_timeout"
        except Exception:
            result.error = "http_error"

    def _download_test(
        self, ssl_sock: ssl.SSLSocket, host: str, result: ProbeResult
    ):
        """Issue a second HTTP GET and measure throughput.

        Only called when HTTP validation has already passed, so we know
        the connection is genuinely reaching Cloudflare.
        """
        try:
            req = (
                f"GET {self.download_url} HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                f"User-Agent: Mozilla/5.0\r\n"
                f"Connection: close\r\n\r\n"
            ).encode()
            ssl_sock.settimeout(self.timeout)

            t0 = time.monotonic()
            ssl_sock.sendall(req)

            chunks = []
            total = 0
            while total < self.download_size:
                chunk = ssl_sock.recv(4096)
                if not chunk:
                    break
                chunks.append(chunk)
                total += len(chunk)

            elapsed = time.monotonic() - t0
            result.download_ms = elapsed * 1000
            if elapsed > 0 and total > 0:
                # Validate the download response too
                response = b"".join(chunks)
                body = response.decode("utf-8", errors="replace")
                if any(marker in body for marker in CLOUDFLARE_TRACE_MARKERS):
                    result.download_speed = total / elapsed
                    result.download_ok = True
                else:
                    # Download response doesn't look like Cloudflare
                    result.download_ok = False
        except Exception:
            result.download_ok = False
