"""Low-level probing routines for a single IP.

Each probe performs up to three stages:
1. **TCP connect** -- measures raw TCP handshake latency.
2. **TLS handshake** -- performs a real TLS 1.2/1.3 handshake with a
   given SNI and records the time.  A successful handshake proves the
   IP is not RST-blocked for that SNI.
3. **Download speed** (optional) -- fetches a small payload over HTTPS
   and measures throughput.

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


@dataclass
class ProbeResult:
    """Result of probing a single IP address."""

    ip: str
    port: int = 443
    sni: str = ""

    # Stage results
    tcp_ms: float = -1.0         # TCP connect latency in ms
    tls_ms: float = -1.0         # TLS handshake latency in ms
    download_ms: float = -1.0    # Download time in ms
    download_speed: float = 0.0  # Bytes per second

    # Status
    tcp_ok: bool = False
    tls_ok: bool = False
    download_ok: bool = False
    tls_version: str = ""
    error: str = ""

    @property
    def alive(self) -> bool:
        """IP passed at least TCP + TLS stages."""
        return self.tcp_ok and self.tls_ok

    @property
    def score(self) -> float:
        """Lower is better.  Combines latency and penalises failures."""
        if not self.alive:
            return float("inf")
        s = self.tcp_ms + self.tls_ms
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

        # Stage 2: TLS handshake
        ssl_sock = self._tls_handshake(sock, ip, port, sni, result)
        if ssl_sock is None:
            return result

        # Stage 3: Optional download speed test
        if self.test_download:
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
        """Perform a real TLS handshake with the given SNI."""
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

    def _download_test(
        self, ssl_sock: ssl.SSLSocket, host: str, result: ProbeResult
    ):
        """Issue a small HTTP GET and measure throughput."""
        try:
            req = (
                f"GET {self.download_url} HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                f"User-Agent: SNISPF\r\n"
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
                result.download_speed = total / elapsed
                result.download_ok = True
        except Exception:
            result.download_ok = False
