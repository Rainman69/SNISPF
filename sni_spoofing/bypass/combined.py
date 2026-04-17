"""Combined bypass strategy.

Combines multiple bypass techniques for maximum effectiveness.

With raw sockets (Linux + root):
  1. The raw injector sends a fake ClientHello with an out-of-window
     seq number during the TCP handshake (DPI parses it, server drops it)
  2. Then the real ClientHello is fragmented at the SNI boundary
  Both techniques hit DPI at once.

Without raw sockets (fallback):
  Uses fragmentation only (with optional TTL trick for the fake).
  The fake_sni prefix method is NOT used on the real TCP stream
  because it corrupts the TLS handshake.
"""

import asyncio
import logging
import socket
import time
from typing import Optional

from .base import BypassStrategy
from ..tls import ClientHelloBuilder
from ..tls.fragment import fragment_client_hello, fragment_data

logger = logging.getLogger("snispf")


class CombinedBypass(BypassStrategy):
    """Combined DPI bypass using multiple techniques simultaneously.

    With raw injector available:
      1. Fake ClientHello injected out-of-window (by the sniffer/injector)
      2. Real ClientHello fragmented at SNI boundary
      3. Small inter-fragment delays

    Without raw injector:
      1. (Optional) TTL trick to send fake ClientHello that expires
         before reaching the server
      2. Real ClientHello fragmented at SNI boundary
      3. Small inter-fragment delays
    """

    name = "combined"

    def __init__(
        self,
        fragment_strategy: str = "sni_split",
        use_ttl_trick: bool = False,
        fragment_delay: float = 0.1,
        fake_first: bool = True,
        raw_injector=None,
    ):
        self.fragment_strategy = fragment_strategy
        self.use_ttl_trick = use_ttl_trick
        self.fragment_delay = fragment_delay
        self.fake_first = fake_first
        self.raw_injector = raw_injector

    async def apply(
        self,
        client_sock: socket.socket,
        server_sock: socket.socket,
        fake_sni: str,
        first_data: bytes,
        loop=None,
    ) -> bool:
        if loop is None:
            loop = asyncio.get_running_loop()

        try:
            server_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

            # Step 1: Handle fake ClientHello
            if self.raw_injector is not None:
                # Raw injector already sent the fake out-of-window during
                # the TCP handshake. Wait for server confirmation.
                local_port = server_sock.getsockname()[1]
                confirmed = await loop.run_in_executor(
                    None,
                    self.raw_injector.wait_for_confirmation,
                    local_port,
                    2.0,
                )
                if not confirmed:
                    logger.warning(
                        f"port={local_port}: no confirmation that server "
                        f"ignored the fake packet (timeout)"
                    )

            elif self.fake_first and self.use_ttl_trick:
                # TTL trick: send fake with low TTL so it reaches DPI
                # but expires before the server.  This is the default
                # fallback on macOS, Android/Termux, and unprivileged
                # Linux where AF_PACKET raw sockets are not available.
                fake_hello = ClientHelloBuilder.build_client_hello(sni=fake_sni)
                try:
                    original_ttl = server_sock.getsockopt(
                        socket.IPPROTO_IP, socket.IP_TTL
                    )
                    # Try multiple TTL values for wider DPI coverage
                    for ttl in (3, 5, 8):
                        try:
                            server_sock.setsockopt(
                                socket.IPPROTO_IP, socket.IP_TTL, ttl
                            )
                            await loop.sock_sendall(server_sock, fake_hello)
                            break
                        except OSError:
                            continue
                    await asyncio.sleep(0.05)
                    server_sock.setsockopt(
                        socket.IPPROTO_IP, socket.IP_TTL, original_ttl
                    )
                except OSError:
                    # TTL trick not available on this socket, skip
                    pass

                await asyncio.sleep(0.001)

            # NOTE: Without raw sockets or TTL trick, we do NOT send a fake
            # ClientHello on the real TCP stream. It would corrupt the
            # handshake because the server receives it as real data.

            # Step 2: Fragment and send the real ClientHello
            fragments = fragment_client_hello(first_data, self.fragment_strategy)

            for i, fragment in enumerate(fragments):
                await loop.sock_sendall(server_sock, fragment)
                if i < len(fragments) - 1 and self.fragment_delay > 0:
                    await asyncio.sleep(self.fragment_delay)

            server_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 0)
            return True

        except Exception:
            return False
