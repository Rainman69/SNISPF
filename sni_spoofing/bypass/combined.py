"""Combined bypass strategy.

Combines multiple bypass techniques for maximum effectiveness.
This is the recommended default strategy.
"""

import asyncio
import os
import socket
import time
from typing import Optional

from .base import BypassStrategy
from ..tls import ClientHelloBuilder
from ..tls.fragment import fragment_client_hello, fragment_data


class CombinedBypass(BypassStrategy):
    """Combined DPI bypass using multiple techniques simultaneously.

    This strategy chains:
    1. TLS ClientHello with fake SNI (sent first, with optional TTL trick)
    2. Real ClientHello fragmented at the SNI boundary
    3. Small inter-fragment delays

    This is the most effective approach as it targets multiple types
    of DPI implementations simultaneously.
    """

    name = "combined"

    def __init__(
        self,
        fragment_strategy: str = "sni_split",
        use_ttl_trick: bool = False,
        fragment_delay: float = 0.1,
        fake_first: bool = True,
    ):
        """Initialize combined bypass.

        Args:
            fragment_strategy: How to fragment the real ClientHello
            use_ttl_trick: Whether to use TTL trick for fake packets
            fragment_delay: Delay between fragments
            fake_first: Whether to send fake ClientHello before real one
        """
        self.fragment_strategy = fragment_strategy
        self.use_ttl_trick = use_ttl_trick
        self.fragment_delay = fragment_delay
        self.fake_first = fake_first

    async def apply(
        self,
        client_sock: socket.socket,
        server_sock: socket.socket,
        fake_sni: str,
        first_data: bytes,
        loop=None,
    ) -> bool:
        """Apply combined bypass strategy."""
        if loop is None:
            loop = asyncio.get_running_loop()

        try:
            # Enable TCP_NODELAY for precise segment control
            server_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

            if self.fake_first:
                # Step 1: Send fake ClientHello with allowed SNI
                fake_hello = ClientHelloBuilder.build_client_hello(sni=fake_sni)

                if self.use_ttl_trick:
                    try:
                        original_ttl = server_sock.getsockopt(
                            socket.IPPROTO_IP, socket.IP_TTL
                        )
                        server_sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, 3)
                        await loop.sock_sendall(server_sock, fake_hello)
                        await asyncio.sleep(0.05)
                        server_sock.setsockopt(
                            socket.IPPROTO_IP, socket.IP_TTL, original_ttl
                        )
                    except OSError:
                        # TTL trick not available, send normally
                        await loop.sock_sendall(server_sock, fake_hello)
                else:
                    await loop.sock_sendall(server_sock, fake_hello)

                await asyncio.sleep(0.001)

            # Step 2: Fragment and send the real ClientHello
            fragments = fragment_client_hello(first_data, self.fragment_strategy)

            for i, fragment in enumerate(fragments):
                await loop.sock_sendall(server_sock, fragment)
                if i < len(fragments) - 1 and self.fragment_delay > 0:
                    await asyncio.sleep(self.fragment_delay)

            # Restore TCP_NODELAY
            server_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 0)

            return True

        except Exception:
            return False
