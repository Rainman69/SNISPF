"""Fragment-based DPI bypass strategy.

Splits the real TLS ClientHello into fragments so that DPI systems
that only inspect the first packet or don't reassemble TCP streams
cannot read the SNI.
"""

import asyncio
import socket
import time
from typing import Optional

from .base import BypassStrategy
from ..tls.fragment import fragment_client_hello


class FragmentBypass(BypassStrategy):
    """Bypass DPI by fragmenting the TLS ClientHello.

    This is the most compatible cross-platform bypass method.
    It works by splitting the ClientHello into multiple TCP segments,
    with the split point strategically placed in the middle of the
    SNI extension value.

    DPI systems that don't reassemble TCP streams will see an incomplete
    SNI in the first packet and won't be able to filter it.
    """

    name = "fragment"

    def __init__(
        self,
        strategy: str = "sni_split",
        fragment_delay: float = 0.1,
        tcp_nodelay: bool = True,
    ):
        """Initialize fragment bypass.

        Args:
            strategy: Fragmentation strategy (sni_split, half, multi, tls_record_frag)
            fragment_delay: Delay between fragments in seconds
            tcp_nodelay: Enable TCP_NODELAY to send fragments immediately
        """
        self.strategy = strategy
        self.fragment_delay = fragment_delay
        self.tcp_nodelay = tcp_nodelay

    async def apply(
        self,
        client_sock: socket.socket,
        server_sock: socket.socket,
        fake_sni: str,
        first_data: bytes,
        loop=None,
    ) -> bool:
        """Apply fragmentation to the first TLS record.

        The first_data from the client (usually a TLS ClientHello) is
        fragmented and sent to the server in multiple TCP segments.
        """
        if loop is None:
            loop = asyncio.get_running_loop()

        try:
            # Enable TCP_NODELAY so each send() becomes its own segment
            if self.tcp_nodelay:
                server_sock.setsockopt(
                    socket.IPPROTO_TCP, socket.TCP_NODELAY, 1
                )

            # Fragment the ClientHello
            fragments = fragment_client_hello(first_data, self.strategy)

            # Send each fragment as a separate TCP segment
            for i, fragment in enumerate(fragments):
                await loop.sock_sendall(server_sock, fragment)
                if i < len(fragments) - 1 and self.fragment_delay > 0:
                    await asyncio.sleep(self.fragment_delay)

            # Disable TCP_NODELAY after fragments are sent (optional)
            if self.tcp_nodelay:
                server_sock.setsockopt(
                    socket.IPPROTO_TCP, socket.TCP_NODELAY, 0
                )

            return True

        except Exception:
            return False
