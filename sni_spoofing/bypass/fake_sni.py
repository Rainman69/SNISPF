"""Fake SNI bypass strategy.

Sends a fake TLS ClientHello with an allowed SNI that DPI will parse
and whitelist, but the real server will ignore.

Two operating modes:
- With raw sockets (Linux + root): Uses the seq_id trick from the
  original tool. Injects a fake ClientHello with an out-of-window
  TCP sequence number. DPI parses it, server drops it.
- Without raw sockets (fallback): Sends the real ClientHello in
  fragments so DPI cannot read the SNI from any single packet.
  The fake_sni prefix method does NOT work without raw sockets
  because sending the fake on the same TCP stream corrupts the
  TLS handshake.
"""

import asyncio
import logging
import socket
from typing import Optional

from .base import BypassStrategy
from ..tls import ClientHelloBuilder
from ..tls.fragment import fragment_client_hello

logger = logging.getLogger("snispf")


class FakeSNIBypass(BypassStrategy):
    """Bypass DPI by injecting a fake TLS ClientHello with spoofed SNI.

    The only reliable way to do this is with raw socket injection
    (out-of-window seq trick). When raw sockets are not available,
    this falls back to TLS fragmentation which hides the SNI by
    splitting it across TCP segments.

    Methods:
    - "raw_inject" - Inject fake ClientHello with wrong seq number
      via AF_PACKET. DPI sees it, server drops it. (Linux + root)
    - "ttl_trick" - Send fake with low IP TTL. May reach DPI but
      expire before the server. Unreliable, platform-dependent.
    - "fragment_fallback" - Falls back to fragmenting the real
      ClientHello. No fake is sent on the real stream.
    """

    name = "fake_sni"

    def __init__(self, method: str = "prefix_fake", raw_injector=None):
        self.method = method
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

        # If we have a raw injector running, the fake was already injected
        # during the TCP handshake. Just send the real data and go.
        if self.raw_injector is not None:
            return await self._raw_inject_send(
                server_sock, first_data, loop
            )

        # Without raw sockets, the old "prefix_fake" method of sending
        # a fake ClientHello on the same TCP stream is broken - the server
        # receives both and the TLS handshake fails. Fall back to
        # TTL trick if requested, otherwise just fragment the real hello.
        if self.method == "ttl_trick":
            return await self._ttl_trick(
                server_sock, fake_sni, first_data, loop
            )
        else:
            # Fragment fallback: split the real ClientHello so DPI can't
            # read the SNI from any single packet.
            return await self._fragment_fallback(
                server_sock, first_data, loop
            )

    async def _raw_inject_send(
        self,
        server_sock: socket.socket,
        first_data: bytes,
        loop,
    ) -> bool:
        """With raw injection, the fake was already sent out-of-window.
        Just send the real ClientHello normally."""
        try:
            local_port = server_sock.getsockname()[1]

            # Wait for the sniffer to confirm the server ignored the fake.
            confirmed = await loop.run_in_executor(
                None,
                self.raw_injector.wait_for_confirmation,
                local_port,
                2.0,
            )

            if not confirmed:
                logger.warning(
                    f"port={local_port}: server did not confirm fake was "
                    f"ignored (timeout). Sending real data anyway."
                )

            # Send the real ClientHello (untouched)
            await loop.sock_sendall(server_sock, first_data)
            return True

        except Exception:
            return False

    async def _ttl_trick(
        self,
        server_sock: socket.socket,
        fake_sni: str,
        first_data: bytes,
        loop,
    ) -> bool:
        """Send fake ClientHello with low TTL, then real data normally.

        The fake packet has a TTL low enough to expire before reaching
        the server, but the DPI middlebox (typically 1-3 hops away)
        will see it. This is unreliable depending on network topology.
        """
        try:
            server_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

            fake_hello = ClientHelloBuilder.build_client_hello(sni=fake_sni)

            # Save original TTL
            original_ttl = server_sock.getsockopt(
                socket.IPPROTO_IP, socket.IP_TTL
            )

            # Low TTL: reaches DPI (1-5 hops) but expires before server
            server_sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, 3)

            try:
                await loop.sock_sendall(server_sock, fake_hello)
            except OSError:
                pass  # May get ICMP TTL exceeded

            await asyncio.sleep(0.05)

            # Restore normal TTL
            server_sock.setsockopt(
                socket.IPPROTO_IP, socket.IP_TTL, original_ttl
            )

            # Send real ClientHello normally
            await loop.sock_sendall(server_sock, first_data)

            server_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 0)
            return True

        except Exception:
            return False

    async def _fragment_fallback(
        self,
        server_sock: socket.socket,
        first_data: bytes,
        loop,
    ) -> bool:
        """Fallback: fragment the real ClientHello at the SNI boundary.

        Without raw sockets we cannot safely send a fake ClientHello
        (it would corrupt the TLS stream). Instead, fragment the real
        ClientHello so DPI cannot read the full SNI from a single packet.
        """
        try:
            server_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

            fragments = fragment_client_hello(first_data, "sni_split")

            for i, fragment in enumerate(fragments):
                await loop.sock_sendall(server_sock, fragment)
                if i < len(fragments) - 1:
                    await asyncio.sleep(0.1)

            server_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 0)
            return True

        except Exception:
            return False
