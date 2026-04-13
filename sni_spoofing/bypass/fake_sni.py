"""Fake SNI bypass strategy.

Sends a fake TLS ClientHello with an allowed SNI before or alongside
the real traffic. This is the core technique from the original patterniha tool.

Cross-platform implementation that uses application-layer tricks instead
of kernel-level packet injection (WinDivert).
"""

import asyncio
import os
import socket
import struct
import time
from typing import Optional

from .base import BypassStrategy
from ..tls import ClientHelloBuilder


class FakeSNIBypass(BypassStrategy):
    """Bypass DPI by sending a fake TLS ClientHello with spoofed SNI.

    This strategy sends a fake ClientHello containing an allowed domain
    as the SNI. There are multiple sub-methods:

    1. "prefix_fake" - Send fake ClientHello, then real ClientHello
       The fake is sent first. DPI sees the fake SNI and allows it.
       The server ignores the fake because the handshake doesn't complete.

    2. "ttl_trick" - Send fake ClientHello with low TTL
       The fake packet has a TTL too low to reach the server but
       high enough for the DPI middlebox to see it. Requires raw sockets.

    3. "wrong_seq" - Send data with invalid sequence (original tool's method)
       In userspace, we approximate this by sending the fake data over a
       separate connection attempt or by using TTL tricks.

    4. "disorder" - Send segments out of order
       Fragment the real ClientHello and send the second part first,
       then the first part with fake SNI in between.
    """

    name = "fake_sni"

    def __init__(self, method: str = "prefix_fake"):
        """Initialize fake SNI bypass.

        Args:
            method: Sub-method to use (prefix_fake, ttl_trick, disorder)
        """
        self.method = method

    async def apply(
        self,
        client_sock: socket.socket,
        server_sock: socket.socket,
        fake_sni: str,
        first_data: bytes,
        loop=None,
    ) -> bool:
        """Apply fake SNI bypass."""
        if loop is None:
            loop = asyncio.get_running_loop()

        if self.method == "prefix_fake":
            return await self._prefix_fake(server_sock, fake_sni, first_data, loop)
        elif self.method == "ttl_trick":
            return await self._ttl_trick(server_sock, fake_sni, first_data, loop)
        elif self.method == "disorder":
            return await self._disorder(server_sock, fake_sni, first_data, loop)
        else:
            return await self._prefix_fake(server_sock, fake_sni, first_data, loop)

    async def _prefix_fake(
        self,
        server_sock: socket.socket,
        fake_sni: str,
        first_data: bytes,
        loop,
    ) -> bool:
        """Send fake ClientHello before real data.

        Strategy:
        1. Build a fake ClientHello with the allowed SNI
        2. Send just the fake ClientHello header (first few bytes)
           as a partial record that the server will buffer/discard
        3. Immediately send the real ClientHello

        The DPI sees the fake SNI in the first TCP segment.
        The server sees a malformed partial record followed by a valid one.
        Most TLS servers will discard the initial garbage and process
        the valid ClientHello.
        """
        try:
            # Build fake ClientHello with the allowed fake SNI
            fake_hello = ClientHelloBuilder.build_client_hello(sni=fake_sni)

            # Enable TCP_NODELAY for precise segment control
            server_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

            # Send the real ClientHello fragmented with fake SNI lead-in
            # Strategy: send first few bytes of fake (contains SNI), then real
            # The DPI sees fake SNI, server processes the real ClientHello

            # Fragment: fake_hello[:fake_split] | real_data
            # The key insight: DPI typically only parses the FIRST ClientHello
            # in a TCP stream. We make that first one have the fake SNI.

            # Method 1: Send fake as one segment, real as next
            await loop.sock_sendall(server_sock, fake_hello)
            await asyncio.sleep(0.001)
            await loop.sock_sendall(server_sock, first_data)

            server_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 0)
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
        """Use IP TTL trick to send fake data that reaches DPI but not the server.

        This requires the ability to set IP_TTL on the socket, which is
        available on most platforms without raw sockets.

        Strategy:
        1. Set TTL to a low value (e.g., 3-5) - enough for ISP's DPI
        2. Send fake ClientHello with allowed SNI
        3. Restore TTL to normal
        4. Send real ClientHello
        """
        try:
            # Enable TCP_NODELAY
            server_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

            # Build fake ClientHello
            fake_hello = ClientHelloBuilder.build_client_hello(sni=fake_sni)

            # Save original TTL
            original_ttl = server_sock.getsockopt(socket.IPPROTO_IP, socket.IP_TTL)

            # Set low TTL - packet reaches DPI but not the destination
            # The DPI middlebox is typically 1-5 hops away
            server_sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, 3)

            # Send fake ClientHello (will be dropped before reaching server)
            try:
                await loop.sock_sendall(server_sock, fake_hello)
            except OSError:
                pass  # Expected - may get ICMP TTL exceeded

            await asyncio.sleep(0.05)

            # Restore normal TTL
            server_sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, original_ttl)

            # Send real ClientHello (will reach server normally)
            await loop.sock_sendall(server_sock, first_data)

            server_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 0)
            return True

        except Exception:
            return False

    async def _disorder(
        self,
        server_sock: socket.socket,
        fake_sni: str,
        first_data: bytes,
        loop,
    ) -> bool:
        """Send ClientHello fragments out of order with fake SNI inserted.

        Strategy:
        1. Split real ClientHello into [part1, part2]
        2. Send part2 first (doesn't contain SNI beginning)
        3. Send fake ClientHello with low TTL (reaches DPI, not server)
        4. Send part1 (server reassembles correctly)

        DPI sees: part2 (incomplete) -> fake SNI -> part1
        Server sees: part1 + part2 (reassembled in order by TCP)
        """
        try:
            server_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

            # Build fake
            fake_hello = ClientHelloBuilder.build_client_hello(sni=fake_sni)

            # Split real data
            mid = len(first_data) // 2
            part1 = first_data[:mid]
            part2 = first_data[mid:]

            # Send first part normally
            await loop.sock_sendall(server_sock, part1)
            await asyncio.sleep(0.001)

            # Try TTL trick for fake
            try:
                original_ttl = server_sock.getsockopt(socket.IPPROTO_IP, socket.IP_TTL)
                server_sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, 2)
                await loop.sock_sendall(server_sock, fake_hello)
                await asyncio.sleep(0.01)
                server_sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, original_ttl)
            except OSError:
                pass  # TTL trick not available, skip

            # Send second part
            await loop.sock_sendall(server_sock, part2)

            server_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 0)
            return True

        except Exception:
            return False
