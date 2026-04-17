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
    this falls back to the TTL trick (sending a fake ClientHello with
    low IP TTL) combined with TLS fragmentation.

    Methods:
    - "raw_inject" - Inject fake ClientHello with wrong seq number
      via AF_PACKET. DPI sees it, server drops it. (Linux + root)
    - "ttl_trick" - Send fake with low IP TTL. May reach DPI but
      expire before the server. Works on macOS, Android, Linux.
    - "fragment_fallback" - Falls back to fragmenting the real
      ClientHello. No fake is sent on the real stream.
    """

    name = "fake_sni"

    def __init__(self, method: str = "prefix_fake", raw_injector=None,
                 use_ttl_trick: bool = False):
        self.method = method
        self.raw_injector = raw_injector
        self.use_ttl_trick = use_ttl_trick

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

        # Without raw sockets, use TTL trick if enabled (auto-enabled
        # on macOS/Android/unprivileged Linux), otherwise fragment only.
        if self.method == "ttl_trick" or self.use_ttl_trick:
            return await self._ttl_trick_and_fragment(
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

    async def _ttl_trick_and_fragment(
        self,
        server_sock: socket.socket,
        fake_sni: str,
        first_data: bytes,
        loop,
    ) -> bool:
        """Send fake ClientHello via a separate socket, then real data fragmented.

        The fake ClientHello is sent through a **separate** raw TCP socket
        (not the proxied connection) with a very low IP TTL.  This ensures
        the fake reaches DPI middleboxes (typically 1-3 hops away) but
        expires before the real server, so the server never sees it and
        the real TLS handshake on the main socket stays clean.

        If the separate-socket approach fails (e.g. no permission),
        we fall back to pure fragmentation which still works well.

        This is the default fallback on macOS, Android/Termux, and
        unprivileged Linux where AF_PACKET raw sockets are not available.
        """
        try:
            server_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

            # --- Send fake on a SEPARATE socket with low TTL ---
            # This prevents corrupting the real TLS stream.
            remote_addr = server_sock.getpeername()
            fake_hello = ClientHelloBuilder.build_client_hello(sni=fake_sni)

            try:
                probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                probe.setblocking(False)
                probe.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                # Use a very low TTL so the packet dies before the server
                for ttl in (1, 2, 3):
                    try:
                        probe.setsockopt(
                            socket.IPPROTO_IP, socket.IP_TTL, ttl
                        )
                        # Non-blocking connect -- we don't care if it
                        # completes; we just want the SYN + fake data
                        # to traverse the DPI middlebox path.
                        try:
                            await asyncio.wait_for(
                                loop.sock_connect(probe, remote_addr),
                                timeout=0.3,
                            )
                            await loop.sock_sendall(probe, fake_hello)
                        except (asyncio.TimeoutError, OSError):
                            pass
                        break
                    except OSError:
                        continue
                try:
                    probe.close()
                except OSError:
                    pass
            except OSError:
                # Separate socket approach failed, that's fine
                pass

            await asyncio.sleep(0.05)

            # --- Send the real ClientHello fragmented on the main socket ---
            fragments = fragment_client_hello(first_data, "sni_split")

            for i, fragment in enumerate(fragments):
                await loop.sock_sendall(server_sock, fragment)
                if i < len(fragments) - 1:
                    await asyncio.sleep(0.1)

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
        """Legacy TTL trick: send fake with low TTL then real data normally."""
        return await self._ttl_trick_and_fragment(
            server_sock, fake_sni, first_data, loop
        )

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
