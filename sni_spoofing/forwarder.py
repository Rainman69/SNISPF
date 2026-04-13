"""Core TCP forwarder with DPI bypass.

This is the main engine that:
1. Listens for incoming TCP connections
2. Reads the first TLS ClientHello from the client
3. Applies the chosen DPI bypass strategy
4. Relays data bidirectionally between client and server

When a raw injector is available (Linux + root), it registers each
outgoing connection so the sniffer can capture the SYN/ACK handshake
and inject the fake ClientHello with an out-of-window seq number.

Uses pure userspace techniques on platforms without raw socket support.
"""

import asyncio
import logging
import socket
import sys
import traceback
from typing import Optional

from .bypass.base import BypassStrategy
from .tls import ClientHelloBuilder

logger = logging.getLogger("snispf")

# Buffer size for socket operations
BUFFER_SIZE = 65535


async def handle_connection(
    incoming_sock: socket.socket,
    incoming_addr: tuple,
    connect_ip: str,
    connect_port: int,
    fake_sni: str,
    bypass_strategy: BypassStrategy,
    interface_ip: Optional[str] = None,
    raw_injector=None,
):
    """Handle a single incoming connection.

    Flow:
    1. Read first data from client (should be TLS ClientHello)
    2. Create outgoing socket, optionally register with raw injector
    3. Connect to target server (3-way handshake happens here;
       the raw injector captures SYN and injects after 3rd ACK)
    4. Apply the bypass strategy (sends real data, waits for inject confirmation)
    5. Relay data bidirectionally
    """
    loop = asyncio.get_running_loop()
    outgoing_sock = None
    local_port = None

    try:
        # Read the first data from client (should be TLS ClientHello)
        first_data = await asyncio.wait_for(
            loop.sock_recv(incoming_sock, BUFFER_SIZE),
            timeout=30.0,
        )

        if not first_data:
            incoming_sock.close()
            return

        # Parse to see if it's a TLS ClientHello
        parsed = ClientHelloBuilder.parse_client_hello(first_data)
        client_sni = parsed.get("sni", "unknown")
        logger.info(
            f"[{incoming_addr[0]}:{incoming_addr[1]}] -> "
            f"{connect_ip}:{connect_port} | SNI: {client_sni} | "
            f"Bypass: {bypass_strategy.name}"
        )

        # Create outgoing socket
        outgoing_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        outgoing_sock.setblocking(False)

        # Bind to specific interface if configured
        if interface_ip:
            outgoing_sock.bind((interface_ip, 0))

        # Set keepalive
        outgoing_sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        try:
            outgoing_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 60)
            outgoing_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 10)
            outgoing_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 5)
        except (AttributeError, OSError):
            pass  # Not available on all platforms

        # If raw injector is available, register the outgoing port
        # BEFORE connecting so the sniffer can see the SYN.
        if raw_injector is not None:
            # We need to bind first to know the local port
            if not interface_ip:
                outgoing_sock.bind(("", 0))
            local_port = outgoing_sock.getsockname()[1]
            fake_hello = ClientHelloBuilder.build_client_hello(sni=fake_sni)
            raw_injector.register_port(local_port, fake_hello)

        # Connect to target server (triggers SYN -> SYN+ACK -> ACK)
        await asyncio.wait_for(
            loop.sock_connect(outgoing_sock, (connect_ip, connect_port)),
            timeout=30.0,
        )

        # If we didn't know the port before, grab it now
        if local_port is None and raw_injector is not None:
            local_port = outgoing_sock.getsockname()[1]

        # Apply DPI bypass strategy
        # The strategy handles:
        # - Waiting for raw injection confirmation (if available)
        # - Sending the real ClientHello (fragmented or not)
        success = await bypass_strategy.apply(
            client_sock=incoming_sock,
            server_sock=outgoing_sock,
            fake_sni=fake_sni,
            first_data=first_data,
            loop=loop,
        )

        if not success:
            logger.warning(
                f"[{incoming_addr[0]}:{incoming_addr[1]}] "
                f"Bypass strategy '{bypass_strategy.name}' failed, "
                f"falling back to direct relay"
            )
            # Fallback: just send the data directly
            await loop.sock_sendall(outgoing_sock, first_data)

        # Bidirectional relay
        done = asyncio.Event()

        async def _relay(s_in, s_out, label):
            try:
                while True:
                    data = await loop.sock_recv(s_in, BUFFER_SIZE)
                    if not data:
                        break
                    await loop.sock_sendall(s_out, data)
            except (ConnectionResetError, BrokenPipeError, OSError):
                pass
            except Exception:
                logger.debug(f"Relay error ({label}): {traceback.format_exc()}")
            finally:
                done.set()

        c2s_task = loop.create_task(_relay(incoming_sock, outgoing_sock, "C->S"))
        s2c_task = loop.create_task(_relay(outgoing_sock, incoming_sock, "S->C"))

        # Wait until one direction closes, then cancel the other
        await done.wait()
        c2s_task.cancel()
        s2c_task.cancel()
        await asyncio.gather(c2s_task, s2c_task, return_exceptions=True)

    except asyncio.TimeoutError:
        logger.debug(f"[{incoming_addr[0]}:{incoming_addr[1]}] Connection timeout")
    except Exception:
        logger.debug(f"Connection handler error: {traceback.format_exc()}")
    finally:
        try:
            incoming_sock.close()
        except Exception:
            pass
        try:
            if outgoing_sock:
                outgoing_sock.close()
        except Exception:
            pass
        # Clean up raw injector port state
        if raw_injector is not None and local_port is not None:
            raw_injector.cleanup_port(local_port)


async def start_server(
    listen_host: str,
    listen_port: int,
    connect_ip: str,
    connect_port: int,
    fake_sni: str,
    bypass_strategy: BypassStrategy,
    interface_ip: Optional[str] = None,
    raw_injector=None,
):
    """Start the TCP forwarding server.

    Creates a listening socket and handles incoming connections,
    applying the DPI bypass strategy to each one.
    """
    # Create listening socket
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setblocking(False)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind((listen_host, listen_port))

    # Set keepalive on the listening socket
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    try:
        server_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 60)
        server_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 10)
        server_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 5)
    except (AttributeError, OSError):
        pass

    server_sock.listen(128)

    loop = asyncio.get_running_loop()

    logger.info(f"Listening on {listen_host}:{listen_port}")
    logger.info(f"Forwarding to {connect_ip}:{connect_port}")
    logger.info(f"Fake SNI: {fake_sni}")
    logger.info(f"Bypass strategy: {bypass_strategy.name}")
    if raw_injector is not None:
        logger.info("Raw packet injection: ACTIVE (seq_id trick enabled)")
    else:
        logger.info("Raw packet injection: not available (fragmentation only)")
    logger.info(f"Interface IP: {interface_ip or 'auto'}")
    logger.info("=" * 60)
    logger.info("Ready! Configure your application to use:")
    logger.info(f"  Address: 127.0.0.1:{listen_port}")
    logger.info("=" * 60)

    try:
        while True:
            incoming_sock, addr = await loop.sock_accept(server_sock)
            incoming_sock.setblocking(False)

            loop.create_task(
                handle_connection(
                    incoming_sock=incoming_sock,
                    incoming_addr=addr,
                    connect_ip=connect_ip,
                    connect_port=connect_port,
                    fake_sni=fake_sni,
                    bypass_strategy=bypass_strategy,
                    interface_ip=interface_ip,
                    raw_injector=raw_injector,
                )
            )
    except asyncio.CancelledError:
        pass
    finally:
        server_sock.close()
        logger.info("Server stopped.")
