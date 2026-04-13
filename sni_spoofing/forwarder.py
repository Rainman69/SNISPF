"""Core TCP forwarder with DPI bypass.

This is the main engine that:
1. Listens for incoming TCP connections
2. Reads the first TLS ClientHello from the client
3. Applies the chosen DPI bypass strategy
4. Relays data bidirectionally between client and server

Uses pure userspace techniques (no WinDivert/kernel drivers required).
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


async def relay_data(
    sock_in: socket.socket,
    sock_out: socket.socket,
    peer_task: asyncio.Task,
    first_data: Optional[bytes] = None,
    loop: Optional[asyncio.AbstractEventLoop] = None,
    direction: str = "",
):
    """Relay data from one socket to another.

    This is the bidirectional relay loop. Two instances run in parallel:
    one for client->server and one for server->client.

    Args:
        sock_in: Source socket to read from
        sock_out: Destination socket to write to
        peer_task: The peer relay task (cancelled on error)
        first_data: Optional first chunk to send before reading
        loop: Event loop
        direction: Description string for logging
    """
    if loop is None:
        loop = asyncio.get_running_loop()

    try:
        # Send any initial data
        if first_data:
            await loop.sock_sendall(sock_out, first_data)

        while True:
            data = await loop.sock_recv(sock_in, BUFFER_SIZE)
            if not data:
                break  # Connection closed

            await loop.sock_sendall(sock_out, data)

    except (ConnectionResetError, BrokenPipeError, OSError):
        pass  # Normal connection termination
    except Exception:
        logger.debug(f"Relay error ({direction}): {traceback.format_exc()}")
    finally:
        try:
            sock_in.close()
        except Exception:
            pass
        try:
            sock_out.close()
        except Exception:
            pass
        if not peer_task.done():
            peer_task.cancel()


async def handle_connection(
    incoming_sock: socket.socket,
    incoming_addr: tuple,
    connect_ip: str,
    connect_port: int,
    fake_sni: str,
    bypass_strategy: BypassStrategy,
    interface_ip: Optional[str] = None,
):
    """Handle a single incoming connection.

    This implements the connection handling logic from the original tool:
    1. Accept incoming connection
    2. Read first data (TLS ClientHello expected)
    3. Create outgoing connection to target
    4. Apply DPI bypass strategy
    5. Relay data bidirectionally

    Args:
        incoming_sock: The accepted client socket
        incoming_addr: Client address tuple (ip, port)
        connect_ip: Target server IP
        connect_port: Target server port
        fake_sni: Fake SNI for bypass
        bypass_strategy: The bypass strategy to use
        interface_ip: Optional local IP to bind outgoing connections
    """
    loop = asyncio.get_running_loop()
    outgoing_sock = None

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

        # Connect to target server
        await asyncio.wait_for(
            loop.sock_connect(outgoing_sock, (connect_ip, connect_port)),
            timeout=30.0,
        )

        # Apply DPI bypass strategy
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

        # Create bidirectional relay tasks
        # client -> server is already handled (first_data sent by bypass)
        # Now set up continuous relay

        # Use a done event to signal when either direction closes
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


async def start_server(
    listen_host: str,
    listen_port: int,
    connect_ip: str,
    connect_port: int,
    fake_sni: str,
    bypass_strategy: BypassStrategy,
    interface_ip: Optional[str] = None,
):
    """Start the TCP forwarding server.

    Creates a listening socket and handles incoming connections,
    applying the DPI bypass strategy to each one.

    Args:
        listen_host: IP to listen on (0.0.0.0 for all interfaces)
        listen_port: Port to listen on
        connect_ip: Target server IP to forward to
        connect_port: Target server port
        fake_sni: Fake SNI hostname for bypass
        bypass_strategy: DPI bypass strategy to use
        interface_ip: Optional local IP for outgoing connections
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
    logger.info(f"Interface IP: {interface_ip or 'auto'}")
    logger.info("=" * 60)
    logger.info("Ready! Configure your application to use:")
    logger.info(f"  Address: 127.0.0.1:{listen_port}")
    logger.info("=" * 60)

    try:
        while True:
            incoming_sock, addr = await loop.sock_accept(server_sock)
            incoming_sock.setblocking(False)

            # Handle each connection in its own task
            loop.create_task(
                handle_connection(
                    incoming_sock=incoming_sock,
                    incoming_addr=addr,
                    connect_ip=connect_ip,
                    connect_port=connect_port,
                    fake_sni=fake_sni,
                    bypass_strategy=bypass_strategy,
                    interface_ip=interface_ip,
                )
            )
    except asyncio.CancelledError:
        pass
    finally:
        server_sock.close()
        logger.info("Server stopped.")
