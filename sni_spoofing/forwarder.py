"""Core TCP forwarder with DPI bypass and automatic failover.

This is the main engine that:
1. Listens for incoming TCP connections
2. Reads the first TLS ClientHello from the client
3. Resolves the target IP (static or auto-scanned)
4. Applies the chosen DPI bypass strategy
5. Relays data bidirectionally between client and server
6. Detects blocked connections and triggers failover

When a raw injector is available (Linux + root), it registers each
outgoing connection so the sniffer can capture the SYN/ACK handshake
and inject the fake ClientHello with an out-of-window seq number.

When the internal scanner is active, the forwarder automatically
selects the best Cloudflare IP and SNI, and rotates to a new one
if the current selection becomes unreachable.
"""

import asyncio
import logging
import socket
import sys
import time
import traceback
from typing import Optional

from .bypass.base import BypassStrategy
from .tls import ClientHelloBuilder

logger = logging.getLogger("snispf")

# Buffer size for socket operations
BUFFER_SIZE = 65535

# How many consecutive failures on a single IP before triggering failover
FAILOVER_THRESHOLD = 3

# Rapid failure window -- if we get FAILOVER_THRESHOLD failures within
# this many seconds, the IP is considered blocked.
FAILOVER_WINDOW = 30.0


class ConnectionTracker:
    """Tracks per-IP connection failures to detect blocking."""

    def __init__(self):
        self._failures = {}   # ip -> list of failure timestamps
        self._successes = {}  # ip -> count

    def record_failure(self, ip: str) -> int:
        """Record a failure and return how many occurred within the window."""
        now = time.monotonic()
        if ip not in self._failures:
            self._failures[ip] = []
        self._failures[ip].append(now)
        # Prune old entries
        cutoff = now - FAILOVER_WINDOW
        self._failures[ip] = [t for t in self._failures[ip] if t > cutoff]
        return len(self._failures[ip])

    def record_success(self, ip: str):
        """Record a successful connection (resets the failure counter)."""
        self._failures.pop(ip, None)
        self._successes[ip] = self._successes.get(ip, 0) + 1

    def should_failover(self, ip: str) -> bool:
        count = len(self._failures.get(ip, []))
        return count >= FAILOVER_THRESHOLD

    def clear(self, ip: str):
        self._failures.pop(ip, None)


# Module-level tracker shared across connections
_conn_tracker = ConnectionTracker()


async def handle_connection(
    incoming_sock: socket.socket,
    incoming_addr: tuple,
    connect_ip: str,
    connect_port: int,
    fake_sni: str,
    bypass_strategy: BypassStrategy,
    interface_ip: Optional[str] = None,
    raw_injector=None,
    scan_engine=None,
    sni_provider=None,
):
    """Handle a single incoming connection.

    Flow:
    1. Read first data from client (should be TLS ClientHello)
    2. Resolve target IP -- use scanner's best IP if available
    3. Create outgoing socket, optionally register with raw injector
    4. Connect to target server (3-way handshake happens here;
       the raw injector captures SYN and injects after 3rd ACK)
    5. Apply the bypass strategy (sends real data, waits for inject confirmation)
    6. Relay data bidirectionally
    7. On failure, report to scanner for failover
    """
    loop = asyncio.get_running_loop()
    outgoing_sock = None
    local_port = None
    active_ip = connect_ip
    active_sni = fake_sni

    try:
        # Read the first data from client (should be TLS ClientHello)
        first_data = await asyncio.wait_for(
            loop.sock_recv(incoming_sock, BUFFER_SIZE),
            timeout=30.0,
        )

        if not first_data:
            incoming_sock.close()
            return

        # If scanner is running, pick the best available IP
        if scan_engine is not None:
            best = scan_engine.get_best_ip()
            if best:
                active_ip = best

        # If SNI provider is available, pick the best SNI
        if sni_provider is not None:
            active_sni = sni_provider.get_best()

        # Parse to see if it's a TLS ClientHello
        parsed = ClientHelloBuilder.parse_client_hello(first_data)
        client_sni = parsed.get("sni", "unknown")
        logger.info(
            f"[{incoming_addr[0]}:{incoming_addr[1]}] -> "
            f"{active_ip}:{connect_port} | SNI: {client_sni} | "
            f"Fake: {active_sni} | Bypass: {bypass_strategy.name}"
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
            fake_hello = ClientHelloBuilder.build_client_hello(sni=active_sni)
            raw_injector.register_port(local_port, fake_hello)

        # Connect to target server (triggers SYN -> SYN+ACK -> ACK)
        try:
            await asyncio.wait_for(
                loop.sock_connect(outgoing_sock, (active_ip, connect_port)),
                timeout=15.0,
            )
        except (asyncio.TimeoutError, ConnectionRefusedError, OSError) as exc:
            # Connection failed -- record failure for failover
            fail_count = _conn_tracker.record_failure(active_ip)
            logger.debug(
                "[%s:%d] Connect to %s failed (%d/%d): %s",
                incoming_addr[0], incoming_addr[1], active_ip,
                fail_count, FAILOVER_THRESHOLD, exc,
            )
            if _conn_tracker.should_failover(active_ip) and scan_engine:
                scan_engine.report_failure(active_ip)
                logger.warning(
                    "IP %s reached failure threshold -- triggering failover",
                    active_ip,
                )
            if sni_provider is not None:
                sni_provider.mark_failed(active_sni)
            raise

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
            fake_sni=active_sni,
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

        # Connection established successfully -- record success
        _conn_tracker.record_success(active_ip)
        if sni_provider is not None:
            sni_provider.mark_success(active_sni)

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
    scan_engine=None,
    sni_provider=None,
):
    """Start the TCP forwarding server.

    Creates a listening socket and handles incoming connections,
    applying the DPI bypass strategy to each one.

    When *scan_engine* is provided, the server uses its best IP
    instead of the static *connect_ip*, and triggers automatic
    failover when connections are blocked.

    When *sni_provider* is provided, the fake SNI is dynamically
    selected from the provider's healthy domain list.
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
    if scan_engine is not None:
        best = scan_engine.get_best_ip()
        if best:
            logger.info(f"Auto-selected IP: {best} (scanner active)")
        else:
            logger.info(f"Scanner active -- will select IP after first scan")
        logger.info(f"Fallback IP: {connect_ip}:{connect_port}")
    else:
        logger.info(f"Forwarding to {connect_ip}:{connect_port}")
    if sni_provider is not None:
        logger.info(f"SNI provider active: {len(sni_provider.alive_domains)} domains")
        logger.info(f"Current best SNI: {sni_provider.get_best()}")
    else:
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
                    scan_engine=scan_engine,
                    sni_provider=sni_provider,
                )
            )
    except asyncio.CancelledError:
        pass
    finally:
        server_sock.close()
        logger.info("Server stopped.")
