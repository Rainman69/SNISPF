"""Raw socket packet injection for out-of-window fake SNI.

Implements the seq_id trick from the Go reference:
1. Sniff the outbound SYN to record the ISN (Initial Sequence Number)
2. Sniff the outbound 3rd ACK (handshake complete)
3. Inject a fake TLS ClientHello with seq = ISN+1 - len(fake)
   This puts it BEFORE the server's receive window, so the server drops it,
   but DPI sees and parses the fake SNI.
4. Wait for the server to ACK with ack == ISN+1, confirming the fake was
   ignored and the server still expects the real data.

Linux only. Requires CAP_NET_RAW (run as root).
"""

import logging
import os
import socket
import struct
import threading
import time
from typing import Optional, Dict

logger = logging.getLogger("snispf")

ETH_P_IP = 0x0800
ETH_P_ALL = 0x0003
IPPROTO_TCP = 6

# TCP flags
FIN = 0x01
SYN = 0x02
RST = 0x04
PSH = 0x08
ACK = 0x10


def _htons(v):
    return socket.htons(v)


def _ip_hdr_len(ip_bytes):
    return (ip_bytes[0] & 0x0F) * 4


def _checksum_fold(s):
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


def _sum16(data):
    s = 0
    for i in range(0, len(data) - 1, 2):
        s += (data[i] << 8) | data[i + 1]
    if len(data) % 2 == 1:
        s += data[-1] << 8
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return s


def _ip_checksum(iph):
    return _checksum_fold(_sum16(iph))


def _tcp_checksum(iph, tcp_with_payload):
    ihl = _ip_hdr_len(iph)
    pseudo = bytearray(12)
    pseudo[0:4] = iph[12:16]  # src IP
    pseudo[4:8] = iph[16:20]  # dst IP
    pseudo[9] = 6  # TCP protocol
    struct.pack_into("!H", pseudo, 10, len(tcp_with_payload))
    return _checksum_fold(_sum16(pseudo) + _sum16(tcp_with_payload))


def _build_fake_frame(template_pkt, isn, fake_payload):
    """Build the injection frame from a captured 3rd-ACK packet template.

    Takes the captured Ethernet+IP+TCP headers from the 3rd handshake ACK,
    appends the fake TLS ClientHello as payload, and sets:
    - seq = ISN + 1 - len(fake_payload)  (out of window for the server)
    - PSH flag added
    - Proper IP and TCP checksums recalculated
    """
    ip_off = 14  # Ethernet header is 14 bytes
    ihl = _ip_hdr_len(template_pkt[ip_off:])
    tcp_off = ip_off + ihl
    tcp_hdr_len = (template_pkt[tcp_off + 12] >> 4) * 4

    # Copy headers (Ethernet + IP + TCP) and append fake payload
    headers = bytearray(template_pkt[:tcp_off + tcp_hdr_len])
    out = headers + fake_payload

    # Update IP total length
    struct.pack_into("!H", out, ip_off + 2, len(out) - ip_off)

    # Increment IP ID
    old_id = struct.unpack("!H", out[ip_off + 4:ip_off + 6])[0]
    struct.pack_into("!H", out, ip_off + 4, (old_id + 1) & 0xFFFF)

    # Recalculate IP checksum
    out[ip_off + 10] = 0
    out[ip_off + 11] = 0
    ip_cksum = _ip_checksum(out[ip_off:ip_off + ihl])
    struct.pack_into("!H", out, ip_off + 10, ip_cksum)

    # Set PSH flag
    out[tcp_off + 13] |= PSH

    # Set out-of-window sequence number: ISN + 1 - len(fake)
    seq = (isn + 1 - len(fake_payload)) & 0xFFFFFFFF
    struct.pack_into("!I", out, tcp_off + 4, seq)

    # Recalculate TCP checksum
    out[tcp_off + 16] = 0
    out[tcp_off + 17] = 0
    tcp_cksum = _tcp_checksum(
        out[ip_off:ip_off + ihl],
        bytes(out[tcp_off:]),
    )
    struct.pack_into("!H", out, tcp_off + 16, tcp_cksum)

    return bytes(out)


class PortState:
    """Per-connection state tracked by the sniffer."""

    def __init__(self, syn_seq, fake_hello):
        self.syn_seq = syn_seq
        self.fake_hello = fake_hello
        self.fake_sent = False
        self.confirmed = threading.Event()
        self.lock = threading.Lock()


class RawInjector:
    """Raw socket sniffer and injector for out-of-window fake SNI.

    This is the core mechanism that makes the seq_id trick work:
    - Monitors all TCP traffic between local and target IPs
    - When a new outbound SYN is detected, records the ISN
    - When the 3rd handshake ACK is seen, injects the fake ClientHello
    - Waits for server confirmation (ACK with ack == ISN+1)
    """

    def __init__(self, local_ip, remote_ip, remote_port, fake_sni_builder):
        self.local_ip = socket.inet_aton(local_ip)
        self.remote_ip = socket.inet_aton(remote_ip)
        self.remote_port = remote_port
        self.fake_sni_builder = fake_sni_builder

        self.ports: Dict[int, PortState] = {}
        self.ports_lock = threading.Lock()

        self.raw_fd = None
        self.iface_idx = None
        self.iface_name = None
        self.running = False
        self._sniffer_thread = None

    def start(self):
        """Open the raw socket and start the sniffer loop."""
        try:
            self.raw_fd = socket.socket(
                socket.AF_PACKET,
                socket.SOCK_RAW,
                socket.htons(ETH_P_ALL),
            )
        except (PermissionError, OSError) as e:
            logger.warning(f"Cannot open AF_PACKET socket: {e}")
            logger.warning("Raw injection unavailable - need root/CAP_NET_RAW")
            return False

        # Find the interface
        result = self._find_interface()
        if result is None:
            logger.warning("Cannot determine outgoing interface for raw injection")
            self.raw_fd.close()
            self.raw_fd = None
            return False

        self.iface_name, self.iface_idx = result
        self.raw_fd.bind((self.iface_name, ETH_P_ALL))

        self.running = True
        self._sniffer_thread = threading.Thread(
            target=self._sniff_loop, daemon=True
        )
        self._sniffer_thread.start()
        logger.info("Raw packet injector started")
        return True

    def stop(self):
        """Stop the sniffer."""
        self.running = False
        if self.raw_fd:
            try:
                self.raw_fd.close()
            except Exception:
                pass

    def _find_interface(self):
        """Find the network interface name and index for the target IP.

        Returns (iface_name, iface_index) or None.
        """
        import fcntl
        import array

        try:
            # Use a UDP connect to find which interface is used
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect((socket.inet_ntoa(self.remote_ip), 53))
            local_addr = s.getsockname()[0]
            s.close()

            # Get all interfaces and find the matching one
            # Using SIOCGIFCONF
            max_bytes = 8096
            buf = array.array("B", b"\0" * max_bytes)
            ifconf = struct.pack("iL", max_bytes, buf.buffer_info()[0])
            result = fcntl.ioctl(
                self.raw_fd.fileno(), 0x8912, ifconf  # SIOCGIFCONF
            )
            out_bytes = struct.unpack("iL", result)[0]

            offset = 0
            while offset < out_bytes:
                name = buf[offset:offset + 16].tobytes().split(b"\0", 1)[0]
                ip_bytes = buf[offset + 20:offset + 24].tobytes()
                ip_str = socket.inet_ntoa(ip_bytes)
                if ip_str == local_addr:
                    iface_name = name.decode("ascii", errors="replace")
                    # Get interface index
                    ifreq = struct.pack("16sI", name, 0)
                    result = fcntl.ioctl(
                        self.raw_fd.fileno(), 0x8933, ifreq  # SIOCGIFINDEX
                    )
                    idx = struct.unpack("16sI", result)[1]
                    logger.debug(f"Using interface {iface_name} (index {idx})")
                    return (iface_name, idx)
                offset += 40  # struct ifreq size

        except Exception as e:
            logger.debug(f"Interface detection error: {e}")

        return None

    def register_port(self, local_port, fake_hello):
        """Register a port for monitoring (called before connect)."""
        with self.ports_lock:
            self.ports[local_port] = PortState(0, fake_hello)

    def wait_for_confirmation(self, local_port, timeout=2.0):
        """Wait for the server to confirm it ignored the fake packet.

        Returns True if confirmed, False on timeout.
        """
        with self.ports_lock:
            ps = self.ports.get(local_port)

        if ps is None:
            return False

        return ps.confirmed.wait(timeout=timeout)

    def cleanup_port(self, local_port):
        """Clean up state for a port."""
        with self.ports_lock:
            self.ports.pop(local_port, None)

    def _inject_frame(self, frame):
        """Inject a raw Ethernet frame."""
        try:
            addr = (
                self.iface_name,  # interface name
                ETH_P_IP,
                0,  # packet type
                0,  # arp hardware type
                frame[0:6],  # destination MAC
            )
            self.raw_fd.sendto(frame, addr)
            return True
        except Exception as e:
            logger.debug(f"Inject error: {e}")
            # Fallback: try sendto with sockaddr_ll style
            try:
                sll = struct.pack(
                    "HH I BB 8s",
                    socket.htons(ETH_P_IP),  # protocol
                    self.iface_idx,  # ifindex
                    0,  # pkttype
                    6,  # halen
                    0,
                    frame[0:8],  # addr
                )
                os.write(self.raw_fd.fileno(), frame)
                return True
            except Exception as e2:
                logger.debug(f"Inject fallback error: {e2}")
                return False

    def _sniff_loop(self):
        """Main sniffer loop - watches TCP handshakes and injects fake packets."""
        while self.running:
            try:
                pkt, _ = self.raw_fd.recvfrom(65536)
            except (OSError, socket.error):
                if not self.running:
                    break
                continue

            if len(pkt) < 14 + 20 + 20:
                continue

            # Check Ethernet type is IPv4
            eth_type = struct.unpack("!H", pkt[12:14])[0]
            if eth_type != ETH_P_IP:
                continue

            ip = pkt[14:]
            if (ip[0] >> 4) != 4 or ip[9] != IPPROTO_TCP:
                continue

            ihl = _ip_hdr_len(ip)
            src_ip = ip[12:16]
            dst_ip = ip[16:20]
            tcp = ip[ihl:]
            if len(tcp) < 20:
                continue

            flags = tcp[13]
            tcp_hdr_len = (tcp[12] >> 4) * 4
            payload_len = len(tcp) - tcp_hdr_len

            outbound = (src_ip == self.local_ip and dst_ip == self.remote_ip)
            inbound = (src_ip == self.remote_ip and dst_ip == self.local_ip)

            if outbound:
                src_port = struct.unpack("!H", tcp[0:2])[0]
                seq = struct.unpack("!I", tcp[4:8])[0]

                # SYN (no ACK): new outbound connection
                if (flags & SYN) and not (flags & ACK):
                    with self.ports_lock:
                        ps = self.ports.get(src_port)
                    if ps is not None:
                        with ps.lock:
                            ps.syn_seq = seq
                        logger.debug(
                            f"[sniff] SYN port={src_port} isn={seq}"
                        )
                    continue

                # 3rd-handshake ACK: ACK only, no payload
                if (flags & ACK) and not (flags & (SYN | FIN | RST)) and payload_len == 0:
                    with self.ports_lock:
                        ps = self.ports.get(src_port)
                    if ps is None:
                        continue

                    with ps.lock:
                        if ps.fake_sent:
                            continue
                        ps.fake_sent = True
                        syn_seq = ps.syn_seq
                        fake = ps.fake_hello

                    # Inject after a tiny delay (like the Go version's 1ms)
                    tpl_copy = bytearray(pkt)

                    def _do_inject(tpl=tpl_copy, isn=syn_seq, payload=fake, port=src_port):
                        time.sleep(0.001)
                        frame = _build_fake_frame(bytes(tpl), isn, payload)
                        if self._inject_frame(frame):
                            out_seq = (isn + 1 - len(payload)) & 0xFFFFFFFF
                            logger.debug(
                                f"[inject] port={port} fake seq={out_seq} "
                                f"(ISN={isn}, fake_len={len(payload)})"
                            )
                        else:
                            logger.debug(f"[inject] port={port} injection failed")

                    threading.Thread(target=_do_inject, daemon=True).start()

            if inbound:
                dst_port = struct.unpack("!H", tcp[2:4])[0]
                ack_num = struct.unpack("!I", tcp[8:12])[0]

                # Server's ACK confirming fake was ignored
                if (flags & ACK) and not (flags & (SYN | FIN | RST)) and payload_len == 0:
                    with self.ports_lock:
                        ps = self.ports.get(dst_port)
                    if ps is None:
                        continue

                    with ps.lock:
                        if ps.fake_sent and ack_num == (ps.syn_seq + 1) & 0xFFFFFFFF:
                            if not ps.confirmed.is_set():
                                ps.confirmed.set()
                                logger.debug(
                                    f"[sniff] port={dst_port} CONFIRMED "
                                    f"server acked ISN+1={ack_num}"
                                )


def is_raw_available():
    """Check if raw socket injection is available on this system."""
    try:
        s = socket.socket(
            socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL)
        )
        s.close()
        return True
    except (PermissionError, OSError, AttributeError):
        return False
