"""TLS record fragmentation utilities.

Implements various strategies for splitting TLS records to confuse
DPI (Deep Packet Inspection) systems that don't fully reassemble
TLS handshakes.
"""

import struct
from typing import List, Tuple


def fragment_client_hello(data: bytes, strategy: str = "sni_split") -> List[bytes]:
    """Fragment a TLS ClientHello into multiple TCP segments.

    DPI systems often only inspect the first packet or fail to reassemble
    fragmented TLS records. By splitting the ClientHello at strategic points
    (especially around the SNI extension), we can hide the real SNI.

    Args:
        data: Complete TLS record bytes
        strategy: Fragmentation strategy:
            - "sni_split": Split right in the middle of the SNI value
            - "half": Split the record in half
            - "multi": Split into many small fragments
            - "tls_record_frag": Use TLS-level record fragmentation
            - "none": No fragmentation

    Returns:
        List of byte fragments to send as separate TCP segments
    """
    if strategy == "none" or len(data) < 10:
        return [data]

    if strategy == "sni_split":
        return _fragment_at_sni(data)
    elif strategy == "half":
        mid = len(data) // 2
        return [data[:mid], data[mid:]]
    elif strategy == "multi":
        return _fragment_multi(data)
    elif strategy == "tls_record_frag":
        return _tls_record_fragment(data)
    else:
        return [data]


def _find_sni_offset(data: bytes) -> Tuple[int, int]:
    """Find the offset and length of the SNI value in a ClientHello.

    Returns:
        Tuple of (sni_value_offset, sni_value_length) or (-1, 0) if not found
    """
    # Look for SNI extension type (0x0000) followed by reasonable length
    pos = 0
    while pos < len(data) - 10:
        # Look for the SNI extension pattern: 00 00 xx xx xx xx 00 xx xx 00
        if data[pos] == 0x00 and data[pos + 1] == 0x00:
            try:
                ext_len = struct.unpack("!H", data[pos + 2 : pos + 4])[0]
                if 4 < ext_len < 256:  # Reasonable SNI extension length
                    list_len = struct.unpack("!H", data[pos + 4 : pos + 6])[0]
                    name_type = data[pos + 6]
                    name_len = struct.unpack("!H", data[pos + 7 : pos + 9])[0]
                    if name_type == 0 and name_len > 0 and name_len < 256:
                        sni_start = pos + 9
                        # Verify it looks like a domain name
                        sni_data = data[sni_start : sni_start + name_len]
                        if all(0x20 <= b < 0x7F for b in sni_data):
                            return sni_start, name_len
            except (struct.error, IndexError):
                pass
        pos += 1
    return -1, 0


def _fragment_at_sni(data: bytes) -> List[bytes]:
    """Split the TLS record right in the middle of the SNI value."""
    sni_offset, sni_len = _find_sni_offset(data)

    if sni_offset < 0:
        # Fallback to half split
        mid = len(data) // 2
        return [data[:mid], data[mid:]]

    # Split in the middle of the SNI hostname
    split_point = sni_offset + sni_len // 2
    return [data[:split_point], data[split_point:]]


def _fragment_multi(data: bytes, chunk_size: int = 24) -> List[bytes]:
    """Split into many small fragments.

    Each fragment gets sent as its own TCP segment with TCP_NODELAY.
    A chunk size of 24 bytes keeps the fragment count reasonable
    (about 22 fragments for a 517-byte ClientHello) while still being
    small enough that no single fragment contains the entire SNI.
    """
    fragments = []
    for i in range(0, len(data), chunk_size):
        fragments.append(data[i : i + chunk_size])
    return fragments


def _tls_record_fragment(data: bytes) -> List[bytes]:
    """Use TLS-level record fragmentation.

    Instead of splitting at the TCP level, we create multiple valid
    TLS records that together contain the full handshake message.
    This is a more sophisticated approach that some DPI systems
    can't handle.
    """
    if len(data) < 6 or data[0] != 0x16:
        return [data]

    # Extract the handshake data from the TLS record
    record_version = data[1:3]
    handshake_data = data[5:]

    # Split the handshake data into two parts
    mid = len(handshake_data) // 2
    part1 = handshake_data[:mid]
    part2 = handshake_data[mid:]

    # Create two separate TLS records
    record1 = b"\x16" + record_version + struct.pack("!H", len(part1)) + part1
    record2 = b"\x16" + record_version + struct.pack("!H", len(part2)) + part2

    return [record1, record2]


def fragment_data(data: bytes, sizes: List[int]) -> List[bytes]:
    """Fragment data into specified sizes.

    Args:
        data: Raw bytes to fragment
        sizes: List of fragment sizes. Last fragment gets remaining data.

    Returns:
        List of byte fragments
    """
    if not sizes or not data:
        return [data] if data else []

    fragments = []
    pos = 0
    for i, size in enumerate(sizes):
        if pos >= len(data):
            break
        if i == len(sizes) - 1:
            # Last specified size: include all remaining data
            fragments.append(data[pos:])
            pos = len(data)
        else:
            fragments.append(data[pos : pos + size])
            pos += size

    # If we consumed all specified sizes but data remains
    if pos < len(data):
        fragments.append(data[pos:])

    return fragments if fragments else [data]
