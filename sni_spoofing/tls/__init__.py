"""TLS ClientHello builder and parser module.

Constructs TLS 1.3 ClientHello messages with customizable SNI fields
for DPI bypass purposes.
"""

import struct
import os
from typing import Optional


class ClientHelloBuilder:
    """Builds TLS ClientHello packets with spoofed SNI.

    The ClientHello is the first message in a TLS handshake. DPI systems
    inspect the SNI (Server Name Indication) extension to determine the
    destination hostname. By sending a ClientHello with a fake SNI to an
    allowed domain, we can bypass SNI-based filtering.
    """

    # Pre-built template parts from the original tool
    # TLS Record Header + Handshake Header + Client Version + ...
    # Cipher suites, compression methods, and most extensions are static
    # Only SNI, session_id, random, and key_share are dynamic

    # TLS 1.3 cipher suites that look legitimate
    CIPHER_SUITES = bytes.fromhex(
        "0024"  # length = 36 bytes (18 cipher suites x 2)
        "1302"  # TLS_AES_256_GCM_SHA384
        "1303"  # TLS_CHACHA20_POLY1305_SHA256
        "1301"  # TLS_AES_128_GCM_SHA256
        "c02c"  # TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
        "c030"  # TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
        "c02b"  # TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
        "c02f"  # TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
        "cca9"  # TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
        "cca8"  # TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
        "c024"  # TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384
        "c028"  # TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384
        "c023"  # TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256
        "c027"  # TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256
        "009f"  # TLS_DHE_RSA_WITH_AES_256_GCM_SHA384
        "009e"  # TLS_DHE_RSA_WITH_AES_128_GCM_SHA256
        "006b"  # TLS_DHE_RSA_WITH_AES_256_CBC_SHA256
        "0067"  # TLS_DHE_RSA_WITH_AES_128_CBC_SHA256
        "00ff"  # TLS_EMPTY_RENEGOTIATION_INFO_SCSV
    )

    # Supported groups extension
    SUPPORTED_GROUPS = bytes.fromhex(
        "000a"  # extension type: supported_groups
        "0016"  # length
        "0014"  # list length
        "001d"  # x25519
        "0017"  # secp256r1
        "001e"  # x448
        "0019"  # secp521r1
        "0018"  # secp384r1
        "0100"  # ffdhe2048
        "0101"  # ffdhe3072
        "0102"  # ffdhe4096
        "0103"  # ffdhe6144
        "0104"  # ffdhe8192
    )

    # Signature algorithms extension
    SIGNATURE_ALGORITHMS = bytes.fromhex(
        "000d"  # extension type: signature_algorithms
        "002a"  # length
        "0028"  # list length
        "0403"  # ecdsa_secp256r1_sha256
        "0503"  # ecdsa_secp384r1_sha384
        "0603"  # ecdsa_secp521r1_sha512
        "0807"  # ed25519
        "0808"  # ed448
        "0809"  # ...
        "080a"
        "080b"
        "0804"  # rsa_pss_rsae_sha256
        "0805"  # rsa_pss_rsae_sha384
        "0806"  # rsa_pss_rsae_sha512
        "0401"  # rsa_pkcs1_sha256
        "0501"  # rsa_pkcs1_sha384
        "0601"  # rsa_pkcs1_sha512
        "0303"  # ...
        "0301"
        "0302"
        "0402"
        "0502"
        "0602"
    )

    # EC point formats
    EC_POINT_FORMATS = bytes.fromhex(
        "000b"  # extension type: ec_point_formats
        "0004"  # length
        "0300"  # list length + uncompressed
        "0102"  # ansiX962_compressed_prime + ansiX962_compressed_char2
    )

    # Session ticket extension (empty)
    SESSION_TICKET = bytes.fromhex(
        "0023"  # extension type: session_ticket
        "0000"  # length: 0
    )

    # ALPN extension (h2, http/1.1)
    ALPN = bytes.fromhex(
        "0010"  # extension type: ALPN
        "000e"  # length
        "000c"  # protocols length
        "0268"  # length + 'h'
        "3208"  # '2' + length
        "6874"  # 'ht'
        "7470"  # 'tp'
        "2f31"  # '/1'
        "2e31"  # '.1'
    )

    # Encrypt then MAC
    ENCRYPT_THEN_MAC = bytes.fromhex("0016" "0000")

    # Extended master secret
    EXTENDED_MASTER_SECRET = bytes.fromhex("0017" "0000")

    # Supported versions extension (TLS 1.3, TLS 1.2)
    SUPPORTED_VERSIONS = bytes.fromhex(
        "002b"  # extension type: supported_versions
        "0005"  # length
        "0403"  # list length
        "0304"  # TLS 1.3
        "0303"  # TLS 1.2
    )

    # PSK key exchange modes
    PSK_KEY_EXCHANGE = bytes.fromhex(
        "002d"  # extension type: psk_key_exchange_modes
        "0002"  # length
        "0101"  # psk_dhe_ke
    )

    @classmethod
    def build_sni_extension(cls, sni: str) -> bytes:
        """Build the SNI (Server Name Indication) extension."""
        sni_bytes = sni.encode("ascii")
        sni_len = len(sni_bytes)

        # Server name entry: type(1) + length(2) + name
        entry = struct.pack("!BH", 0, sni_len) + sni_bytes
        # Server name list: length(2) + entries
        name_list = struct.pack("!H", len(entry)) + entry
        # Extension: type(2) + length(2) + data
        return struct.pack("!HH", 0x0000, len(name_list)) + name_list

    @classmethod
    def build_key_share_extension(cls, public_key: Optional[bytes] = None) -> bytes:
        """Build the key_share extension with x25519 key."""
        if public_key is None:
            public_key = os.urandom(32)

        # Key share entry: group(2) + key_length(2) + key
        entry = struct.pack("!HH", 0x001D, 32) + public_key
        # Key share extension: length(2) + entries
        data = struct.pack("!H", len(entry)) + entry
        return struct.pack("!HH", 0x0033, len(data)) + data

    @classmethod
    def build_padding_extension(cls, target_length: int, current_length: int) -> bytes:
        """Build padding extension to reach target ClientHello size.

        Padding is used to make the ClientHello a specific size, which helps
        avoid fingerprinting and ensures consistent packet sizes.
        """
        # Extension header is 4 bytes (type + length)
        padding_needed = target_length - current_length - 4
        if padding_needed < 0:
            return b""
        return struct.pack("!HH", 0x0015, padding_needed) + (b"\x00" * padding_needed)

    @classmethod
    def build_client_hello(
        cls,
        sni: str,
        session_id: Optional[bytes] = None,
        random_bytes: Optional[bytes] = None,
        key_share: Optional[bytes] = None,
        target_size: int = 517,
    ) -> bytes:
        """Build a complete TLS ClientHello record.

        Args:
            sni: The Server Name Indication to include
            session_id: 32-byte session ID (random if None)
            random_bytes: 32-byte client random (random if None)
            key_share: 32-byte x25519 public key (random if None)
            target_size: Target total size for the TLS record (default 517)

        Returns:
            Complete TLS record bytes ready to send
        """
        if session_id is None:
            session_id = os.urandom(32)
        if random_bytes is None:
            random_bytes = os.urandom(32)

        # Client version: TLS 1.2 (0x0303) - real version in extensions
        client_version = b"\x03\x03"

        # Session ID
        session_id_field = struct.pack("!B", len(session_id)) + session_id

        # Compression methods: null only
        compression = b"\x01\x00"

        # Build extensions
        sni_ext = cls.build_sni_extension(sni)
        key_share_ext = cls.build_key_share_extension(key_share)

        # Assemble extensions (order matters for fingerprint matching)
        extensions = b"".join([
            sni_ext,
            cls.EC_POINT_FORMATS,
            cls.SUPPORTED_GROUPS,
            cls.SESSION_TICKET,
            cls.ALPN,
            cls.ENCRYPT_THEN_MAC,
            cls.EXTENDED_MASTER_SECRET,
            cls.SIGNATURE_ALGORITHMS,
            cls.SUPPORTED_VERSIONS,
            cls.PSK_KEY_EXCHANGE,
            key_share_ext,
        ])

        # Calculate size for padding
        # Handshake body (without record header): version(2) + random(32) + session_id_field + cipher_suites + compression + extensions_header(2) + extensions
        handshake_body_no_pad = (
            client_version
            + random_bytes
            + session_id_field
            + cls.CIPHER_SUITES
            + compression
        )
        extensions_len_so_far = len(extensions)
        # Total handshake msg = 4 (handshake header) + body + 2 (extensions length) + extensions
        total_so_far = 4 + len(handshake_body_no_pad) + 2 + extensions_len_so_far
        # TLS record = 5 (record header) + handshake
        record_so_far = 5 + total_so_far

        # Add padding to reach target size
        padding_ext = cls.build_padding_extension(target_size, record_so_far)
        extensions += padding_ext

        # Extensions length prefix
        extensions_with_len = struct.pack("!H", len(extensions)) + extensions

        # Handshake body
        handshake_body = handshake_body_no_pad + extensions_with_len

        # Handshake message: type(1) + length(3) + body
        handshake_len = len(handshake_body)
        handshake = (
            b"\x01"  # ClientHello
            + struct.pack("!I", handshake_len)[1:]  # 3-byte length
            + handshake_body
        )

        # TLS record: content_type(1) + version(2) + length(2) + data
        record = (
            b"\x16"  # Handshake
            + b"\x03\x01"  # TLS 1.0 (legacy for compatibility)
            + struct.pack("!H", len(handshake))
            + handshake
        )

        return record

    @classmethod
    def build_client_response(cls, random_bytes: Optional[bytes] = None) -> bytes:
        """Build a fake TLS client response (ChangeCipherSpec + ApplicationData).

        This simulates the client's response after receiving ServerHello,
        which is useful for making the connection look legitimate to DPI.
        """
        if random_bytes is None:
            random_bytes = os.urandom(32)

        # Change Cipher Spec
        ccs = b"\x14\x03\x03\x00\x01\x01"

        # Application Data (fake encrypted payload)
        app_data = (
            b"\x17"  # Application Data
            + b"\x03\x03"  # TLS 1.2
            + struct.pack("!H", len(random_bytes))
            + random_bytes
        )

        return ccs + app_data

    @staticmethod
    def parse_client_hello(data: bytes) -> dict:
        """Parse a TLS ClientHello to extract SNI and other fields.

        Args:
            data: Raw TLS record bytes

        Returns:
            Dictionary with parsed fields
        """
        result = {}

        if len(data) < 5:
            return result

        # TLS Record header
        content_type = data[0]
        tls_version = struct.unpack("!H", data[1:3])[0]
        record_len = struct.unpack("!H", data[3:5])[0]
        result["content_type"] = content_type
        result["tls_version"] = f"0x{tls_version:04x}"

        if content_type != 0x16:  # Not handshake
            return result

        pos = 5  # Skip record header

        # Handshake header
        if pos + 4 > len(data):
            return result
        hs_type = data[pos]
        hs_len = struct.unpack("!I", b"\x00" + data[pos + 1 : pos + 4])[0]
        pos += 4

        if hs_type != 0x01:  # Not ClientHello
            return result

        result["handshake_type"] = "ClientHello"

        # Client version
        client_version = struct.unpack("!H", data[pos : pos + 2])[0]
        result["client_version"] = f"0x{client_version:04x}"
        pos += 2

        # Random (32 bytes)
        result["random"] = data[pos : pos + 32].hex()
        pos += 32

        # Session ID
        sess_len = data[pos]
        pos += 1
        result["session_id"] = data[pos : pos + sess_len].hex()
        pos += sess_len

        # Cipher suites
        cs_len = struct.unpack("!H", data[pos : pos + 2])[0]
        pos += 2 + cs_len

        # Compression
        comp_len = data[pos]
        pos += 1 + comp_len

        # Extensions
        if pos + 2 > len(data):
            return result
        ext_len = struct.unpack("!H", data[pos : pos + 2])[0]
        pos += 2

        ext_end = pos + ext_len
        while pos + 4 <= ext_end:
            ext_type = struct.unpack("!H", data[pos : pos + 2])[0]
            ext_data_len = struct.unpack("!H", data[pos + 2 : pos + 4])[0]
            ext_data = data[pos + 4 : pos + 4 + ext_data_len]
            pos += 4 + ext_data_len

            if ext_type == 0x0000:  # SNI
                if len(ext_data) >= 5:
                    name_list_len = struct.unpack("!H", ext_data[0:2])[0]
                    name_type = ext_data[2]
                    name_len = struct.unpack("!H", ext_data[3:5])[0]
                    sni = ext_data[5 : 5 + name_len].decode("ascii", errors="replace")
                    result["sni"] = sni

        return result

    @staticmethod
    def parse_server_hello(data: bytes) -> dict:
        """Parse a TLS ServerHello message."""
        result = {}

        if len(data) < 5:
            return result

        content_type = data[0]
        if content_type != 0x16:
            return result

        pos = 5  # Skip record header
        if pos + 4 > len(data):
            return result

        hs_type = data[pos]
        pos += 4

        if hs_type != 0x02:  # Not ServerHello
            return result

        result["handshake_type"] = "ServerHello"

        # Server version
        server_version = struct.unpack("!H", data[pos : pos + 2])[0]
        result["server_version"] = f"0x{server_version:04x}"
        pos += 2

        # Server random
        result["random"] = data[pos : pos + 32].hex()
        pos += 32

        # Session ID
        sess_len = data[pos]
        pos += 1
        result["session_id"] = data[pos : pos + sess_len].hex()
        pos += sess_len

        # Cipher suite
        cipher = struct.unpack("!H", data[pos : pos + 2])[0]
        result["cipher_suite"] = f"0x{cipher:04x}"
        pos += 2

        # Compression
        result["compression"] = data[pos]
        pos += 1

        return result
