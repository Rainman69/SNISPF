"""Unit tests for TLS ClientHello builder and parser."""

import os
import sys
import struct
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sni_spoofing.tls import ClientHelloBuilder
from sni_spoofing.tls.fragment import (
    fragment_client_hello,
    fragment_data,
    _find_sni_offset,
)


class TestClientHelloBuilder(unittest.TestCase):
    """Test TLS ClientHello construction."""

    def test_build_client_hello_basic(self):
        """Test basic ClientHello construction."""
        hello = ClientHelloBuilder.build_client_hello(sni="example.com")

        # Should start with TLS record header
        self.assertEqual(hello[0], 0x16)  # Handshake
        self.assertEqual(hello[1], 0x03)  # TLS major version
        self.assertEqual(hello[2], 0x01)  # TLS 1.0 (legacy)

        # Record length should match
        record_len = struct.unpack("!H", hello[3:5])[0]
        self.assertEqual(record_len, len(hello) - 5)

        # Handshake type should be ClientHello
        self.assertEqual(hello[5], 0x01)

    def test_build_client_hello_contains_sni(self):
        """Test that built ClientHello contains the specified SNI."""
        sni = "auth.vercel.com"
        hello = ClientHelloBuilder.build_client_hello(sni=sni)

        # The SNI should be present in the packet
        self.assertIn(sni.encode("ascii"), hello)

    def test_build_client_hello_different_snis(self):
        """Test building with different SNI values."""
        for sni in ["google.com", "cloudflare.com", "example.org", "test.co"]:
            hello = ClientHelloBuilder.build_client_hello(sni=sni)
            self.assertIn(sni.encode("ascii"), hello)
            self.assertEqual(hello[0], 0x16)

    def test_build_client_hello_custom_session_id(self):
        """Test with custom session ID."""
        session_id = os.urandom(32)
        hello = ClientHelloBuilder.build_client_hello(
            sni="test.com", session_id=session_id
        )
        self.assertIn(session_id, hello)

    def test_build_client_hello_custom_random(self):
        """Test with custom random bytes."""
        random_bytes = os.urandom(32)
        hello = ClientHelloBuilder.build_client_hello(
            sni="test.com", random_bytes=random_bytes
        )
        self.assertIn(random_bytes, hello)

    def test_parse_client_hello_roundtrip(self):
        """Test build and parse roundtrip."""
        sni = "auth.vercel.com"
        hello = ClientHelloBuilder.build_client_hello(sni=sni)
        parsed = ClientHelloBuilder.parse_client_hello(hello)

        self.assertEqual(parsed.get("handshake_type"), "ClientHello")
        self.assertEqual(parsed.get("sni"), sni)
        self.assertEqual(parsed.get("content_type"), 0x16)

    def test_parse_client_hello_multiple(self):
        """Test parsing multiple different ClientHellos."""
        for sni in ["test.com", "example.org", "cloudflare.com"]:
            hello = ClientHelloBuilder.build_client_hello(sni=sni)
            parsed = ClientHelloBuilder.parse_client_hello(hello)
            self.assertEqual(parsed.get("sni"), sni)

    def test_build_sni_extension(self):
        """Test SNI extension construction."""
        ext = ClientHelloBuilder.build_sni_extension("test.com")

        # Extension type should be 0x0000 (SNI)
        ext_type = struct.unpack("!H", ext[0:2])[0]
        self.assertEqual(ext_type, 0x0000)

        # Should contain the hostname
        self.assertIn(b"test.com", ext)

    def test_build_key_share_extension(self):
        """Test key share extension construction."""
        key = os.urandom(32)
        ext = ClientHelloBuilder.build_key_share_extension(key)

        # Extension type should be 0x0033 (key_share)
        ext_type = struct.unpack("!H", ext[0:2])[0]
        self.assertEqual(ext_type, 0x0033)

        # Should contain the key
        self.assertIn(key, ext)

    def test_build_client_response(self):
        """Test client response (CCS + AppData) construction."""
        resp = ClientHelloBuilder.build_client_response()

        # Should start with Change Cipher Spec
        self.assertEqual(resp[0], 0x14)  # CCS content type
        self.assertEqual(resp[1], 0x03)
        self.assertEqual(resp[2], 0x03)

    def test_parse_empty_data(self):
        """Test parsing empty or too-short data."""
        self.assertEqual(ClientHelloBuilder.parse_client_hello(b""), {})
        self.assertEqual(ClientHelloBuilder.parse_client_hello(b"\x00"), {})

    def test_parse_non_handshake(self):
        """Test parsing non-handshake data."""
        result = ClientHelloBuilder.parse_client_hello(b"\x17\x03\x03\x00\x05hello")
        self.assertEqual(result.get("content_type"), 0x17)
        self.assertNotIn("handshake_type", result)


class TestFragmentation(unittest.TestCase):
    """Test TLS record fragmentation."""

    def test_sni_split_fragments(self):
        """Test SNI-split fragmentation produces exactly 2 fragments."""
        hello = ClientHelloBuilder.build_client_hello(sni="test.example.com")
        fragments = fragment_client_hello(hello, "sni_split")

        self.assertEqual(len(fragments), 2)
        # Reassembled should equal original
        self.assertEqual(b"".join(fragments), hello)

    def test_half_split(self):
        """Test half-split fragmentation."""
        hello = ClientHelloBuilder.build_client_hello(sni="test.com")
        fragments = fragment_client_hello(hello, "half")

        self.assertEqual(len(fragments), 2)
        self.assertEqual(b"".join(fragments), hello)

    def test_multi_split(self):
        """Test multi-fragment split."""
        hello = ClientHelloBuilder.build_client_hello(sni="test.com")
        fragments = fragment_client_hello(hello, "multi")

        self.assertGreater(len(fragments), 2)
        self.assertEqual(b"".join(fragments), hello)

    def test_tls_record_fragment(self):
        """Test TLS record-level fragmentation."""
        hello = ClientHelloBuilder.build_client_hello(sni="test.com")
        fragments = fragment_client_hello(hello, "tls_record_frag")

        self.assertEqual(len(fragments), 2)
        # Each fragment should be a valid TLS record
        for frag in fragments:
            self.assertEqual(frag[0], 0x16)  # Handshake type

    def test_no_fragmentation(self):
        """Test 'none' strategy returns single fragment."""
        hello = ClientHelloBuilder.build_client_hello(sni="test.com")
        fragments = fragment_client_hello(hello, "none")

        self.assertEqual(len(fragments), 1)
        self.assertEqual(fragments[0], hello)

    def test_find_sni_offset(self):
        """Test SNI offset detection."""
        hello = ClientHelloBuilder.build_client_hello(sni="example.com")
        offset, length = _find_sni_offset(hello)

        self.assertGreater(offset, 0)
        self.assertEqual(length, len("example.com"))
        # Verify the SNI at that offset
        self.assertEqual(hello[offset:offset + length], b"example.com")

    def test_fragment_data_custom_sizes(self):
        """Test custom size fragmentation."""
        data = b"A" * 100
        fragments = fragment_data(data, [10, 20, 30])

        self.assertEqual(len(fragments[0]), 10)
        self.assertEqual(len(fragments[1]), 20)
        self.assertEqual(b"".join(fragments), data)

    def test_fragment_preserves_data(self):
        """Test that fragmentation preserves all data."""
        for strategy in ["sni_split", "half", "multi", "tls_record_frag", "none"]:
            hello = ClientHelloBuilder.build_client_hello(sni="test.example.org")
            fragments = fragment_client_hello(hello, strategy)
            if strategy != "tls_record_frag":
                # For TLS record frag, the output is re-wrapped
                reassembled = b"".join(fragments)
                self.assertEqual(
                    len(reassembled),
                    len(hello),
                    f"Strategy '{strategy}' changed data length",
                )


class TestUtilities(unittest.TestCase):
    """Test utility functions."""

    def test_imports(self):
        """Test that all modules import correctly."""
        from sni_spoofing.bypass import (
            BypassStrategy,
            CombinedBypass,
            FakeSNIBypass,
            FragmentBypass,
        )
        from sni_spoofing.forwarder import relay_data, handle_connection, start_server
        from sni_spoofing.utils import (
            get_default_interface_ipv4,
            check_platform_capabilities,
            resolve_host,
            is_valid_ip,
            is_valid_port,
        )

    def test_is_valid_ip(self):
        """Test IP validation."""
        from sni_spoofing.utils import is_valid_ip

        self.assertTrue(is_valid_ip("127.0.0.1"))
        self.assertTrue(is_valid_ip("192.168.1.1"))
        self.assertTrue(is_valid_ip("0.0.0.0"))
        self.assertFalse(is_valid_ip("not-an-ip"))
        self.assertFalse(is_valid_ip(""))

    def test_is_valid_port(self):
        """Test port validation."""
        from sni_spoofing.utils import is_valid_port

        self.assertTrue(is_valid_port(80))
        self.assertTrue(is_valid_port(443))
        self.assertTrue(is_valid_port(40443))
        self.assertTrue(is_valid_port(65535))
        self.assertFalse(is_valid_port(0))
        self.assertFalse(is_valid_port(65536))
        self.assertFalse(is_valid_port(-1))

    def test_platform_capabilities(self):
        """Test platform capabilities detection."""
        from sni_spoofing.utils import check_platform_capabilities

        caps = check_platform_capabilities()
        self.assertIn("platform", caps)
        self.assertIn("fragment_support", caps)
        self.assertIn("tls_record_frag", caps)
        self.assertTrue(caps["fragment_support"])
        self.assertTrue(caps["tls_record_frag"])
        self.assertTrue(caps["fake_sni"])

    def test_strategy_construction(self):
        """Test bypass strategy construction."""
        from sni_spoofing.bypass import FragmentBypass, FakeSNIBypass, CombinedBypass

        frag = FragmentBypass(strategy="sni_split")
        self.assertEqual(frag.name, "fragment")

        fake = FakeSNIBypass(method="prefix_fake")
        self.assertEqual(fake.name, "fake_sni")

        combo = CombinedBypass()
        self.assertEqual(combo.name, "combined")


if __name__ == "__main__":
    unittest.main(verbosity=2)
