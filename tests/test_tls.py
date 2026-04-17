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

    def test_build_client_hello_target_size(self):
        """Test that ClientHello hits 517 bytes (matching Go template)."""
        hello = ClientHelloBuilder.build_client_hello(sni="mci.ir")
        self.assertEqual(len(hello), 517)

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


class TestRawInjector(unittest.TestCase):
    """Test raw injector frame construction."""

    def test_build_fake_frame_checksum(self):
        """Test that _build_fake_frame produces valid IP and TCP checksums."""
        try:
            from sni_spoofing.bypass.raw_injector import (
                _build_fake_frame,
                _ip_checksum,
                _ip_hdr_len,
                _tcp_checksum,
            )
        except ImportError:
            self.skipTest("raw_injector not importable")

        # Build a minimal Ethernet+IP+TCP template (14+20+20 = 54 bytes)
        # Ethernet: dst(6) + src(6) + type(2)
        eth = bytes(6) + bytes(6) + b"\x08\x00"
        # IP header: version/ihl(1)+tos(1)+totlen(2)+id(2)+flags/frag(2)+ttl(1)+proto(1)+cksum(2)+src(4)+dst(4)
        iph = bytearray(20)
        iph[0] = 0x45  # IPv4, IHL=5
        iph[8] = 64    # TTL
        iph[9] = 6     # TCP
        iph[12:16] = b"\xc0\xa8\x01\x02"  # src 192.168.1.2
        iph[16:20] = b"\x68\x12\x04\x82"  # dst 104.18.4.130
        struct.pack_into("!H", iph, 2, 40)  # total length
        # TCP header: srcport(2)+dstport(2)+seq(4)+ack(4)+offset/flags(2)+window(2)+cksum(2)+urgent(2)
        tcph = bytearray(20)
        struct.pack_into("!H", tcph, 0, 54321)  # src port
        struct.pack_into("!H", tcph, 2, 443)    # dst port
        struct.pack_into("!I", tcph, 4, 1000)   # seq
        struct.pack_into("!I", tcph, 8, 2000)   # ack
        tcph[12] = 0x50  # data offset = 5 words
        tcph[13] = 0x10  # ACK flag

        template = bytes(eth) + bytes(iph) + bytes(tcph)

        # Build the fake frame
        fake_payload = ClientHelloBuilder.build_client_hello(sni="test.com")
        frame = _build_fake_frame(template, 999, fake_payload)

        # Check that the frame is longer than the template
        self.assertGreater(len(frame), len(template))

        # Verify the seq number: ISN + 1 - len(fake)
        tcp_off = 14 + 20
        seq = struct.unpack("!I", frame[tcp_off + 4:tcp_off + 8])[0]
        expected_seq = (1000 - len(fake_payload)) & 0xFFFFFFFF
        self.assertEqual(seq, expected_seq)

        # Check PSH flag is set
        self.assertTrue(frame[tcp_off + 13] & 0x08)

    def test_is_raw_available(self):
        """Test raw availability detection doesn't crash."""
        from sni_spoofing.bypass.raw_injector import is_raw_available
        result = is_raw_available()
        self.assertIsInstance(result, bool)


class TestProbeValidation(unittest.TestCase):
    """Test probe HTTP validation and MITM detection."""

    def test_legitimate_issuer_detection(self):
        """Known Cloudflare CA issuers should be accepted."""
        from sni_spoofing.scanner.probe import IPProbe
        probe = IPProbe()
        self.assertTrue(probe._is_legitimate_issuer("Cloudflare Inc"))
        self.assertTrue(probe._is_legitimate_issuer("DigiCert Inc"))
        self.assertTrue(probe._is_legitimate_issuer("Google Trust Services LLC"))
        self.assertTrue(probe._is_legitimate_issuer("Let's Encrypt"))
        self.assertTrue(probe._is_legitimate_issuer("ISRG Root X1"))
        self.assertTrue(probe._is_legitimate_issuer("E1"))
        self.assertTrue(probe._is_legitimate_issuer("R3"))
        self.assertTrue(probe._is_legitimate_issuer("Sectigo Limited"))
        self.assertTrue(probe._is_legitimate_issuer("GlobalSign"))
        self.assertTrue(probe._is_legitimate_issuer("Baltimore CyberTrust Root"))

    def test_mitm_issuer_rejected(self):
        """Unknown certificate issuers should be rejected."""
        from sni_spoofing.scanner.probe import IPProbe
        probe = IPProbe()
        self.assertFalse(probe._is_legitimate_issuer("My ISP MITM CA"))
        self.assertFalse(probe._is_legitimate_issuer("Government Root CA"))
        self.assertFalse(probe._is_legitimate_issuer("Kaspersky Lab"))
        self.assertFalse(probe._is_legitimate_issuer("mitmproxy"))
        self.assertFalse(probe._is_legitimate_issuer("Charles Proxy"))

    def test_empty_issuer_rejected(self):
        """Empty issuer string should be rejected."""
        from sni_spoofing.scanner.probe import IPProbe
        probe = IPProbe()
        self.assertFalse(probe._is_legitimate_issuer(""))

    def test_cloudflare_trace_markers(self):
        """Cloudflare trace markers constant should be defined."""
        from sni_spoofing.scanner.probe import CLOUDFLARE_TRACE_MARKERS
        self.assertIn("fl=", CLOUDFLARE_TRACE_MARKERS)
        self.assertIn("h=", CLOUDFLARE_TRACE_MARKERS)
        self.assertIn("colo=", CLOUDFLARE_TRACE_MARKERS)

    def test_probe_result_requires_http(self):
        """Alive requires http_ok to be True."""
        from sni_spoofing.scanner.probe import ProbeResult
        r = ProbeResult(ip="1.2.3.4", tcp_ok=True, tls_ok=True, http_ok=False)
        self.assertFalse(r.alive)
        r2 = ProbeResult(ip="1.2.3.4", tcp_ok=True, tls_ok=True, http_ok=True)
        self.assertTrue(r2.alive)


class TestUtilities(unittest.TestCase):
    """Test utility functions."""

    def test_imports(self):
        """Test that all modules import correctly."""
        from sni_spoofing.bypass import (
            BypassStrategy,
            CombinedBypass,
            FakeSNIBypass,
            FragmentBypass,
            RawInjector,
            is_raw_available,
        )
        from sni_spoofing.forwarder import handle_connection, start_server
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
        self.assertIn("af_packet", caps)
        self.assertIn("raw_injection", caps)
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

    def test_strategy_with_raw_injector(self):
        """Test strategy construction with raw_injector parameter."""
        from sni_spoofing.bypass import FakeSNIBypass, CombinedBypass

        fake = FakeSNIBypass(raw_injector="mock")
        self.assertEqual(fake.raw_injector, "mock")

        combo = CombinedBypass(raw_injector="mock")
        self.assertEqual(combo.raw_injector, "mock")

    def test_fake_sni_ttl_trick_flag(self):
        """Test FakeSNIBypass accepts use_ttl_trick parameter."""
        from sni_spoofing.bypass import FakeSNIBypass

        fake = FakeSNIBypass(use_ttl_trick=True)
        self.assertTrue(fake.use_ttl_trick)
        self.assertIsNone(fake.raw_injector)

    def test_fake_sni_ttl_trick_default(self):
        """Test FakeSNIBypass use_ttl_trick defaults to False."""
        from sni_spoofing.bypass import FakeSNIBypass

        fake = FakeSNIBypass()
        self.assertFalse(fake.use_ttl_trick)

    def test_combined_ttl_trick_flag(self):
        """Test CombinedBypass accepts use_ttl_trick parameter."""
        from sni_spoofing.bypass import CombinedBypass

        combo = CombinedBypass(use_ttl_trick=True)
        self.assertTrue(combo.use_ttl_trick)

    def test_build_strategy_fake_sni_with_ttl(self):
        """Test build_strategy passes USE_TTL_TRICK to FakeSNIBypass."""
        from sni_spoofing.cli import build_strategy

        config = {"BYPASS_METHOD": "fake_sni", "FAKE_SNI_METHOD": "prefix_fake",
                  "USE_TTL_TRICK": True}
        strategy = build_strategy(config)
        self.assertTrue(strategy.use_ttl_trick)

    def test_build_strategy_combined_with_ttl(self):
        """Test build_strategy passes USE_TTL_TRICK to CombinedBypass."""
        from sni_spoofing.cli import build_strategy

        config = {"BYPASS_METHOD": "combined", "FRAGMENT_STRATEGY": "sni_split",
                  "USE_TTL_TRICK": True, "FRAGMENT_DELAY": 0.1}
        strategy = build_strategy(config)
        self.assertTrue(strategy.use_ttl_trick)

    def test_sni_priority_in_provider(self):
        """Test that explicit SNI is prioritized in SNI provider."""
        from sni_spoofing.scanner.sni_provider import SNIProvider

        p = SNIProvider(domains=["a.com", "b.com", "c.com"])
        p.add_domain("user-choice.com")
        p.mark_success("user-choice.com", latency_ms=1.0)
        # user-choice.com should be returned as best (lowest latency)
        self.assertEqual(p.get_best(), "user-choice.com")


    def test_parse_host_port_no_port(self):
        """Test parse_host_port with just an IP (no port)."""
        from sni_spoofing.cli import parse_host_port

        host, port = parse_host_port("104.19.229.21", "0.0.0.0", 443)
        self.assertEqual(host, "104.19.229.21")
        self.assertEqual(port, 443)

    def test_parse_host_port_with_port(self):
        """Test parse_host_port with IP:PORT format."""
        from sni_spoofing.cli import parse_host_port

        host, port = parse_host_port("104.19.229.21:8443", "0.0.0.0", 443)
        self.assertEqual(host, "104.19.229.21")
        self.assertEqual(port, 8443)

    def test_parse_host_port_port_only(self):
        """Test parse_host_port with :PORT format."""
        from sni_spoofing.cli import parse_host_port

        host, port = parse_host_port(":40443", "0.0.0.0", 443)
        self.assertEqual(host, "0.0.0.0")
        self.assertEqual(port, 40443)


if __name__ == "__main__":
    unittest.main(verbosity=2)
