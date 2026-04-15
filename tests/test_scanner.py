"""Unit tests for the Cloudflare IP scanner and SNI provider modules."""

import os
import sys
import json
import struct
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sni_spoofing.scanner.ip_ranges import CloudflareIPPool, CLOUDFLARE_IPV4_RANGES, CLOUDFLARE_SEED_IPS
from sni_spoofing.scanner.probe import IPProbe, ProbeResult
from sni_spoofing.scanner.sni_provider import SNIProvider, DEFAULT_SNI_DOMAINS
from sni_spoofing.scanner.engine import ScanEngine, ScanConfig


class TestCloudflareIPPool(unittest.TestCase):
    """Tests for the Cloudflare IP range pool."""

    def test_load_defaults(self):
        """Loading defaults should populate at least 10 networks."""
        pool = CloudflareIPPool()
        pool.load_defaults()
        self.assertGreater(pool.network_count, 10)
        self.assertGreater(pool.total_hosts, 1000)

    def test_seed_ips_in_cloudflare_ranges(self):
        """All seed IPs must belong to Cloudflare ranges."""
        pool = CloudflareIPPool()
        pool.load_defaults()
        for ip in CLOUDFLARE_SEED_IPS:
            self.assertTrue(
                pool.contains(ip),
                f"Seed IP {ip} is NOT in any Cloudflare range!",
            )

    def test_seed_ips_not_empty(self):
        """Seed list must have a meaningful number of IPs."""
        self.assertGreater(len(CLOUDFLARE_SEED_IPS), 50)

    def test_sample_with_seeds(self):
        """sample_with_seeds should return seed IPs first."""
        pool = CloudflareIPPool()
        pool.load_defaults()
        ips = pool.sample_with_seeds(10)
        self.assertEqual(len(ips), 10)
        # At least some should be from the seed list
        seed_set = set(CLOUDFLARE_SEED_IPS)
        seed_count = sum(1 for ip in ips if ip in seed_set)
        self.assertGreater(seed_count, 0)

    def test_sample_with_seeds_respects_blacklist(self):
        """Blacklisted seed IPs should be skipped."""
        pool = CloudflareIPPool()
        pool.load_defaults()
        for ip in CLOUDFLARE_SEED_IPS[:5]:
            pool.blacklist_ip(ip)
        ips = pool.sample_with_seeds(20)
        for ip in CLOUDFLARE_SEED_IPS[:5]:
            self.assertNotIn(ip, ips)

    def test_random_ip_from_defaults(self):
        """Random IPs should be valid IPv4 addresses in Cloudflare ranges."""
        pool = CloudflareIPPool()
        pool.load_defaults()
        ip = pool.random_ip()
        self.assertTrue(pool.contains(ip), f"{ip} not in Cloudflare ranges")

    def test_sample_unique(self):
        """Sample should return unique IPs."""
        pool = CloudflareIPPool()
        pool.load_defaults()
        ips = pool.sample(50)
        self.assertEqual(len(ips), 50)
        self.assertEqual(len(set(ips)), 50)

    def test_sample_within_ranges(self):
        """All sampled IPs should be within Cloudflare ranges."""
        pool = CloudflareIPPool()
        pool.load_defaults()
        for ip in pool.sample(20):
            self.assertTrue(pool.contains(ip), f"{ip} not in Cloudflare ranges")

    def test_blacklist(self):
        """Blacklisted IPs should not be returned (probabilistic check)."""
        pool = CloudflareIPPool()
        pool.add_ranges(["192.0.2.0/30"])  # Only 2 host IPs: .1 and .2
        pool.blacklist_ip("192.0.2.1")
        # With only 2 hosts and 1 blacklisted, most samples should be .2
        ips = [pool.random_ip() for _ in range(50)]
        self.assertNotIn("192.0.2.1", ips)

    def test_contains_valid(self):
        pool = CloudflareIPPool()
        pool.load_defaults()
        # 104.16.0.0/13 includes 104.16.x.x
        self.assertTrue(pool.contains("104.16.1.1"))
        self.assertFalse(pool.contains("8.8.8.8"))
        self.assertFalse(pool.contains("not-an-ip"))

    def test_add_custom_ranges(self):
        pool = CloudflareIPPool()
        pool.add_ranges(["10.0.0.0/24", "10.0.1.0/24"])
        self.assertEqual(pool.network_count, 2)
        ip = pool.random_ip()
        self.assertTrue(ip.startswith("10.0."))

    def test_add_invalid_range(self):
        """Invalid CIDR strings should be skipped without crashing."""
        pool = CloudflareIPPool()
        pool.add_ranges(["not-a-cidr", "10.0.0.0/24"])
        self.assertEqual(pool.network_count, 1)

    def test_empty_pool_raises(self):
        pool = CloudflareIPPool()
        with self.assertRaises(RuntimeError):
            pool.random_ip()


class TestProbeResult(unittest.TestCase):
    """Tests for the ProbeResult data class."""

    def test_alive_when_both_pass(self):
        r = ProbeResult(ip="1.1.1.1", tcp_ok=True, tls_ok=True)
        self.assertTrue(r.alive)

    def test_not_alive_when_tcp_fails(self):
        r = ProbeResult(ip="1.1.1.1", tcp_ok=False, tls_ok=True)
        self.assertFalse(r.alive)

    def test_not_alive_when_tls_fails(self):
        r = ProbeResult(ip="1.1.1.1", tcp_ok=True, tls_ok=False)
        self.assertFalse(r.alive)

    def test_score_inf_when_dead(self):
        r = ProbeResult(ip="1.1.1.1", tcp_ok=False, tls_ok=False)
        self.assertEqual(r.score, float("inf"))

    def test_score_combines_latencies(self):
        r = ProbeResult(
            ip="1.1.1.1", tcp_ok=True, tls_ok=True,
            tcp_ms=50.0, tls_ms=100.0,
        )
        self.assertAlmostEqual(r.score, 150.0)

    def test_score_rewards_download(self):
        r1 = ProbeResult(
            ip="1.1.1.1", tcp_ok=True, tls_ok=True,
            tcp_ms=50.0, tls_ms=100.0,
        )
        r2 = ProbeResult(
            ip="2.2.2.2", tcp_ok=True, tls_ok=True,
            tcp_ms=50.0, tls_ms=100.0,
            download_ok=True, download_speed=100000.0,
        )
        self.assertLess(r2.score, r1.score)

    def test_summary_format(self):
        r = ProbeResult(
            ip="104.16.1.1", tcp_ok=True, tls_ok=True,
            tcp_ms=42.0, tls_ms=88.0,
        )
        s = r.summary()
        self.assertIn("104.16.1.1", s)
        self.assertIn("tcp=42ms", s)
        self.assertIn("tls=88ms", s)

    def test_summary_failure(self):
        r = ProbeResult(ip="1.2.3.4", error="tcp_timeout")
        s = r.summary()
        self.assertIn("FAIL", s)
        self.assertIn("tcp_timeout", s)


class TestSNIProvider(unittest.TestCase):
    """Tests for the SNI domain provider."""

    def test_defaults_loaded(self):
        p = SNIProvider()
        self.assertGreater(len(p.domains), 5)

    def test_custom_domains(self):
        p = SNIProvider(domains=["a.com", "b.com", "c.com"])
        self.assertEqual(len(p.domains), 3)
        self.assertIn("a.com", p.domains)

    def test_get_best_returns_domain(self):
        p = SNIProvider(domains=["x.com", "y.com"])
        best = p.get_best()
        self.assertIn(best, ["x.com", "y.com"])

    def test_mark_failed_rotation(self):
        p = SNIProvider(domains=["a.com", "b.com"], max_failures=2)
        # Fail a.com twice
        p.mark_failed("a.com")
        p.mark_failed("a.com")
        # a.com should be dead now
        self.assertNotIn("a.com", p.alive_domains)
        # get_best should return b.com
        self.assertEqual(p.get_best(), "b.com")

    def test_mark_success_resets_failures(self):
        p = SNIProvider(domains=["a.com", "b.com"], max_failures=3)
        p.mark_failed("a.com")
        p.mark_failed("a.com")
        p.mark_success("a.com", latency_ms=50.0)
        self.assertIn("a.com", p.alive_domains)

    def test_all_failed_resets(self):
        """When all domains fail, provider should reset and return one."""
        p = SNIProvider(domains=["a.com"], max_failures=1)
        p.mark_failed("a.com")
        # All dead -- get_best should reset
        best = p.get_best()
        self.assertEqual(best, "a.com")

    def test_get_next_excludes(self):
        p = SNIProvider(domains=["a.com", "b.com", "c.com"])
        p.mark_success("a.com", latency_ms=10.0)
        p.mark_success("b.com", latency_ms=20.0)
        p.mark_success("c.com", latency_ms=30.0)
        nxt = p.get_next(exclude="a.com")
        self.assertNotEqual(nxt, "a.com")

    def test_add_domain(self):
        p = SNIProvider(domains=["a.com"])
        p.add_domain("new.com")
        self.assertIn("new.com", p.domains)

    def test_remove_domain(self):
        p = SNIProvider(domains=["a.com", "b.com"])
        p.remove_domain("a.com")
        self.assertNotIn("a.com", p.domains)

    def test_status_table(self):
        p = SNIProvider(domains=["x.com"])
        p.mark_success("x.com", latency_ms=42.0)
        table = p.status_table()
        self.assertIn("x.com", table)
        self.assertIn("42ms", table)


class TestScanConfig(unittest.TestCase):
    """Tests for scan configuration."""

    def test_default_values(self):
        cfg = ScanConfig()
        self.assertEqual(cfg.scan_count, 100)
        self.assertEqual(cfg.concurrency, 16)
        self.assertEqual(cfg.timeout, 4.0)
        self.assertFalse(cfg.test_download)
        self.assertEqual(cfg.port, 443)

    def test_custom_values(self):
        cfg = ScanConfig(scan_count=200, concurrency=32, timeout=2.0)
        self.assertEqual(cfg.scan_count, 200)
        self.assertEqual(cfg.concurrency, 32)
        self.assertEqual(cfg.timeout, 2.0)


class TestScanEngine(unittest.TestCase):
    """Tests for the scan engine."""

    def test_engine_construction(self):
        cfg = ScanConfig(scan_count=10, concurrency=2)
        engine = ScanEngine(cfg)
        self.assertIsNotNone(engine.pool)
        self.assertGreater(engine.pool.network_count, 0)

    def test_engine_with_custom_ranges(self):
        cfg = ScanConfig(
            scan_count=5,
            custom_ranges=["10.0.0.0/24"],
        )
        engine = ScanEngine(cfg)
        self.assertTrue(engine.pool.contains("10.0.0.1"))

    def test_report_failure_blacklists(self):
        cfg = ScanConfig(scan_count=5)
        engine = ScanEngine(cfg)
        # Add a fake result
        from sni_spoofing.scanner.probe import ProbeResult
        r = ProbeResult(ip="1.2.3.4", tcp_ok=True, tls_ok=True, tcp_ms=10, tls_ms=20)
        engine._results = [r]
        engine.report_failure("1.2.3.4")
        self.assertEqual(engine.get_best_ip(), None)

    def test_results_table_format(self):
        cfg = ScanConfig(scan_count=5)
        engine = ScanEngine(cfg)
        table = engine.results_table()
        self.assertIn("IP", table)
        self.assertIn("TCP", table)

    def test_cache_roundtrip(self):
        """Test saving and loading scan cache."""
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            cache_path = f.name

        try:
            cfg = ScanConfig(scan_count=5, cache_path=cache_path)
            engine = ScanEngine(cfg)
            from sni_spoofing.scanner.probe import ProbeResult
            engine._results = [
                ProbeResult(
                    ip="104.16.1.1", tcp_ok=True, tls_ok=True,
                    tcp_ms=50, tls_ms=100,
                ),
            ]
            engine._save_cache()

            # Load in a new engine
            engine2 = ScanEngine(cfg)
            self.assertEqual(len(engine2._results), 1)
            self.assertEqual(engine2._results[0].ip, "104.16.1.1")
        finally:
            os.unlink(cache_path)

    def test_get_top_ips(self):
        cfg = ScanConfig(scan_count=5)
        engine = ScanEngine(cfg)
        from sni_spoofing.scanner.probe import ProbeResult
        engine._results = [
            ProbeResult(ip=f"10.0.0.{i}", tcp_ok=True, tls_ok=True, tcp_ms=i*10, tls_ms=i*20)
            for i in range(1, 6)
        ]
        top = engine.get_top_ips(3)
        self.assertEqual(len(top), 3)
        self.assertEqual(top[0], "10.0.0.1")


class TestIPProbe(unittest.TestCase):
    """Tests for the IP probe (non-network tests)."""

    def test_probe_construction(self):
        probe = IPProbe(timeout=2.0, test_download=True)
        self.assertEqual(probe.timeout, 2.0)
        self.assertTrue(probe.test_download)

    def test_probe_unreachable_ip(self):
        """Probing a non-routable IP should fail fast."""
        probe = IPProbe(timeout=1.0)
        result = probe.check("192.0.2.1", 443, "test.com")
        self.assertFalse(result.alive)
        self.assertIn("tcp_", result.error)


class TestConnectionTracker(unittest.TestCase):
    """Tests for the failover connection tracker."""

    def test_track_failures(self):
        from sni_spoofing.forwarder import ConnectionTracker, FAILOVER_THRESHOLD
        tracker = ConnectionTracker()
        for _ in range(FAILOVER_THRESHOLD):
            tracker.record_failure("10.0.0.1")
        self.assertTrue(tracker.should_failover("10.0.0.1"))

    def test_success_resets(self):
        from sni_spoofing.forwarder import ConnectionTracker
        tracker = ConnectionTracker()
        tracker.record_failure("10.0.0.1")
        tracker.record_failure("10.0.0.1")
        tracker.record_success("10.0.0.1")
        self.assertFalse(tracker.should_failover("10.0.0.1"))


class TestModuleImports(unittest.TestCase):
    """Verify all new modules import correctly."""

    def test_scanner_package(self):
        from sni_spoofing.scanner import (
            CloudflareIPPool,
            IPProbe,
            ProbeResult,
            ScanEngine,
            ScanConfig,
            SNIProvider,
        )

    def test_scanner_ip_ranges(self):
        from sni_spoofing.scanner.ip_ranges import CLOUDFLARE_IPV4_RANGES
        self.assertIsInstance(CLOUDFLARE_IPV4_RANGES, list)
        self.assertGreater(len(CLOUDFLARE_IPV4_RANGES), 10)

    def test_sni_defaults(self):
        from sni_spoofing.scanner.sni_provider import DEFAULT_SNI_DOMAINS
        self.assertIsInstance(DEFAULT_SNI_DOMAINS, list)
        self.assertGreater(len(DEFAULT_SNI_DOMAINS), 15)

    def test_sni_defaults_no_non_cloudflare_domains(self):
        """Default SNI list must NOT contain known non-Cloudflare domains."""
        from sni_spoofing.scanner.sni_provider import DEFAULT_SNI_DOMAINS
        non_cf = {
            "dl.google.com", "cdn.shopify.com", "www.figma.com",
            "fonts.googleapis.com", "cdn.jsdelivr.net", "www.notion.so",
            "www.zoom.us",
        }
        for d in DEFAULT_SNI_DOMAINS:
            self.assertNotIn(
                d, non_cf,
                f"{d} is NOT behind Cloudflare and should not be in defaults!",
            )

    def test_seed_ips_importable(self):
        from sni_spoofing.scanner import CLOUDFLARE_SEED_IPS
        self.assertIsInstance(CLOUDFLARE_SEED_IPS, list)
        self.assertGreater(len(CLOUDFLARE_SEED_IPS), 50)


if __name__ == "__main__":
    unittest.main(verbosity=2)
