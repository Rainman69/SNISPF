"""Scan engine -- orchestrates IP scanning with concurrent workers.

Pulls random IPs from the Cloudflare pool, probes them in parallel
with configurable concurrency, ranks results by latency and speed,
and returns the best candidates.

Designed to run both as a one-shot scan and as a background daemon
that continuously refreshes the best-IP list.
"""

import asyncio
import concurrent.futures
import json
import logging
import os
import time
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, List, Optional, Set

from .ip_ranges import CloudflareIPPool
from .probe import IPProbe, ProbeResult
from .sni_provider import SNIProvider

logger = logging.getLogger("snispf")


@dataclass
class ScanConfig:
    """Configuration for a scan run."""

    # How many IPs to test per round
    scan_count: int = 100
    # Maximum parallel workers
    concurrency: int = 16
    # Per-probe timeout (seconds)
    timeout: float = 4.0
    # Also run a small download speed test
    test_download: bool = False
    # Target port
    port: int = 443
    # Use specific SNI for probing (empty = use SNIProvider)
    sni: str = ""
    # Use custom CIDR ranges (empty = Cloudflare defaults)
    custom_ranges: List[str] = field(default_factory=list)
    # Fetch live ranges from Cloudflare
    fetch_live_ranges: bool = False
    # Path to save/load cached results
    cache_path: str = ""
    # How many top results to keep
    top_n: int = 10
    # Background scan interval (seconds, 0 = one-shot only)
    rescan_interval: float = 0.0


class ScanEngine:
    """Concurrent Cloudflare IP scanner with ranking and failover.

    Usage (one-shot)::

        engine = ScanEngine(ScanConfig(scan_count=50, concurrency=8))
        results = engine.scan_once()
        for r in results[:5]:
            print(r.summary())

    Usage (background)::

        engine = ScanEngine(config)
        engine.start_background()
        best = engine.get_best_ip()   # non-blocking, returns cached best
        engine.stop_background()
    """

    def __init__(self, config: ScanConfig, sni_provider: Optional[SNIProvider] = None):
        self.config = config
        self.sni_provider = sni_provider or SNIProvider()

        self.pool = CloudflareIPPool()
        if config.custom_ranges:
            self.pool.add_ranges(config.custom_ranges)
        elif config.fetch_live_ranges:
            if not self.pool.load_from_url():
                self.pool.load_defaults()
        else:
            self.pool.load_defaults()

        # Ranked results (best first)
        self._results: List[ProbeResult] = []
        self._results_lock = threading.Lock()
        self._last_scan: float = 0.0

        # Background scanner
        self._bg_thread: Optional[threading.Thread] = None
        self._bg_stop = threading.Event()

        # Load cached results if available
        if config.cache_path:
            self._load_cache()

    # ── One-shot scan ─────────────────────────────────────────────────

    def scan_once(self, progress_cb: Optional[Callable] = None) -> List[ProbeResult]:
        """Scan *config.scan_count* random Cloudflare IPs.

        Returns results sorted by score (best first).  Optionally calls
        *progress_cb(done, total)* as probes finish.

        Uses a thread pool for parallelism since each probe is
        I/O-bound (TCP + TLS).
        """
        ips = self.pool.sample(self.config.scan_count)
        sni = self.config.sni or self.sni_provider.get_best()

        probe = IPProbe(
            timeout=self.config.timeout,
            test_download=self.config.test_download,
        )

        results: List[ProbeResult] = []
        done_count = 0
        total = len(ips)

        logger.info(
            "Scanning %d Cloudflare IPs (workers=%d, sni=%s, timeout=%.1fs)",
            total, self.config.concurrency, sni, self.config.timeout,
        )

        t_start = time.monotonic()

        with concurrent.futures.ThreadPoolExecutor(
            max_workers=self.config.concurrency
        ) as executor:
            futures = {
                executor.submit(probe.check, ip, self.config.port, sni): ip
                for ip in ips
            }
            for future in concurrent.futures.as_completed(futures):
                done_count += 1
                try:
                    result = future.result()
                    results.append(result)
                    if result.alive:
                        logger.debug(
                            "[%d/%d] OK  %s", done_count, total, result.summary()
                        )
                    else:
                        logger.debug(
                            "[%d/%d] FAIL %s", done_count, total, result.summary()
                        )
                except Exception as exc:
                    ip = futures[future]
                    logger.debug("[%d/%d] ERR %s: %s", done_count, total, ip, exc)

                if progress_cb:
                    try:
                        progress_cb(done_count, total)
                    except Exception:
                        pass

        elapsed = time.monotonic() - t_start

        # Sort by score (lower = better)
        results.sort(key=lambda r: r.score)
        alive_count = sum(1 for r in results if r.alive)

        logger.info(
            "Scan complete: %d/%d alive, best=%s (%.1fs)",
            alive_count,
            total,
            results[0].summary() if alive_count else "none",
            elapsed,
        )

        # Keep only top-N and update internal state
        top = results[:self.config.top_n]
        with self._results_lock:
            self._results = top
            self._last_scan = time.monotonic()

        if self.config.cache_path:
            self._save_cache()

        return results

    # ── Best-IP access ────────────────────────────────────────────────

    def get_best_ip(self) -> Optional[str]:
        """Return the best IP from the last scan, or ``None``."""
        with self._results_lock:
            for r in self._results:
                if r.alive:
                    return r.ip
        return None

    def get_best_result(self) -> Optional[ProbeResult]:
        with self._results_lock:
            for r in self._results:
                if r.alive:
                    return r
        return None

    def get_top_ips(self, n: int = 5) -> List[str]:
        """Return up to *n* best IPs."""
        with self._results_lock:
            return [r.ip for r in self._results if r.alive][:n]

    def get_results(self) -> List[ProbeResult]:
        with self._results_lock:
            return list(self._results)

    def report_failure(self, ip: str):
        """Called when a connection through *ip* is blocked at runtime.

        Blacklists the IP and removes it from cached results.
        """
        self.pool.blacklist_ip(ip)
        with self._results_lock:
            self._results = [r for r in self._results if r.ip != ip]
        logger.info("IP %s blacklisted after runtime failure", ip)

    # ── Background scanner ────────────────────────────────────────────

    def start_background(self):
        """Start periodic background scanning."""
        if self._bg_thread is not None:
            return
        self._bg_stop.clear()
        self._bg_thread = threading.Thread(
            target=self._bg_loop, daemon=True, name="snispf-scanner"
        )
        self._bg_thread.start()
        logger.info(
            "Background scanner started (interval=%ds)",
            int(self.config.rescan_interval),
        )

    def stop_background(self):
        """Stop background scanning."""
        self._bg_stop.set()
        if self._bg_thread:
            self._bg_thread.join(timeout=5.0)
            self._bg_thread = None
        logger.info("Background scanner stopped")

    def _bg_loop(self):
        # Run an initial scan immediately
        try:
            self.scan_once()
        except Exception as exc:
            logger.error("Background scan error: %s", exc)

        interval = max(self.config.rescan_interval, 30.0)
        while not self._bg_stop.wait(timeout=interval):
            try:
                self.scan_once()
            except Exception as exc:
                logger.error("Background scan error: %s", exc)

    # ── Cache persistence ─────────────────────────────────────────────

    def _save_cache(self):
        try:
            data = []
            with self._results_lock:
                for r in self._results:
                    data.append({
                        "ip": r.ip,
                        "port": r.port,
                        "sni": r.sni,
                        "tcp_ms": r.tcp_ms,
                        "tls_ms": r.tls_ms,
                        "download_speed": r.download_speed,
                        "alive": r.alive,
                    })
            path = Path(self.config.cache_path)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(data, indent=2))
        except Exception as exc:
            logger.debug("Cache save failed: %s", exc)

    def _load_cache(self):
        try:
            path = Path(self.config.cache_path)
            if not path.exists():
                return
            raw = json.loads(path.read_text())
            results = []
            for entry in raw:
                r = ProbeResult(
                    ip=entry["ip"],
                    port=entry.get("port", 443),
                    sni=entry.get("sni", ""),
                    tcp_ms=entry.get("tcp_ms", -1),
                    tls_ms=entry.get("tls_ms", -1),
                    download_speed=entry.get("download_speed", 0),
                    tcp_ok=entry.get("alive", False),
                    tls_ok=entry.get("alive", False),
                    download_ok=entry.get("download_speed", 0) > 0,
                )
                results.append(r)
            with self._results_lock:
                self._results = results
            logger.debug("Loaded %d cached scan results", len(results))
        except Exception as exc:
            logger.debug("Cache load failed: %s", exc)

    # ── Utility ───────────────────────────────────────────────────────

    def results_table(self) -> str:
        """Formatted results table for display."""
        lines = [
            f"{'#':>3}  {'IP':<18} {'TCP':>8} {'TLS':>8} "
            f"{'Speed':>10} {'Score':>8} {'Status':<6}"
        ]
        lines.append("-" * 70)
        with self._results_lock:
            for i, r in enumerate(self._results, 1):
                tcp_str = f"{r.tcp_ms:.0f}ms" if r.tcp_ok else "-"
                tls_str = f"{r.tls_ms:.0f}ms" if r.tls_ok else "-"
                if r.download_ok and r.download_speed > 0:
                    speed_str = f"{r.download_speed / 1024:.1f}KB/s"
                else:
                    speed_str = "-"
                score_str = f"{r.score:.0f}" if r.alive else "fail"
                status = "OK" if r.alive else "FAIL"
                lines.append(
                    f"{i:>3}  {r.ip:<18} {tcp_str:>8} {tls_str:>8} "
                    f"{speed_str:>10} {score_str:>8} {status:<6}"
                )
        return "\n".join(lines)
