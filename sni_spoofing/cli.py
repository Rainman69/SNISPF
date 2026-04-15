"""
SNISPF - Cross-platform SNI spoofing and DPI bypass tool.

Works on Windows, macOS, and Linux without requiring kernel drivers.
On Linux with root, enables raw packet injection for the seq_id trick.
Includes an internal Cloudflare IP scanner for automatic endpoint
selection and failover.

Usage:
    snispf --config config.json
    snispf --listen 0.0.0.0:40443 --connect 104.18.38.202:443 --sni cdnjs.cloudflare.com
    snispf --scan --scan-count 100 --sni cdnjs.cloudflare.com
    snispf --auto
"""

import argparse
import asyncio
import json
import logging
import os
import platform
import signal
import sys
from pathlib import Path

# Add parent to path for direct script execution
if __name__ == "__main__":
    sys.path.insert(0, str(Path(__file__).parent.parent))

from sni_spoofing import __version__
from sni_spoofing.bypass import (
    BypassStrategy,
    CombinedBypass,
    FakeSNIBypass,
    FragmentBypass,
    RawInjector,
    is_raw_available,
)
from sni_spoofing.forwarder import start_server
from sni_spoofing.utils import (
    check_platform_capabilities,
    get_default_interface_ipv4,
    is_valid_ip,
    is_valid_port,
    resolve_host,
)

# ─── Banner ──────────────────────────────────────────────────────────────────

BANNER = r"""
 ███████╗███╗   ██╗██╗███████╗██████╗ ███████╗
 ██╔════╝████╗  ██║██║██╔════╝██╔══██╗██╔════╝
 ███████╗██╔██╗ ██║██║███████╗██████╔╝█████╗
 ╚════██║██║╚██╗██║██║╚════██║██╔═══╝ ██╔══╝
 ███████║██║ ╚████║██║███████║██║     ██║
 ╚══════╝╚═╝  ╚═══╝╚═╝╚══════╝╚═╝     ╚═╝

     ┌──────────────────────────────────────────────────────────────────┐
     │  SNISPF - Cross-Platform DPI Bypass Tool                        │
     │  SNI Spoofing + TLS Fragmentation + Auto Scanner                │
     │  Works on Windows / macOS / Linux                               │
     │  https://github.com/Rainman69/SNISPF                            │
     └──────────────────────────────────────────────────────────────────┘
"""

# ─── Logging ─────────────────────────────────────────────────────────────────

def setup_logging(verbose: bool = False, quiet: bool = False):
    """Configure logging with deduplication guard."""
    if quiet:
        level = logging.WARNING
    elif verbose:
        level = logging.DEBUG
    else:
        level = logging.INFO

    formatter = logging.Formatter(
        "%(asctime)s │ %(levelname)-7s │ %(message)s",
        datefmt="%H:%M:%S",
    )

    logger = logging.getLogger("snispf")
    # Prevent handler accumulation on repeated calls
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(formatter)
        logger.addHandler(handler)
    logger.setLevel(level)

    return logger


# ─── Config ──────────────────────────────────────────────────────────────────

DEFAULT_CONFIG = {
    "LISTEN_HOST": "0.0.0.0",
    "LISTEN_PORT": 40443,
    "CONNECT_IP": "104.18.38.202",
    "CONNECT_PORT": 443,
    "FAKE_SNI": "cdnjs.cloudflare.com",
    "BYPASS_METHOD": "fragment",
    "FRAGMENT_STRATEGY": "sni_split",
    "FRAGMENT_DELAY": 0.1,
    "USE_TTL_TRICK": False,
    "FAKE_SNI_METHOD": "prefix_fake",
    # Scanner settings
    "SCANNER_ENABLED": False,
    "SCANNER_COUNT": 100,
    "SCANNER_CONCURRENCY": 16,
    "SCANNER_TIMEOUT": 4.0,
    "SCANNER_TEST_DOWNLOAD": False,
    "SCANNER_RESCAN_INTERVAL": 0,
    "SCANNER_CACHE": "",
    "SCANNER_TOP_N": 10,
    "SCANNER_CUSTOM_RANGES": [],
    # SNI domain pool
    "SNI_DOMAINS": [],
}


def load_config(config_path: str) -> dict:
    """Load configuration from JSON file."""
    try:
        with open(config_path, "r") as f:
            user_config = json.load(f)

        # Merge with defaults
        config = DEFAULT_CONFIG.copy()
        config.update(user_config)
        return config
    except FileNotFoundError:
        print(f"Error: Config file not found: {config_path}")
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"Error: Invalid JSON in config file: {e}")
        sys.exit(1)


def generate_config(output_path: str):
    """Generate a default configuration file."""
    config = {
        "LISTEN_HOST": "0.0.0.0",
        "LISTEN_PORT": 40443,
        "CONNECT_IP": "104.18.38.202",
        "CONNECT_PORT": 443,
        "FAKE_SNI": "cdnjs.cloudflare.com",
        "BYPASS_METHOD": "fragment",
        "FRAGMENT_STRATEGY": "sni_split",
        "FRAGMENT_DELAY": 0.1,
        "USE_TTL_TRICK": False,
        "FAKE_SNI_METHOD": "prefix_fake",
        "SCANNER_ENABLED": False,
        "SCANNER_COUNT": 100,
        "SCANNER_CONCURRENCY": 16,
        "SCANNER_TIMEOUT": 4.0,
        "SCANNER_TEST_DOWNLOAD": False,
        "SCANNER_RESCAN_INTERVAL": 0,
        "SCANNER_CACHE": "",
        "SCANNER_TOP_N": 10,
        "SCANNER_CUSTOM_RANGES": [],
        "SNI_DOMAINS": [],
    }

    with open(output_path, "w") as f:
        json.dump(config, f, indent=2)

    print(f"Generated default config: {output_path}")
    print(json.dumps(config, indent=2))


# ─── Strategy Builder ────────────────────────────────────────────────────────

def build_strategy(config: dict, raw_injector=None) -> BypassStrategy:
    """Build the appropriate bypass strategy from config.

    Available methods:
    - "fragment": Fragment TLS ClientHello at SNI boundary
    - "fake_sni": Send fake ClientHello with spoofed SNI (needs raw sockets
      for the seq_id trick; falls back to fragmentation without them)
    - "combined": Both fragmentation and fake SNI (recommended)
    """
    method = config.get("BYPASS_METHOD", "fragment").lower()

    if method == "fragment":
        return FragmentBypass(
            strategy=config.get("FRAGMENT_STRATEGY", "sni_split"),
            fragment_delay=config.get("FRAGMENT_DELAY", 0.1),
        )
    elif method == "fake_sni":
        return FakeSNIBypass(
            method=config.get("FAKE_SNI_METHOD", "prefix_fake"),
            raw_injector=raw_injector,
        )
    elif method == "combined":
        return CombinedBypass(
            fragment_strategy=config.get("FRAGMENT_STRATEGY", "sni_split"),
            use_ttl_trick=config.get("USE_TTL_TRICK", False),
            fragment_delay=config.get("FRAGMENT_DELAY", 0.1),
            raw_injector=raw_injector,
        )
    else:
        print(f"Warning: Unknown bypass method '{method}', using 'fragment'")
        return FragmentBypass()


# ─── CLI ─────────────────────────────────────────────────────────────────────

def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        prog="snispf",
        description=(
            "SNISPF - Cross-platform DPI bypass tool.\n\n"
            "This tool forwards TCP connections while applying DPI bypass\n"
            "techniques (SNI spoofing, TLS fragmentation) to circumvent\n"
            "internet censorship.\n\n"
            "Includes an internal Cloudflare IP scanner that automatically\n"
            "finds the fastest clean IPs and rotates when they are blocked."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  %(prog)s --config config.json\n"
            "  %(prog)s -l 0.0.0.0:40443 -c 104.18.38.202:443 -s cdnjs.cloudflare.com\n"
            "  %(prog)s -l :40443 -c 104.18.38.202:443 -s www.speedtest.net -m combined\n"
            "  %(prog)s --generate-config my_config.json\n"
            "\nScanner Mode:\n"
            "  %(prog)s --scan                        Run a one-shot IP scan\n"
            "  %(prog)s --scan --scan-count 200       Scan 200 IPs\n"
            "  %(prog)s --scan --download              Include download speed tests\n"
            "\nAuto Mode (scanner + proxy):\n"
            "  %(prog)s --auto                        Scan, pick best IP, start proxy\n"
            "  %(prog)s --auto --rescan 300           Re-scan every 5 minutes\n"
            "  %(prog)s --auto --sni-list a.com,b.com Custom SNI domains\n"
            "\nBypass Methods:\n"
            "  fragment   - Fragment TLS ClientHello at SNI boundary (default)\n"
            "  fake_sni   - Inject fake ClientHello (needs root for seq_id trick)\n"
            "  combined   - Both fragmentation and fake SNI (most effective)\n"
            "\nhttps://github.com/Rainman69/SNISPF"
        ),
    )

    # Config file
    parser.add_argument(
        "--config", "-C",
        help="Path to JSON config file",
    )
    parser.add_argument(
        "--generate-config",
        metavar="PATH",
        help="Generate a default config file and exit",
    )

    # Connection settings
    parser.add_argument(
        "--listen", "-l",
        metavar="HOST:PORT",
        help="Listen address (default: 0.0.0.0:40443)",
    )
    parser.add_argument(
        "--connect", "-c",
        metavar="IP:PORT",
        help="Target server address (default: 104.18.38.202:443)",
    )
    parser.add_argument(
        "--sni", "-s",
        metavar="HOSTNAME",
        help="Fake SNI hostname (default: cdnjs.cloudflare.com)",
    )

    # Bypass settings
    parser.add_argument(
        "--method", "-m",
        choices=["fragment", "fake_sni", "combined"],
        help="Bypass method (default: fragment)",
    )
    parser.add_argument(
        "--fragment-strategy",
        choices=["sni_split", "half", "multi", "tls_record_frag"],
        help="Fragment strategy (default: sni_split)",
    )
    parser.add_argument(
        "--fragment-delay",
        type=float,
        metavar="SECONDS",
        help="Delay between fragments in seconds (default: 0.1)",
    )
    parser.add_argument(
        "--ttl-trick",
        action="store_true",
        help="Use IP TTL trick for fake packets (may need privileges)",
    )
    parser.add_argument(
        "--no-raw",
        action="store_true",
        help="Disable raw socket injection even if available",
    )

    # ─── Scanner ──────────────────────────────────────────────────────
    scanner_group = parser.add_argument_group("Scanner Options")
    scanner_group.add_argument(
        "--scan",
        action="store_true",
        help="Run a one-shot Cloudflare IP scan and display results",
    )
    scanner_group.add_argument(
        "--auto",
        action="store_true",
        help="Auto mode: scan for best IP, then start proxy with failover",
    )
    scanner_group.add_argument(
        "--scan-count",
        type=int,
        default=None,
        metavar="N",
        help="Number of IPs to test per scan (default: 100)",
    )
    scanner_group.add_argument(
        "--scan-workers",
        type=int,
        default=None,
        metavar="N",
        help="Parallel scan workers (default: 16)",
    )
    scanner_group.add_argument(
        "--scan-timeout",
        type=float,
        default=None,
        metavar="SECONDS",
        help="Per-probe timeout (default: 4.0)",
    )
    scanner_group.add_argument(
        "--download",
        action="store_true",
        help="Include download speed test during scan",
    )
    scanner_group.add_argument(
        "--rescan",
        type=float,
        default=None,
        metavar="SECONDS",
        help="Re-scan interval in seconds (0 = one-shot, default: 0)",
    )
    scanner_group.add_argument(
        "--scan-cache",
        metavar="PATH",
        help="File to cache scan results across runs",
    )
    scanner_group.add_argument(
        "--sni-list",
        metavar="DOMAINS",
        help="Comma-separated list of SNI domains for rotation",
    )
    scanner_group.add_argument(
        "--ip-ranges",
        metavar="CIDRS",
        help="Comma-separated custom CIDR ranges to scan",
    )
    scanner_group.add_argument(
        "--fetch-ranges",
        action="store_true",
        help="Fetch live Cloudflare IP ranges before scanning",
    )

    # Output settings
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Verbose output (debug logging)",
    )
    parser.add_argument(
        "--quiet", "-q",
        action="store_true",
        help="Quiet output (warnings only)",
    )
    parser.add_argument(
        "--version", "-V",
        action="version",
        version=f"SNISPF {__version__}",
    )
    parser.add_argument(
        "--info",
        action="store_true",
        help="Show platform capabilities and exit",
    )

    return parser.parse_args()


def parse_host_port(addr: str, default_host: str = "0.0.0.0", default_port: int = 443) -> tuple:
    """Parse HOST:PORT string.  Returns (host, port)."""
    if not addr:
        return default_host, default_port

    if addr.startswith(":"):
        try:
            return default_host, int(addr[1:])
        except ValueError:
            print(f"Error: Invalid port in '{addr}'")
            sys.exit(1)

    parts = addr.rsplit(":", 1)
    if len(parts) == 2:
        host = parts[0] or default_host
        try:
            port = int(parts[1])
        except ValueError:
            print(f"Error: Invalid port in '{addr}'")
            sys.exit(1)
        return host, port
    else:
        return parts[0], default_port


def show_platform_info():
    """Display platform capability information."""
    caps = check_platform_capabilities()

    # Also check raw injection availability
    caps["raw_injection"] = is_raw_available()

    print("\n╔══════════════════════════════════════════╗")
    print("║       Platform Capabilities              ║")
    print("╠══════════════════════════════════════════╣")
    for key, value in caps.items():
        status = "✓" if value is True else ("✗" if value is False else str(value))
        print(f"║  {key:<28} {status:>8}  ║")
    print("╚══════════════════════════════════════════╝")

    print("\nRecommended bypass methods for your platform:")
    if caps["raw_injection"]:
        print("  ✓ Raw packet injection available (running as root)")
        print("  ★ Recommended: combined (uses seq_id trick + fragmentation)")
        print("  ★ Also good:   fake_sni (uses seq_id trick)")
    elif caps["raw_socket"]:
        print("  ✓ All methods available (running with sufficient privileges)")
        print("  ★ Recommended: combined --ttl-trick")
    else:
        print("  ✓ fragment    - TLS ClientHello fragmentation")
        print("  ✓ combined    - Fragmentation (fake_sni needs root for seq_id)")
        print("  ★ Recommended: fragment or combined")
        if platform.system() != "Windows":
            print("  ℹ  Run with sudo/root for raw injection (seq_id trick)")

    print("\nScanner:")
    print("  ✓ Cloudflare IP scanner available (no special privileges)")
    print("  ★ Use --scan to find the fastest clean IP")
    print("  ★ Use --auto for automatic IP selection + failover")


# ─── Scanner Command ─────────────────────────────────────────────────────────

def run_scan(args, config: dict, logger):
    """Execute a one-shot scan and print results."""
    from sni_spoofing.scanner import ScanEngine, ScanConfig, SNIProvider

    sni_domains = None
    if args.sni_list:
        sni_domains = [d.strip() for d in args.sni_list.split(",") if d.strip()]
    elif config.get("SNI_DOMAINS"):
        sni_domains = config["SNI_DOMAINS"]

    sni_provider = SNIProvider(domains=sni_domains)

    custom_ranges = []
    if args.ip_ranges:
        custom_ranges = [r.strip() for r in args.ip_ranges.split(",") if r.strip()]
    elif config.get("SCANNER_CUSTOM_RANGES"):
        custom_ranges = config["SCANNER_CUSTOM_RANGES"]

    scan_cfg = ScanConfig(
        scan_count=args.scan_count or config.get("SCANNER_COUNT", 100),
        concurrency=args.scan_workers or config.get("SCANNER_CONCURRENCY", 16),
        timeout=args.scan_timeout or config.get("SCANNER_TIMEOUT", 4.0),
        test_download=args.download or config.get("SCANNER_TEST_DOWNLOAD", False),
        port=config.get("CONNECT_PORT", 443),
        sni=config.get("FAKE_SNI", "") if not sni_domains else "",
        custom_ranges=custom_ranges,
        fetch_live_ranges=args.fetch_ranges,
        cache_path=args.scan_cache or config.get("SCANNER_CACHE", ""),
        top_n=config.get("SCANNER_TOP_N", 10),
    )

    engine = ScanEngine(scan_cfg, sni_provider=sni_provider)

    # Progress display
    def progress(done, total):
        pct = done * 100 // total
        bar = "█" * (pct // 5) + "░" * (20 - pct // 5)
        print(f"\r  Scanning: [{bar}] {done}/{total} ({pct}%)", end="", flush=True)

    results = engine.scan_once(progress_cb=progress)
    print()  # newline after progress bar

    # Display results
    alive = [r for r in results if r.alive]
    print(f"\n{'═' * 80}")
    print(f"  Scan Results: {len(alive)}/{len(results)} IPs alive")
    print(f"{'═' * 80}")
    print(engine.results_table())

    if alive:
        best = alive[0]
        print(f"\n{'─' * 80}")
        print(f"  Best IP: {best.ip}")
        print(f"  TCP Latency: {best.tcp_ms:.0f}ms")
        print(f"  TLS Latency: {best.tls_ms:.0f}ms")
        print(f"  HTTP Validation: {'OK' if best.http_ok else 'FAIL'} ({best.http_ms:.0f}ms)")
        if best.download_ok:
            print(f"  Download Speed: {best.download_speed / 1024:.1f} KB/s")
        print(f"{'─' * 80}")
        print(f"\n  Use this IP with:")
        print(f"    snispf -l :40443 -c {best.ip}:443 -s {best.sni or 'cdnjs.cloudflare.com'}")
    else:
        print("\n  No working IPs found.  Try increasing --scan-count or")
        print("  using a different --sni.")

    return engine


# ─── Main ────────────────────────────────────────────────────────────────────

def main():
    """Main entry point."""
    args = parse_args()

    # Handle special commands
    if args.generate_config:
        generate_config(args.generate_config)
        return

    if args.info:
        print(BANNER)
        show_platform_info()
        return

    # Print banner
    print(BANNER)

    # Setup logging
    logger = setup_logging(verbose=args.verbose, quiet=args.quiet)

    # Load configuration
    if args.config:
        config = load_config(args.config)
    else:
        config = DEFAULT_CONFIG.copy()

    # Override with CLI arguments
    if args.listen:
        host, port = parse_host_port(args.listen, "0.0.0.0", 40443)
        config["LISTEN_HOST"] = host
        config["LISTEN_PORT"] = port

    if args.connect:
        host, port = parse_host_port(args.connect, "104.18.38.202", 443)
        config["CONNECT_IP"] = host
        config["CONNECT_PORT"] = port

    if args.sni:
        config["FAKE_SNI"] = args.sni

    if args.method:
        config["BYPASS_METHOD"] = args.method

    if args.fragment_strategy:
        config["FRAGMENT_STRATEGY"] = args.fragment_strategy

    if args.fragment_delay is not None:
        config["FRAGMENT_DELAY"] = args.fragment_delay

    if args.ttl_trick:
        config["USE_TTL_TRICK"] = True

    # ── Scan-only mode ────────────────────────────────────────────────
    if args.scan and not args.auto:
        run_scan(args, config, logger)
        return

    # ── Validate config ───────────────────────────────────────────────
    if not is_valid_port(config["LISTEN_PORT"]):
        print(f"Error: Invalid listen port: {config['LISTEN_PORT']}")
        sys.exit(1)

    if not is_valid_port(config["CONNECT_PORT"]):
        print(f"Error: Invalid connect port: {config['CONNECT_PORT']}")
        sys.exit(1)

    # Resolve target host if needed
    config["CONNECT_IP"] = resolve_host(config["CONNECT_IP"])

    # Detect interface IP
    interface_ip = get_default_interface_ipv4(config["CONNECT_IP"])
    logger.info(f"Default interface: {interface_ip or 'auto'}")

    # ── Scanner + SNI provider setup ──────────────────────────────────
    scan_engine = None
    sni_provider = None

    auto_mode = args.auto or config.get("SCANNER_ENABLED", False)

    if auto_mode:
        from sni_spoofing.scanner import ScanEngine, ScanConfig, SNIProvider

        sni_domains = None
        if args.sni_list:
            sni_domains = [d.strip() for d in args.sni_list.split(",") if d.strip()]
        elif config.get("SNI_DOMAINS"):
            sni_domains = config["SNI_DOMAINS"]

        sni_provider = SNIProvider(domains=sni_domains)

        custom_ranges = []
        if args.ip_ranges:
            custom_ranges = [r.strip() for r in args.ip_ranges.split(",") if r.strip()]
        elif config.get("SCANNER_CUSTOM_RANGES"):
            custom_ranges = config["SCANNER_CUSTOM_RANGES"]

        rescan = 0.0
        if args.rescan is not None:
            rescan = args.rescan
        elif config.get("SCANNER_RESCAN_INTERVAL", 0) > 0:
            rescan = config["SCANNER_RESCAN_INTERVAL"]

        scan_cfg = ScanConfig(
            scan_count=args.scan_count or config.get("SCANNER_COUNT", 100),
            concurrency=args.scan_workers or config.get("SCANNER_CONCURRENCY", 16),
            timeout=args.scan_timeout or config.get("SCANNER_TIMEOUT", 4.0),
            test_download=args.download or config.get("SCANNER_TEST_DOWNLOAD", False),
            port=config.get("CONNECT_PORT", 443),
            sni=config.get("FAKE_SNI", "") if not sni_domains else "",
            custom_ranges=custom_ranges,
            fetch_live_ranges=getattr(args, "fetch_ranges", False),
            cache_path=args.scan_cache or config.get("SCANNER_CACHE", ""),
            top_n=config.get("SCANNER_TOP_N", 10),
            rescan_interval=rescan,
        )

        scan_engine = ScanEngine(scan_cfg, sni_provider=sni_provider)

        # Run initial scan with progress
        def progress(done, total):
            pct = done * 100 // total
            bar = "█" * (pct // 5) + "░" * (20 - pct // 5)
            print(f"\r  Scanning: [{bar}] {done}/{total} ({pct}%)", end="", flush=True)

        logger.info("Running initial Cloudflare IP scan...")
        results = scan_engine.scan_once(progress_cb=progress)
        print()  # newline after progress bar

        alive = [r for r in results if r.alive]
        if alive:
            best = alive[0]
            logger.info(
                "Best IP: %s (tcp=%dms tls=%dms)",
                best.ip, best.tcp_ms, best.tls_ms,
            )
            # Update config with scanned IP
            config["CONNECT_IP"] = best.ip
        else:
            logger.warning(
                "No working IPs found in scan.  Using fallback: %s",
                config["CONNECT_IP"],
            )

        # Start background rescanning if interval is set
        if rescan > 0:
            scan_engine.start_background()

    # ── Raw injector setup ────────────────────────────────────────────
    raw_injector = None
    use_raw = not getattr(args, 'no_raw', False)
    method = config.get("BYPASS_METHOD", "fragment").lower()

    if use_raw and method in ("fake_sni", "combined") and interface_ip:
        if is_raw_available():
            from sni_spoofing.bypass.raw_injector import RawInjector
            raw_injector = RawInjector(
                local_ip=interface_ip,
                remote_ip=config["CONNECT_IP"],
                remote_port=config["CONNECT_PORT"],
                fake_sni_builder=None,
            )
            if not raw_injector.start():
                logger.warning(
                    "Raw injector failed to start. "
                    "Falling back to fragmentation."
                )
                raw_injector = None
        else:
            if method == "fake_sni":
                logger.warning(
                    "Raw sockets not available (need root/CAP_NET_RAW). "
                    "fake_sni will fall back to fragmentation."
                )
            elif method == "combined":
                logger.info(
                    "Raw sockets not available. "
                    "Using fragmentation-only bypass."
                )

    # Build bypass strategy
    strategy = build_strategy(config, raw_injector=raw_injector)

    # Show configuration summary
    logger.info(f"Platform: {platform.system()} {platform.machine()}")
    logger.info(f"Python: {platform.python_version()}")

    # Setup signal handlers for graceful shutdown
    def signal_handler(sig, frame):
        print("\n\nShutting down...")
        if raw_injector:
            raw_injector.stop()
        if scan_engine:
            scan_engine.stop_background()
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)
    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, signal_handler)

    # Run the server
    try:
        asyncio.run(
            start_server(
                listen_host=config["LISTEN_HOST"],
                listen_port=config["LISTEN_PORT"],
                connect_ip=config["CONNECT_IP"],
                connect_port=config["CONNECT_PORT"],
                fake_sni=config["FAKE_SNI"],
                bypass_strategy=strategy,
                interface_ip=interface_ip,
                raw_injector=raw_injector,
                scan_engine=scan_engine,
                sni_provider=sni_provider,
            )
        )
    except KeyboardInterrupt:
        print("\nShutting down...")
    except PermissionError:
        print(f"\nError: Permission denied on port {config['LISTEN_PORT']}.")
        if config["LISTEN_PORT"] < 1024:
            print("Ports below 1024 require root/administrator privileges.")
            print(f"Try: sudo {sys.argv[0]} ... or use a port >= 1024")
        sys.exit(1)
    except OSError as e:
        if "address already in use" in str(e).lower():
            print(f"\nError: Port {config['LISTEN_PORT']} is already in use.")
            print("Use --listen :PORT to specify a different port.")
        else:
            print(f"\nError: {e}")
        sys.exit(1)
    finally:
        if raw_injector:
            raw_injector.stop()
        if scan_engine:
            scan_engine.stop_background()


if __name__ == "__main__":
    main()
