"""
SNI-Spoofing CLI - Cross-platform DPI bypass tool.

Original Windows tool by @patterniha.
This is a cross-platform CLI reimplementation that works on
Windows, macOS, and Linux without requiring kernel drivers.

Usage:
    sni-spoofing --config config.json
    sni-spoofing --listen 0.0.0.0:40443 --connect 188.114.98.0:443 --sni auth.vercel.com
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
 ███████╗███╗   ██╗██╗    ███████╗██████╗  ██████╗  ██████╗ ███████╗██╗███╗   ██╗ ██████╗
 ██╔════╝████╗  ██║██║    ██╔════╝██╔══██╗██╔═══██╗██╔═══██╗██╔════╝██║████╗  ██║██╔════╝
 ███████╗██╔██╗ ██║██║    ███████╗██████╔╝██║   ██║██║   ██║█████╗  ██║██╔██╗ ██║██║  ███╗
 ╚════██║██║╚██╗██║██║    ╚════██║██╔═══╝ ██║   ██║██║   ██║██╔══╝  ██║██║╚██╗██║██║   ██║
 ███████║██║ ╚████║██║    ███████║██║     ╚██████╔╝╚██████╔╝██║     ██║██║ ╚████║╚██████╔╝
 ╚══════╝╚═╝  ╚═══╝╚═╝    ╚══════╝╚═╝      ╚═════╝  ╚═════╝ ╚═╝     ╚═╝╚═╝  ╚═══╝ ╚═════╝

     ┌──────────────────────────────────────────────────────────────────┐
     │  Original Tool by @patterniha                                   │
     │  CLI Cross-Platform Version (Windows / macOS / Linux)           │
     │  DPI Bypass via SNI Spoofing + TLS Fragmentation                │
     └──────────────────────────────────────────────────────────────────┘
"""

# ─── Logging ─────────────────────────────────────────────────────────────────

def setup_logging(verbose: bool = False, quiet: bool = False):
    """Configure logging."""
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

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(formatter)

    logger = logging.getLogger("sni-spoofing")
    logger.setLevel(level)
    logger.addHandler(handler)

    return logger


# ─── Config ──────────────────────────────────────────────────────────────────

DEFAULT_CONFIG = {
    "LISTEN_HOST": "0.0.0.0",
    "LISTEN_PORT": 40443,
    "CONNECT_IP": "188.114.98.0",
    "CONNECT_PORT": 443,
    "FAKE_SNI": "auth.vercel.com",
    "BYPASS_METHOD": "fragment",
    "FRAGMENT_STRATEGY": "sni_split",
    "FRAGMENT_DELAY": 0.1,
    "USE_TTL_TRICK": False,
    "FAKE_SNI_METHOD": "prefix_fake",
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
        "CONNECT_IP": "188.114.98.0",
        "CONNECT_PORT": 443,
        "FAKE_SNI": "auth.vercel.com",
        "BYPASS_METHOD": "fragment",
        "FRAGMENT_STRATEGY": "sni_split",
        "FRAGMENT_DELAY": 0.1,
        "USE_TTL_TRICK": False,
        "FAKE_SNI_METHOD": "prefix_fake",
    }

    with open(output_path, "w") as f:
        json.dump(config, f, indent=2)

    print(f"Generated default config: {output_path}")
    print(json.dumps(config, indent=2))


# ─── Strategy Builder ────────────────────────────────────────────────────────

def build_strategy(config: dict) -> BypassStrategy:
    """Build the appropriate bypass strategy from config.

    Available methods:
    - "fragment": Fragment TLS ClientHello at SNI boundary
    - "fake_sni": Send fake ClientHello with spoofed SNI
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
        )
    elif method == "combined":
        return CombinedBypass(
            fragment_strategy=config.get("FRAGMENT_STRATEGY", "sni_split"),
            use_ttl_trick=config.get("USE_TTL_TRICK", False),
            fragment_delay=config.get("FRAGMENT_DELAY", 0.1),
        )
    else:
        print(f"Warning: Unknown bypass method '{method}', using 'fragment'")
        return FragmentBypass()


# ─── CLI ─────────────────────────────────────────────────────────────────────

def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        prog="sni-spoofing",
        description=(
            "SNI-Spoofing CLI - Cross-platform DPI bypass tool.\n"
            "Original tool by @patterniha. CLI version for all OS.\n\n"
            "This tool forwards TCP connections while applying DPI bypass\n"
            "techniques (SNI spoofing, TLS fragmentation) to circumvent\n"
            "internet censorship."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  %(prog)s --config config.json\n"
            "  %(prog)s -l 0.0.0.0:40443 -c 188.114.98.0:443 -s auth.vercel.com\n"
            "  %(prog)s -l :40443 -c 188.114.98.0:443 -s dl.google.com -m combined\n"
            "  %(prog)s --generate-config my_config.json\n"
            "\nBypass Methods:\n"
            "  fragment   - Fragment TLS ClientHello at SNI boundary (default)\n"
            "  fake_sni   - Send fake ClientHello with spoofed SNI\n"
            "  combined   - Both fragmentation and fake SNI (most effective)\n"
            "\nFragment Strategies (for fragment/combined methods):\n"
            "  sni_split        - Split in middle of SNI value (default)\n"
            "  half             - Split record in half\n"
            "  multi            - Split into many small fragments\n"
            "  tls_record_frag  - Use TLS-level record fragmentation\n"
            "\nOriginal tool: @patterniha | https://t.me/patterniha"
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
        help="Target server address (default: 188.114.98.0:443)",
    )
    parser.add_argument(
        "--sni", "-s",
        metavar="HOSTNAME",
        help="Fake SNI hostname (default: auth.vercel.com)",
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
        version=f"%(prog)s {__version__}",
    )
    parser.add_argument(
        "--info",
        action="store_true",
        help="Show platform capabilities and exit",
    )

    return parser.parse_args()


def parse_host_port(addr: str, default_host: str = "0.0.0.0", default_port: int = 443) -> tuple:
    """Parse HOST:PORT string."""
    if not addr:
        return default_host, default_port

    if addr.startswith(":"):
        return default_host, int(addr[1:])

    parts = addr.rsplit(":", 1)
    if len(parts) == 2:
        host = parts[0] or default_host
        port = int(parts[1])
        return host, port
    else:
        return parts[0], default_port


def show_platform_info():
    """Display platform capability information."""
    caps = check_platform_capabilities()
    print("\n╔══════════════════════════════════════════╗")
    print("║       Platform Capabilities              ║")
    print("╠══════════════════════════════════════════╣")
    for key, value in caps.items():
        status = "✓" if value is True else ("✗" if value is False else str(value))
        print(f"║  {key:<28} {status:>8}  ║")
    print("╚══════════════════════════════════════════╝")

    print("\nRecommended bypass methods for your platform:")
    if caps["raw_socket"]:
        print("  ✓ All methods available (running with sufficient privileges)")
        print("  ★ Recommended: combined --ttl-trick")
    else:
        print("  ✓ fragment    - TLS ClientHello fragmentation")
        print("  ✓ fake_sni    - Fake SNI prefix method")
        print("  ✓ combined    - Both (without TTL trick)")
        print("  ★ Recommended: combined")
        if platform.system() != "Windows":
            print("  ℹ  Run with sudo/root for TTL trick support")


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
        host, port = parse_host_port(args.connect, "188.114.98.0", 443)
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

    # Validate configuration
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

    # Build bypass strategy
    strategy = build_strategy(config)

    # Show configuration summary
    logger.info(f"Platform: {platform.system()} {platform.machine()}")
    logger.info(f"Python: {platform.python_version()}")

    # Setup signal handlers for graceful shutdown
    def signal_handler(sig, frame):
        print("\n\nShutting down...")
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


if __name__ == "__main__":
    main()
