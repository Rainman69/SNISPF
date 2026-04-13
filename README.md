# SNI-Spoofing CLI

### Cross-Platform DPI Bypass Tool

> **Original tool by [@patterniha](https://t.me/patterniha)**. This repository is a cross-platform CLI conversion of the original Windows-only SNI-Spoofing tool, making it accessible on **Windows, macOS, and Linux**.

```
 ███████╗███╗   ██╗██╗    ███████╗██████╗  ██████╗  ██████╗ ███████╗██╗███╗   ██╗ ██████╗
 ██╔════╝████╗  ██║██║    ██╔════╝██╔══██╗██╔═══██╗██╔═══██╗██╔════╝██║████╗  ██║██╔════╝
 ███████╗██╔██╗ ██║██║    ███████╗██████╔╝██║   ██║██║   ██║█████╗  ██║██╔██╗ ██║██║  ███╗
 ╚════██║██║╚██╗██║██║    ╚════██║██╔═══╝ ██║   ██║██║   ██║██╔══╝  ██║██║╚██╗██║██║   ██║
 ███████║██║ ╚████║██║    ███████║██║     ╚██████╔╝╚██████╔╝██║     ██║██║ ╚████║╚██████╔╝
 ╚══════╝╚═╝  ╚═══╝╚═╝    ╚══════╝╚═╝      ╚═════╝  ╚═════╝ ╚═╝     ╚═╝╚═╝  ╚═══╝ ╚═════╝
```

---

## Credits & Attribution

| | |
|---|---|
| **Original Creator** | **@patterniha** |
| **Original Tool** | SNI-Spoofing by patterniha v1 (Windows) |
| **Telegram** | [@patterniha](https://t.me/patterniha) |
| **Support Original Dev** | `USDT (BEP20): 0x76a768B53Ca77B43086946315f0BDF21156bF424` |

This CLI version is a faithful reimplementation that converts the original Windows-only tool into a cross-platform open-source CLI application. All credit for the concept, technique, and original implementation goes to **@patterniha**.

---

## What Does This Tool Do?

This tool is a **TCP forwarder** that bypasses **Deep Packet Inspection (DPI)** by manipulating TLS handshake packets. It works by:

1. **Listening** on a local port for incoming TCP connections
2. **Intercepting** the TLS ClientHello from your application
3. **Applying bypass techniques** to hide the real SNI (Server Name Indication) from DPI systems
4. **Forwarding** traffic transparently to the target server

### How DPI Bypass Works

```
┌──────────┐    ┌──────────────┐    ┌─────────┐    ┌──────────────┐
│ Your App │───>│ SNI-Spoofing │───>│   DPI   │───>│ Real Server  │
│ (Client) │    │   CLI Tool   │    │ Firewall│    │ (e.g. CF)    │
└──────────┘    └──────────────┘    └─────────┘    └──────────────┘
                       │                  │
                       │  Sends fake/     │ DPI sees fake
                       │  fragmented SNI  │ SNI → allows
                       │                  │ traffic through
```

### Bypass Methods

| Method | Description | Effectiveness | Compatibility |
|--------|-------------|--------------|---------------|
| `fragment` | Splits TLS ClientHello at SNI boundary | High | All platforms |
| `fake_sni` | Sends fake ClientHello with allowed SNI | High | All platforms |
| `combined` | Both fragmentation + fake SNI | Highest | All platforms |

### Fragment Strategies

| Strategy | Description |
|----------|-------------|
| `sni_split` | Split in the middle of the SNI hostname (default, most effective) |
| `half` | Split the TLS record in half |
| `multi` | Split into many small 5-byte fragments |
| `tls_record_frag` | Create multiple valid TLS records from one handshake |

---

## Installation

### Option 1: pip install (Recommended)

```bash
pip install .
```

Then run:
```bash
sni-spoofing --help
```

### Option 2: Run directly (No installation)

```bash
python run.py --help
```

### Option 3: From source

```bash
git clone https://github.com/patterniha/sni-spoofing-cli.git
cd sni-spoofing-cli
python -m sni_spoofing.cli --help
```

---

## Quick Start

### 1. Using config file (compatible with original tool)

```bash
# Generate default config
sni-spoofing --generate-config config.json

# Edit config.json with your settings, then run:
sni-spoofing --config config.json
```

### 2. Using command-line arguments

```bash
# Basic usage with default Cloudflare settings
sni-spoofing -l 0.0.0.0:40443 -c 188.114.98.0:443 -s auth.vercel.com

# With combined bypass method (most effective)
sni-spoofing -l :40443 -c 188.114.98.0:443 -s dl.google.com -m combined

# With verbose logging
sni-spoofing -l :40443 -c 188.114.98.0:443 -s auth.vercel.com -v

# Check platform capabilities
sni-spoofing --info
```

### 3. Configure your application

After starting the tool, configure your application (browser, proxy client, etc.) to connect through:

```
Address: 127.0.0.1
Port: 40443
```

---

## Configuration Reference

### config.json

```json
{
  "LISTEN_HOST": "0.0.0.0",
  "LISTEN_PORT": 40443,
  "CONNECT_IP": "188.114.98.0",
  "CONNECT_PORT": 443,
  "FAKE_SNI": "auth.vercel.com",
  "BYPASS_METHOD": "fragment",
  "FRAGMENT_STRATEGY": "sni_split",
  "FRAGMENT_DELAY": 0.1,
  "USE_TTL_TRICK": false,
  "FAKE_SNI_METHOD": "prefix_fake"
}
```

| Field | Description | Default |
|-------|-------------|---------|
| `LISTEN_HOST` | IP to listen on (`0.0.0.0` = all interfaces) | `0.0.0.0` |
| `LISTEN_PORT` | Local port to listen on | `40443` |
| `CONNECT_IP` | Target server IP to forward to | `188.114.98.0` |
| `CONNECT_PORT` | Target server port | `443` |
| `FAKE_SNI` | Fake hostname for SNI spoofing | `auth.vercel.com` |
| `BYPASS_METHOD` | Bypass method: `fragment`, `fake_sni`, `combined` | `fragment` |
| `FRAGMENT_STRATEGY` | How to fragment: `sni_split`, `half`, `multi`, `tls_record_frag` | `sni_split` |
| `FRAGMENT_DELAY` | Delay between fragments (seconds) | `0.1` |
| `USE_TTL_TRICK` | Use IP TTL trick (needs root/admin) | `false` |
| `FAKE_SNI_METHOD` | Fake SNI sub-method: `prefix_fake`, `ttl_trick`, `disorder` | `prefix_fake` |

### CLI Arguments

```
usage: sni-spoofing [-h] [--config CONFIG] [--generate-config PATH]
                    [--listen HOST:PORT] [--connect IP:PORT] [--sni HOSTNAME]
                    [--method {fragment,fake_sni,combined}]
                    [--fragment-strategy {sni_split,half,multi,tls_record_frag}]
                    [--fragment-delay SECONDS] [--ttl-trick]
                    [--verbose] [--quiet] [--version] [--info]
```

---

## Platform Support

| Platform | Status | Notes |
|----------|--------|-------|
| Windows 10/11 | Fully supported | No admin required for basic methods |
| Linux (Ubuntu, Debian, Fedora, etc.) | Fully supported | Use `sudo` for TTL trick |
| macOS | Fully supported | Use `sudo` for TTL trick |
| Android (Termux) | Supported | Install Python via `pkg install python` |
| WSL / WSL2 | Supported | Standard Linux behavior |

### Key Difference from Original

The original tool used **WinDivert** (Windows kernel driver) for packet-level manipulation. This CLI version uses **pure userspace techniques**:

- **TCP fragmentation** via `TCP_NODELAY` socket option
- **TLS record splitting** at the application layer
- **IP TTL tricks** via standard socket options (no raw sockets needed)

This makes it truly cross-platform without requiring any kernel drivers or special privileges (except for the optional TTL trick).

---

## Architecture

```
sni-spoofing-cli/
├── sni_spoofing/
│   ├── __init__.py          # Package metadata
│   ├── cli.py               # CLI entry point & argument parsing
│   ├── forwarder.py         # Core TCP forwarder (async)
│   ├── bypass/
│   │   ├── __init__.py      # Strategy exports
│   │   ├── base.py          # Abstract strategy base
│   │   ├── fragment.py      # TLS fragmentation bypass
│   │   ├── fake_sni.py      # Fake SNI bypass
│   │   └── combined.py      # Combined strategy
│   ├── tls/
│   │   ├── __init__.py      # TLS ClientHello builder/parser
│   │   └── fragment.py      # TLS record fragmentation
│   └── utils/
│       └── __init__.py      # Network utilities
├── tests/
│   └── test_tls.py          # Unit tests
├── config.json              # Default configuration
├── run.py                   # Direct execution entry point
├── pyproject.toml           # Python packaging config
├── LICENSE                  # MIT License
└── README.md                # This file
```

---

## Troubleshooting

### "Permission denied" on port

Ports below 1024 require root/administrator privileges. Use a port >= 1024:
```bash
sni-spoofing -l :40443 ...
```

### "Address already in use"

Another process is using the port. Either stop it or use a different port:
```bash
sni-spoofing -l :50443 ...
```

### Connection not working

1. Try different bypass methods: `fragment` → `combined` → `fake_sni`
2. Try different fragment strategies: `sni_split` → `multi` → `tls_record_frag`
3. Increase fragment delay: `--fragment-delay 0.2`
4. Try a different fake SNI hostname (one that is allowed in your region)
5. Ensure the target IP and port are correct

### TTL trick not working

The TTL trick requires elevated privileges:
- **Linux/macOS**: Run with `sudo`
- **Windows**: Run as Administrator

---

## How It Works (Technical Details)

### TLS ClientHello Fragmentation

When a TLS connection starts, the client sends a ClientHello message containing the SNI (Server Name Indication) - the hostname it wants to connect to. DPI systems inspect this to filter connections.

**Our approach**: Split the ClientHello into multiple TCP segments so the SNI is divided across packets:

```
Normal:   [TLS Record: ...SNI=blocked-site.com...]  → DPI blocks

Ours:     [Fragment 1: ...SN]  → DPI sees incomplete SNI
          [Fragment 2: I=blocked-site.com...]  → DPI can't match
```

### Fake SNI Injection

Send a fake ClientHello with an allowed SNI before the real one:

```
Step 1:   [Fake ClientHello: SNI=allowed-site.com]  → DPI allows
Step 2:   [Real ClientHello: SNI=blocked-site.com]   → DPI already decided
```

### TTL Trick

Send the fake packet with a low IP TTL (Time To Live):

```
Fake packet (TTL=3):  Reaches DPI (2 hops away) but expires before server
Real packet (TTL=64): Reaches server normally
```

DPI sees the fake SNI, allows traffic. Server never sees the fake packet.

---

## Support the Original Creator

If you use this tool for free internet access, please consider supporting **@patterniha**:

**USDT (BEP20):** `0x76a768B53Ca77B43086946315f0BDF21156bF424`

**Telegram:** [@patterniha](https://t.me/patterniha)

---

## License

MIT License. See [LICENSE](LICENSE) for details.

Original tool by @patterniha. This repository is a CLI cross-platform conversion.
