# SNISPF

### Cross-Platform DPI Bypass Tool

```
 ███████╗███╗   ██╗██╗███████╗██████╗ ███████╗
 ██╔════╝████╗  ██║██║██╔════╝██╔══██╗██╔════╝
 ███████╗██╔██╗ ██║██║███████╗██████╔╝█████╗
 ╚════██║██║╚██╗██║██║╚════██║██╔═══╝ ██╔══╝
 ███████║██║ ╚████║██║███████║██║     ██║
 ╚══════╝╚═╝  ╚═══╝╚═╝╚══════╝╚═╝     ╚═╝
```

**SNISPF** is a lightweight command-line tool that helps you get past internet censorship. It works by messing with the way your connection introduces itself to firewalls, so filtered websites slip through undetected. Runs on **Windows, macOS, and Linux** -- no drivers, no admin rights needed for most features.

**Maintained by [@Rainman69](https://github.com/Rainman69)**

---

## Table of Contents

- [How Does It Work?](#how-does-it-work)
- [Requirements](#requirements)
- [Installation](#installation)
  - [Method 1: pip install (Recommended)](#method-1-pip-install-recommended)
  - [Method 2: Run directly without installing](#method-2-run-directly-without-installing)
  - [Method 3: Clone from source](#method-3-clone-from-source)
  - [Method 4: Docker](#method-4-docker)
- [Quick Start Guide](#quick-start-guide)
  - [Step 1: Start the tool](#step-1-start-the-tool)
  - [Step 2: Point your app at it](#step-2-point-your-app-at-it)
- [Configuration](#configuration)
  - [Using a config file](#using-a-config-file)
  - [Using command-line flags](#using-command-line-flags)
  - [Config file reference](#config-file-reference)
  - [All CLI flags](#all-cli-flags)
- [Bypass Methods Explained](#bypass-methods-explained)
  - [fragment (default)](#fragment-default)
  - [fake_sni](#fake_sni)
  - [combined (strongest)](#combined-strongest)
- [Fragment Strategies](#fragment-strategies)
- [Platform Support](#platform-support)
- [Troubleshooting](#troubleshooting)
- [How It Works (Technical Deep Dive)](#how-it-works-technical-deep-dive)
- [Project Structure](#project-structure)
- [Running the Tests](#running-the-tests)
- [License](#license)
- [Acknowledgements](#acknowledgements)

---

## How Does It Work?

When you visit a website over HTTPS, your device sends a "hello" message (called a **TLS ClientHello**) that contains the website name in plain text. This is known as the **SNI** (Server Name Indication). Internet censorship systems (called **DPI** -- Deep Packet Inspection) read that name and decide whether to block the connection.

SNISPF sits between your app and the internet. It intercepts that "hello" message and either **chops it up** or **sends a decoy** so the censorship system can't read the real website name. The actual destination server still gets the full, correct message and works normally.

```
┌──────────┐     ┌─────────┐     ┌─────────┐     ┌──────────────┐
│ Your App ├────>│ SNISPF  ├────>│  DPI /  ├────>│ Real Server  │
│ (browser,│     │ (local  │     │Firewall │     │ (e.g.        │
│  v2ray,  │     │  proxy) │     │         │     │  Cloudflare) │
│  etc.)   │     │         │     │         │     │              │
└──────────┘     └─────────┘     └─────────┘     └──────────────┘
                      │               │
                      │ sends fake /  │ sees fake or
                      │ fragmented    │ incomplete SNI
                      │ hello message │ --> lets it through
```

---

## Requirements

- **Python 3.8** or newer (check with `python3 --version` or `python --version`)
- That's it. No external dependencies, no C compilers, no kernel modules.

If you don't have Python yet:

| OS | How to install Python |
|---|---|
| **Windows** | Download from [python.org](https://www.python.org/downloads/). During install, **check "Add Python to PATH"**. |
| **macOS** | Run `brew install python` (if you have Homebrew) or download from [python.org](https://www.python.org/downloads/). |
| **Ubuntu / Debian** | `sudo apt update && sudo apt install python3 python3-pip` |
| **Fedora** | `sudo dnf install python3 python3-pip` |
| **Arch** | `sudo pacman -S python python-pip` |
| **Android (Termux)** | `pkg install python` |

---

## Installation

### Method 1: pip install (Recommended)

This installs the `snispf` command system-wide:

```bash
git clone https://github.com/Rainman69/SNISPF.git
cd SNISPF
pip install .
```

Now you can run it from anywhere:

```bash
snispf --help
```

### Method 2: Run directly without installing

No install needed. Just clone and run:

```bash
git clone https://github.com/Rainman69/SNISPF.git
cd SNISPF
python run.py --help
```

### Method 3: Clone from source

If you want to run it as a Python module:

```bash
git clone https://github.com/Rainman69/SNISPF.git
cd SNISPF
python -m sni_spoofing.cli --help
```

### Method 4: Docker

```bash
git clone https://github.com/Rainman69/SNISPF.git
cd SNISPF
docker build -t snispf .
docker run --rm -p 40443:40443 snispf
```

---

## Quick Start Guide

### Step 1: Start the tool

The simplest way to start -- using the default settings:

```bash
snispf -l 0.0.0.0:40443 -c 188.114.98.0:443 -s auth.vercel.com
```

What each part means:

| Flag | What it does | Example value |
|---|---|---|
| `-l` | The local address and port SNISPF listens on | `0.0.0.0:40443` (all interfaces, port 40443) |
| `-c` | The real server IP and port to forward traffic to | `188.114.98.0:443` (a Cloudflare IP) |
| `-s` | The fake website name to show the firewall | `auth.vercel.com` (an allowed domain) |

> **Tip:** If you're not sure what IP or fake SNI to use, the defaults above work for many Cloudflare-based setups.

### Step 2: Point your app at it

Once SNISPF is running, configure your application (web browser, V2Ray, Xray, proxy client, etc.) to connect through:

```
Address: 127.0.0.1
Port:    40443
```

That's it. Your traffic now goes through SNISPF, which handles the bypass automatically.

---

## Configuration

You can configure SNISPF two ways: with a **config file** or with **command-line flags**. Flags override the config file when both are used.

### Using a config file

Generate a default config:

```bash
snispf --generate-config config.json
```

This creates a `config.json` file you can edit. Then run with:

```bash
snispf --config config.json
```

### Using command-line flags

```bash
# Basic usage
snispf -l :40443 -c 188.114.98.0:443 -s auth.vercel.com

# Use the strongest bypass method
snispf -l :40443 -c 188.114.98.0:443 -s dl.google.com -m combined

# See verbose debug output
snispf -l :40443 -c 188.114.98.0:443 -s auth.vercel.com -v

# Check what your system supports
snispf --info
```

### Config file reference

Here's what each field in `config.json` does:

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

| Field | What it does | Default |
|---|---|---|
| `LISTEN_HOST` | IP address to listen on. `0.0.0.0` means all network interfaces. | `0.0.0.0` |
| `LISTEN_PORT` | Port number to listen on locally. | `40443` |
| `CONNECT_IP` | The real server's IP address to forward traffic to. | `188.114.98.0` |
| `CONNECT_PORT` | The real server's port. | `443` |
| `FAKE_SNI` | A website name that is NOT blocked in your region. The firewall will see this instead of the real one. | `auth.vercel.com` |
| `BYPASS_METHOD` | Which bypass technique to use: `fragment`, `fake_sni`, or `combined`. | `fragment` |
| `FRAGMENT_STRATEGY` | How to split the hello message: `sni_split`, `half`, `multi`, or `tls_record_frag`. | `sni_split` |
| `FRAGMENT_DELAY` | How long to wait between sending fragments (in seconds). | `0.1` |
| `USE_TTL_TRICK` | Use the IP TTL trick for extra stealth. Needs root/admin. | `false` |
| `FAKE_SNI_METHOD` | Sub-method for fake_sni: `prefix_fake`, `ttl_trick`, or `disorder`. | `prefix_fake` |

### All CLI flags

```
usage: snispf [-h] [--config CONFIG] [--generate-config PATH]
              [--listen HOST:PORT] [--connect IP:PORT] [--sni HOSTNAME]
              [--method {fragment,fake_sni,combined}]
              [--fragment-strategy {sni_split,half,multi,tls_record_frag}]
              [--fragment-delay SECONDS] [--ttl-trick]
              [--verbose] [--quiet] [--version] [--info]
```

| Flag | Short | Description |
|---|---|---|
| `--config` | `-C` | Path to a JSON config file |
| `--generate-config` | | Create a default config file and exit |
| `--listen` | `-l` | Local listen address (`HOST:PORT`) |
| `--connect` | `-c` | Target server address (`IP:PORT`) |
| `--sni` | `-s` | Fake SNI hostname |
| `--method` | `-m` | Bypass method: `fragment`, `fake_sni`, or `combined` |
| `--fragment-strategy` | | How to fragment: `sni_split`, `half`, `multi`, `tls_record_frag` |
| `--fragment-delay` | | Seconds to wait between fragments |
| `--ttl-trick` | | Enable TTL trick (needs elevated privileges) |
| `--verbose` | `-v` | Show detailed debug output |
| `--quiet` | `-q` | Only show warnings and errors |
| `--version` | `-V` | Print version and exit |
| `--info` | | Show what your platform supports and exit |

---

## Bypass Methods Explained

### `fragment` (default)

Splits your TLS hello message into multiple pieces so the firewall can't read the website name from any single piece.

**Best for:** Most situations. Works everywhere, no special privileges needed.

```
Normal:   [Full hello: ...SNI=blocked-site.com...]  --> Firewall blocks it

SNISPF:   [Piece 1: ...SN]          --> Firewall sees incomplete name
          [Piece 2: I=blocked-site.com...]  --> Too late, already let through
```

### `fake_sni`

Sends a decoy hello message with an allowed website name before sending the real one.

**Best for:** When fragmentation alone doesn't work.

```
Step 1:   [Fake hello: SNI=allowed-site.com]  --> Firewall allows it
Step 2:   [Real hello: SNI=blocked-site.com]   --> Firewall already decided
```

### `combined` (strongest)

Uses both methods at the same time: sends a fake hello first, then sends the real hello in fragments.

**Best for:** Aggressive DPI systems. This is the most effective option.

```bash
snispf -l :40443 -c 188.114.98.0:443 -s dl.google.com -m combined
```

---

## Fragment Strategies

These control *how* the hello message gets split up (used by `fragment` and `combined` methods):

| Strategy | What it does | When to use it |
|---|---|---|
| `sni_split` | Cuts right through the middle of the website name. | Default and most effective for most firewalls. |
| `half` | Cuts the entire message in half. | Simple fallback if `sni_split` doesn't work. |
| `multi` | Chops into many tiny 5-byte pieces. | For firewalls that try to reassemble two fragments. |
| `tls_record_frag` | Creates multiple valid TLS records from one message. | For firewalls that understand TLS but don't handle multi-record. |

Example:

```bash
snispf -l :40443 -c 188.114.98.0:443 -s auth.vercel.com --fragment-strategy multi
```

---

## Platform Support

| Platform | Works? | Notes |
|---|---|---|
| Windows 10 / 11 | Yes | No admin needed for basic methods |
| Linux (Ubuntu, Debian, Fedora, Arch, etc.) | Yes | Use `sudo` for TTL trick |
| macOS | Yes | Use `sudo` for TTL trick |
| Android (Termux) | Yes | Install Python first: `pkg install python` |
| WSL / WSL2 | Yes | Works like native Linux |

All bypass methods work in userspace using standard socket options (`TCP_NODELAY`, `IP_TTL`). No kernel drivers or raw sockets needed for the basic methods.

---

## Troubleshooting

### "Permission denied" when starting

Ports below 1024 need root/admin. Use a higher port:

```bash
snispf -l :40443 ...
```

### "Address already in use"

Something else is using that port. Pick a different one:

```bash
snispf -l :50443 ...
```

### It starts but connections don't work

Try these steps in order:

1. **Switch bypass method:** `fragment` -> `combined` -> `fake_sni`
   ```bash
   snispf -l :40443 -c 188.114.98.0:443 -s auth.vercel.com -m combined
   ```

2. **Try different fragment strategies:** `sni_split` -> `multi` -> `tls_record_frag`
   ```bash
   snispf -l :40443 -c 188.114.98.0:443 -s auth.vercel.com --fragment-strategy multi
   ```

3. **Increase the delay between fragments:**
   ```bash
   snispf -l :40443 -c 188.114.98.0:443 -s auth.vercel.com --fragment-delay 0.2
   ```

4. **Try a different fake SNI.** Pick a major website that's not blocked in your area:
   ```bash
   snispf -l :40443 -c 188.114.98.0:443 -s dl.google.com
   ```

5. **Double-check the target IP and port.** Make sure `CONNECT_IP` actually points to the server you want.

### TTL trick doesn't work

The TTL trick needs elevated privileges:

- **Linux / macOS:** Run with `sudo`
- **Windows:** Run the terminal as Administrator

### How do I check what my system supports?

```bash
snispf --info
```

This shows which features are available on your platform.

---

## How It Works (Technical Deep Dive)

### TLS ClientHello Fragmentation

When a TLS connection starts, the client sends a ClientHello message containing the SNI. DPI systems inspect this to filter connections.

SNISPF splits the ClientHello into multiple TCP segments so the SNI is divided across packets:

```
Normal:   [TLS Record: ...SNI=blocked-site.com...]  --> DPI reads and blocks

SNISPF:   [Fragment 1: ...SN]                       --> DPI sees incomplete SNI
          [Fragment 2: I=blocked-site.com...]        --> DPI can't match pattern
```

This works because many DPI systems only inspect the first TCP segment or don't reassemble the full TCP stream.

### Fake SNI Injection

A fake ClientHello with an allowed SNI is sent before the real one:

```
Step 1:   [Fake ClientHello: SNI=allowed-site.com]  --> DPI allows it
Step 2:   [Real ClientHello: SNI=blocked-site.com]   --> DPI already decided
```

The server ignores the fake because it's a malformed/incomplete handshake.

### TTL Trick

The fake packet is sent with a low IP TTL (Time To Live):

```
Fake packet (TTL=3):  Reaches DPI (2 hops away) but expires before the server
Real packet (TTL=64): Reaches the server normally
```

The DPI sees the fake SNI and allows the traffic. The server never sees the fake packet at all.

---

## Project Structure

```
SNISPF/
├── sni_spoofing/               # Main package
│   ├── __init__.py             # Version and metadata
│   ├── cli.py                  # Command-line interface and argument parsing
│   ├── forwarder.py            # Core async TCP forwarder
│   ├── bypass/                 # Bypass strategy implementations
│   │   ├── __init__.py         # Exports all strategies
│   │   ├── base.py             # Abstract base class for strategies
│   │   ├── fragment.py         # TLS fragmentation bypass
│   │   ├── fake_sni.py         # Fake SNI bypass
│   │   └── combined.py         # Combined (fragment + fake SNI) bypass
│   ├── tls/                    # TLS packet handling
│   │   ├── __init__.py         # ClientHello builder and parser
│   │   └── fragment.py         # TLS record fragmentation logic
│   └── utils/                  # Utility functions
│       └── __init__.py         # Network helpers, platform detection
├── tests/
│   └── test_tls.py             # Unit tests
├── config.json                 # Default configuration file
├── run.py                      # Run without installing (python run.py)
├── pyproject.toml              # Python package configuration
├── Dockerfile                  # Docker support
├── LICENSE                     # MIT License
└── README.md                   # You are here
```

---

## Running the Tests

```bash
cd SNISPF
python -m pytest tests/ -v
```

Or without pytest:

```bash
python -m unittest tests.test_tls -v
```

---

## Changelog

### v1.0.1

- Fixed `supported_versions` TLS extension in the fake ClientHello builder. The version list length byte was encoded as two bytes (`04 03`) instead of one (`04`), which shifted every extension after it by one byte. This corrupted `psk_key_exchange_modes`, `key_share`, and `padding`, making the fake ClientHello malformed. Strict TLS parsers and some DPI systems would reject it outright.
- Fixed the bidirectional relay task setup. The two relay directions (client-to-server and server-to-client) were referencing the wrong peer task during creation, which could cause one relay direction to fail to clean up when the other direction closed.
- Bumped version to 1.0.1.

---

## License

MIT License. See [LICENSE](LICENSE) for the full text.

---

## Acknowledgements

This project is a cross-platform conversion of patterniha's original Windows-only SNI-Spoofing tool.
