# SNISPF

### Cross-Platform DPI Bypass Tool with Automatic IP Scanner

```
 ███████╗███╗   ██╗██╗███████╗██████╗ ███████╗
 ██╔════╝████╗  ██║██║██╔════╝██╔══██╗██╔════╝
 ███████╗██╔██╗ ██║██║███████╗██████╔╝█████╗
 ╚════██║██║╚██╗██║██║╚════██║██╔═══╝ ██╔══╝
 ███████║██║ ╚████║██║███████║██║     ██║
 ╚══════╝╚═╝  ╚═══╝╚═╝╚══════╝╚═╝     ╚═╝
```
**[FA README | توضیحات فارسی](https://github.com/Rainman69/SNISPF/blob/main/README_FA.md)**

**SNISPF** is a lightweight command-line tool that helps you get past internet censorship. It works by messing with the way your connection introduces itself to firewalls, so filtered websites slip through undetected. Runs on **Windows, macOS, and Linux** -- no drivers, no admin rights needed for most features.

**New in v1.6.0:** Fixed `fake_sni` and `combined` methods on macOS and Android/Termux -- they now auto-enable the TTL trick when raw sockets are unavailable, so these bypass methods actually work without root on all platforms. Fixed `--sni` flag being ignored when auto mode is active. Fixed `config.json` not being auto-loaded from the current directory. Inspired by community scanners (GoodbyeDPI, ByeDPI, Zapret, SNI-Spoofing).

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
- [Auto Mode (Recommended)](#auto-mode-recommended)
- [IP Scanner](#ip-scanner)
  - [One-shot scan](#one-shot-scan)
  - [Scan with download speed test](#scan-with-download-speed-test)
  - [Custom IP ranges](#custom-ip-ranges)
  - [Custom SNI domains](#custom-sni-domains)
  - [Background rescanning](#background-rescanning)
  - [Caching results](#caching-results)
- [SNI Domain Rotation](#sni-domain-rotation)
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

**With the built-in scanner**, SNISPF also automatically finds the fastest reachable Cloudflare IP for your network:

```
┌─────────────────┐     ┌─────────────────────────────────────┐
│  SNISPF Scanner  │────>│  Tests 100+ Cloudflare IPs:        │
│                  │     │  1. TCP connect  (latency)          │
│  Runs at startup │     │  2. TLS handshake (reachability)    │
│  + periodically  │     │  3. HTTP validation (Cloudflare     │
│                  │     │     response verification)          │
│                  │     │  4. Download test (speed, optional) │
└────────┬────────┘     └──────────────────┬──────────────────┘
         │                                  │
         │  Picks fastest IP ──────────────>│
         │                                  │
         │  If blocked at runtime ─────────>│  Failover to next best
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
snispf -l 0.0.0.0:40443 -c 104.18.38.202:443 -s cdnjs.cloudflare.com
```

What each part means:

| Flag | What it does | Example value |
|---|---|---|
| `-l` | The local address and port SNISPF listens on | `0.0.0.0:40443` (all interfaces, port 40443) |
| `-c` | The real server IP and port to forward traffic to | `104.18.38.202:443` (a Cloudflare IP) |
| `-s` | The fake website name to show the firewall | `cdnjs.cloudflare.com` (an allowed domain) |

> **Tip:** If you're not sure what IP or fake SNI to use, try **auto mode** instead. It figures everything out for you.

### Step 2: Point your app at it

Once SNISPF is running, configure your application (web browser, V2Ray, Xray, proxy client, etc.) to connect through:

```
Address: 127.0.0.1
Port:    40443
```

That's it. Your traffic now goes through SNISPF, which handles the bypass automatically.

---

## Auto Mode (Recommended)

Auto mode is the easiest way to use SNISPF. It scans Cloudflare IPs, picks the fastest one, starts the proxy, and automatically switches to another IP if the current one gets blocked.

```bash
# Scan + start proxy with automatic failover
snispf --auto

# Scan + start proxy + re-scan every 5 minutes
snispf --auto --rescan 300

# Auto mode with the strongest bypass method
snispf --auto -m combined

# Auto mode with custom SNI domains
snispf --auto --sni-list "cdnjs.cloudflare.com,www.speedtest.net,ajax.cloudflare.com"

# Auto mode with verbose logging to see what's happening
snispf --auto -v
```

What auto mode does:

1. **Scans** 100 random Cloudflare IPs (configurable with `--scan-count`)
2. **Tests** each one for TCP latency, TLS handshake, HTTP response validation, and optionally download speed
3. **Verifies** the response is genuinely from Cloudflare (not a block page or MITM proxy)
4. **Picks** the fastest verified working IP
5. **Starts** the proxy, forwarding your traffic through that IP
6. **Monitors** connections -- if the IP gets blocked, it automatically switches to the next best one
7. **Rescans** periodically (if `--rescan` is set) to keep the IP list fresh

---

## IP Scanner

The built-in scanner tests Cloudflare IP addresses from their published CIDR ranges and ranks them by latency and reachability. This is useful for finding "clean" IPs that aren't filtered on your network.

### One-shot scan

Run a scan and see the results without starting the proxy:

```bash
snispf --scan
```

Output:

```
  Scanning: [████████████████████] 100/100 (100%)

══════════════════════════════════════════════════════════════════════
  Scan Results: 67/100 IPs alive
══════════════════════════════════════════════════════════════════════
  #  IP                      TCP      TLS      Speed    Score  Status
----------------------------------------------------------------------
  1  104.18.42.139           12ms     28ms         -       40  OK
  2  172.67.181.22           14ms     31ms         -       45  OK
  3  104.21.55.17            15ms     35ms         -       50  OK
  ...

  Best IP: 104.18.42.139
  TCP Latency: 12ms
  TLS Latency: 28ms

  Use this IP with:
    snispf -l :40443 -c 104.18.42.139:443 -s cdnjs.cloudflare.com
```

### Scan with download speed test

Add `--download` to also test download throughput:

```bash
snispf --scan --download
```

### Custom IP ranges

By default, the scanner uses all official Cloudflare IPv4 ranges. You can add your own:

```bash
# Scan only specific ranges
snispf --scan --ip-ranges "104.16.0.0/13,172.64.0.0/13"

# Fetch the latest ranges from Cloudflare before scanning
snispf --scan --fetch-ranges
```

### Custom SNI domains

You can specify which SNI domains to use for probing:

```bash
snispf --scan --sni-list "cdnjs.cloudflare.com,www.speedtest.net,ajax.cloudflare.com"
```

### Background rescanning

In auto mode, use `--rescan` to periodically re-scan and update the best IP:

```bash
snispf --auto --rescan 300   # Re-scan every 5 minutes
snispf --auto --rescan 600   # Re-scan every 10 minutes
```

### Caching results

Save scan results to disk so the next startup is instant:

```bash
snispf --auto --scan-cache results.json
```

On the next run, SNISPF loads the cached results first and starts immediately, then runs a fresh scan in the background.

---

## Domain Checker

The built-in domain checker lets you scan a list of domains to find which ones are behind Cloudflare's CDN and can be used as fake SNI targets. This is useful for building your own custom SNI list or verifying third-party domain lists.

### Checking domains from a file

Create a text file with one domain per line:

```text
# domains.txt
example.com
cloudflare.com
discord.com
google.com
```

Then run:

```bash
snispf --check-domains domains.txt
```

Output:

```
  Checking 4 domains...

  Checking: [████████████████████] 4/4 (100%)

══════════════════════════════════════════════════════════════════════════════════════════
  Domain Check Results
══════════════════════════════════════════════════════════════════════════════════════════
  Total domains:    4
  Behind Cloudflare: 3
  Usable as SNI:    3
══════════════════════════════════════════════════════════════════════════════════════════

   #  Domain                                   IP               CDN  TCP  TLS   TLS ms Status
------------------------------------------------------------------------------------------
   1  cloudflare.com                           104.16.133.229    CF   OK   OK     25ms SNI
   2  discord.com                              162.159.135.232   CF   OK   OK     31ms SNI
   3  example.com                              104.18.32.7       CF   OK   OK     33ms SNI

  Note: 1 domains are NOT behind Cloudflare
  (these will not work for SNI spoofing through Cloudflare IPs)
```

### Exporting verified domains

Export the verified Cloudflare-backed domains to a file for use with `--sni-list`:

```bash
snispf --check-domains domains.txt --output verified.txt
```

### Deeper validation with HTTP check

Add `--check-http` to also verify HTTP connectivity:

```bash
snispf --check-domains domains.txt --check-http
```

### Custom concurrency and timeout

```bash
snispf --check-domains domains.txt --check-workers 100 --check-timeout 5
```

---

## SNI Domain Rotation

SNISPF maintains a pool of SNI domains (Cloudflare-fronted sites) and rotates between them automatically. If a particular SNI gets blocked, the tool switches to another one.

Built-in SNI domains include:

- `cdnjs.cloudflare.com`
- `ajax.cloudflare.com`
- `static.cloudflareinsights.com`
- `challenges.cloudflare.com`
- `workers.cloudflare.com`
- `cloudflare-dns.com`
- `www.speedtest.net`
- `www.canva.com`
- `www.discord.com`
- `registry.npmjs.org`
- `api.openai.com`
- `chatgpt.com`
- `auth.vercel.com`
- `www.coursera.org`
- `huggingface.co`
- `proton.me`
- `metamask.io`
- `etherscan.io`
- and 130+ more verified Cloudflare-fronted domains...

> **Important:** All default SNI domains are verified to be behind Cloudflare's CDN. Non-Cloudflare domains (like `dl.google.com`, `cdn.shopify.com`, `fonts.googleapis.com`) will NOT work with Cloudflare IPs and have been removed in v1.3.0. In v1.5.0, the list was expanded to 150+ verified domains across multiple categories (infrastructure, developer tools, education, entertainment, business, fintech, security, AI/ML platforms, and more).

You can override or extend the list:

```bash
# CLI
snispf --auto --sni-list "my-domain1.com,my-domain2.com"

# Config file
{
  "SNI_DOMAINS": ["my-domain1.com", "my-domain2.com", "my-domain3.com"]
}
```

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
snispf -l :40443 -c 104.18.38.202:443 -s cdnjs.cloudflare.com

# Use the strongest bypass method
snispf -l :40443 -c 104.18.38.202:443 -s www.speedtest.net -m combined

# Auto mode with scanner
snispf --auto -m combined --rescan 300

# See verbose debug output
snispf -l :40443 -c 104.18.38.202:443 -s cdnjs.cloudflare.com -v

# Check what your system supports
snispf --info
```

### Config file reference

Here's what each field in `config.json` does:

```json
{
  "LISTEN_HOST": "0.0.0.0",
  "LISTEN_PORT": 40443,
  "CONNECT_IP": "104.18.38.202",
  "CONNECT_PORT": 443,
  "FAKE_SNI": "cdnjs.cloudflare.com",
  "BYPASS_METHOD": "fragment",
  "FRAGMENT_STRATEGY": "sni_split",
  "FRAGMENT_DELAY": 0.1,
  "USE_TTL_TRICK": false,
  "FAKE_SNI_METHOD": "prefix_fake",
  "SCANNER_ENABLED": false,
  "SCANNER_COUNT": 100,
  "SCANNER_CONCURRENCY": 16,
  "SCANNER_TIMEOUT": 4.0,
  "SCANNER_TEST_DOWNLOAD": false,
  "SCANNER_RESCAN_INTERVAL": 0,
  "SCANNER_CACHE": "",
  "SCANNER_TOP_N": 10,
  "SCANNER_CUSTOM_RANGES": [],
  "SNI_DOMAINS": []
}
```

| Field | What it does | Default |
|---|---|---|
| `LISTEN_HOST` | IP address to listen on. `0.0.0.0` means all network interfaces. | `0.0.0.0` |
| `LISTEN_PORT` | Port number to listen on locally. | `40443` |
| `CONNECT_IP` | The real server's IP address to forward traffic to. | `104.18.38.202` |
| `CONNECT_PORT` | The real server's port. | `443` |
| `FAKE_SNI` | A website name that is NOT blocked in your region. The firewall will see this instead of the real one. Must be behind Cloudflare! | `cdnjs.cloudflare.com` |
| `BYPASS_METHOD` | Which bypass technique to use: `fragment`, `fake_sni`, or `combined`. | `fragment` |
| `FRAGMENT_STRATEGY` | How to split the hello message: `sni_split`, `half`, `multi`, or `tls_record_frag`. | `sni_split` |
| `FRAGMENT_DELAY` | How long to wait between sending fragments (in seconds). | `0.1` |
| `USE_TTL_TRICK` | Use the IP TTL trick for extra stealth. Needs root/admin. | `false` |
| `FAKE_SNI_METHOD` | Sub-method for fake_sni: `prefix_fake`, `ttl_trick`, or `disorder`. | `prefix_fake` |
| `SCANNER_ENABLED` | Enable the auto-scanner (same as `--auto` flag). | `false` |
| `SCANNER_COUNT` | How many random IPs to test per scan. | `100` |
| `SCANNER_CONCURRENCY` | Parallel scan workers. | `16` |
| `SCANNER_TIMEOUT` | Per-probe timeout in seconds. | `4.0` |
| `SCANNER_TEST_DOWNLOAD` | Include download speed test. | `false` |
| `SCANNER_RESCAN_INTERVAL` | Re-scan every N seconds (0 = one-shot). | `0` |
| `SCANNER_CACHE` | File path to cache results. | `""` |
| `SCANNER_TOP_N` | Keep top N results. | `10` |
| `SCANNER_CUSTOM_RANGES` | Custom CIDR ranges to scan. | `[]` |
| `SNI_DOMAINS` | Custom SNI domain list for rotation. | `[]` (uses built-in list) |

### All CLI flags

```
usage: snispf [-h] [--config CONFIG] [--generate-config PATH]
              [--listen HOST:PORT] [--connect IP:PORT] [--sni HOSTNAME]
              [--method {fragment,fake_sni,combined}]
              [--fragment-strategy {sni_split,half,multi,tls_record_frag}]
              [--fragment-delay SECONDS] [--ttl-trick] [--no-raw]
              [--scan] [--auto] [--scan-count N] [--scan-workers N]
              [--scan-timeout SECONDS] [--download] [--rescan SECONDS]
              [--scan-cache PATH] [--sni-list DOMAINS] [--ip-ranges CIDRS]
              [--fetch-ranges]
              [--check-domains FILE] [--check-workers N]
              [--check-timeout SECONDS] [--output FILE] [--check-http]
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
| `--no-raw` | | Disable raw socket injection even if available |
| `--scan` | | Run a one-shot IP scan and display results |
| `--auto` | | Auto mode: scan, pick best IP, start proxy with failover |
| `--scan-count` | | Number of IPs to test per scan |
| `--scan-workers` | | Parallel scan workers |
| `--scan-timeout` | | Per-probe timeout in seconds |
| `--download` | | Include download speed test during scan |
| `--rescan` | | Background re-scan interval in seconds |
| `--scan-cache` | | File to cache scan results |
| `--sni-list` | | Comma-separated SNI domains for rotation |
| `--ip-ranges` | | Comma-separated custom CIDR ranges |
| `--fetch-ranges` | | Fetch live Cloudflare IP ranges before scanning |
| `--check-domains` | | Check domains from a file for Cloudflare CDN backing |
| `--check-workers` | | Parallel workers for domain checking (default: 50) |
| `--check-timeout` | | Per-domain timeout in seconds (default: 3.0) |
| `--output` | | Export verified domains to a file |
| `--check-http` | | Also verify HTTP connectivity during domain check |
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

Injects a decoy hello message with an allowed website name that DPI parses, but the server drops.

**Best for:** When fragmentation alone doesn't work. Most effective with root/admin.

**With root (Linux):** Uses raw socket injection to send the fake ClientHello with a TCP sequence number that falls outside the server's receive window. DPI sees it and whitelists the connection. The server drops it because the sequence number is out of range. This is the same technique used by the [original patterniha tool](https://github.com/patterniha/SNI-Spoofing).

**Without root (macOS, Android, Windows, unprivileged Linux):** Uses the **TTL trick** -- sends a fake ClientHello with a low IP TTL (3-8 hops) that reaches the DPI middlebox but expires before the real server. Then sends the real ClientHello in fragments. This is auto-enabled in v1.6.0.

```
With root:        [Fake hello: seq=out-of-window]    --> DPI sees it, server drops it
                  [Real hello: seq=normal]            --> Server processes, DPI ignores

Without root:     [Fake hello: TTL=3-8]              --> DPI sees it, packet expires
                  [Real hello: fragments]             --> DPI sees incomplete SNI
```

### `combined` (strongest)

Uses both methods at the same time: injects a fake hello (if root is available), then sends the real hello in fragments.

**Best for:** Aggressive DPI systems. This is the most effective option.

**With root:** Injects the fake via raw socket (out-of-window seq trick) and fragments the real ClientHello. Hits DPI from two angles simultaneously.

**Without root:** Uses the TTL trick to send a fake ClientHello that expires before the server, then fragments the real ClientHello. Auto-enabled in v1.6.0.

```bash
snispf -l :40443 -c 104.18.38.202:443 -s www.speedtest.net -m combined

# On Linux, run with sudo for the full seq_id trick:
sudo snispf -l :40443 -c 104.18.38.202:443 -s www.speedtest.net -m combined
```

---

## Fragment Strategies

These control *how* the hello message gets split up (used by `fragment` and `combined` methods):

| Strategy | What it does | When to use it |
|---|---|---|
| `sni_split` | Cuts right through the middle of the website name. | Default and most effective for most firewalls. |
| `half` | Cuts the entire message in half. | Simple fallback if `sni_split` doesn't work. |
| `multi` | Chops into many small 24-byte pieces. | For firewalls that try to reassemble two fragments. |
| `tls_record_frag` | Creates multiple valid TLS records from one message. | For firewalls that understand TLS but don't handle multi-record. |

Example:

```bash
snispf -l :40443 -c 104.18.38.202:443 -s cdnjs.cloudflare.com --fragment-strategy multi
```

---

## Platform Support

| Platform | Works? | Notes |
|---|---|---|
| Windows 10 / 11 | Yes | No admin needed for basic methods |
| Linux (Ubuntu, Debian, Fedora, Arch, etc.) | Yes | Use `sudo` for raw injection (seq_id trick) |
| macOS | Yes | TTL trick + fragmentation (auto-enabled for fake_sni/combined) |
| Android (Termux) | Yes | Install Python first: `pkg install python`. TTL trick works. |
| WSL / WSL2 | Yes | Works like native Linux |

The `fragment` method works everywhere using standard socket options (`TCP_NODELAY`). The `fake_sni` and `combined` methods are most effective on Linux with root, where they use `AF_PACKET` raw sockets to inject fake packets with out-of-window TCP sequence numbers. **On macOS, Android, and unprivileged Linux**, they automatically fall back to the **TTL trick** (sending a fake ClientHello with low IP TTL) combined with fragmentation -- this is more effective than fragmentation alone.

The **scanner** works on all platforms with no special privileges.

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

1. **Use auto mode to find a working IP:**
   ```bash
   snispf --auto -m combined
   ```

2. **Switch bypass method:** `fragment` -> `combined` -> `fake_sni`
   ```bash
   snispf --auto -m combined
   ```

3. **Try different fragment strategies:** `sni_split` -> `multi` -> `tls_record_frag`
   ```bash
   snispf --auto --fragment-strategy multi
   ```

4. **Increase the delay between fragments:**
   ```bash
   snispf --auto --fragment-delay 0.2
   ```

5. **Try a different fake SNI.** Pick a major Cloudflare-backed website that's not blocked in your area:
   ```bash
   snispf --auto --sni-list "cdnjs.cloudflare.com,www.speedtest.net,ajax.cloudflare.com"
   ```

6. **Scan more IPs.** The default 100 might not be enough:
   ```bash
   snispf --auto --scan-count 500
   ```

### Scanner finds no working IPs

This usually means your network heavily filters Cloudflare traffic:

1. Try different SNI domains:
   ```bash
   snispf --scan --sni-list "cdnjs.cloudflare.com,www.speedtest.net"
   ```

2. Increase the timeout:
   ```bash
   snispf --scan --scan-timeout 8
   ```

3. Scan more IPs:
   ```bash
   snispf --scan --scan-count 500
   ```

### TTL trick doesn't work

The TTL trick needs elevated privileges:

- **Linux / macOS:** Run with `sudo`
- **Windows:** Run the terminal as Administrator

On Linux, consider using `combined` or `fake_sni` with `sudo` instead. The raw injection method (seq_id trick) is more reliable than the TTL trick because it's independent of network topology.

### How do I get the strongest bypass?

On Linux, run as root with auto mode:

```bash
sudo snispf --auto -m combined --rescan 300
```

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

### IP Scanner Pipeline

The scanner uses a four-stage probing pipeline:

```
Stage 1: TCP Connect
  └─ Measures raw SYN/ACK latency
  └─ Filters out unreachable / RST-blocked IPs

Stage 2: TLS Handshake
  └─ Performs a real TLS 1.2/1.3 handshake with the chosen SNI
  └─ Checks certificate issuer against known Cloudflare CAs
  └─ Detects MITM/censorship proxy certificates
  └─ Measures handshake time

Stage 3: HTTP Validation (always runs)
  └─ Sends GET /cdn-cgi/trace to verify Cloudflare response
  └─ Checks for Cloudflare markers (fl=, h=, colo=)
  └─ Detects block pages and intercepted connections
  └─ Measures HTTP response time

Stage 4: Download Test (optional)
  └─ Issues another HTTP GET with validated Cloudflare response
  └─ Measures throughput

Ranking:
  score = tcp_latency + tls_latency + (http_latency * 0.5) - speed_bonus
  Lower score = better IP
```

IPs are scanned in parallel using a thread pool (default 16 workers). The best results are cached and used by the proxy. When a connection fails at runtime, the IP is blacklisted and the next-best IP is used automatically.

### Failover Mechanism

The forwarder tracks connection failures per-IP:

```
Connection attempt fails --> record_failure(ip)
  └─ If 3 failures within 30 seconds:
       └─ Blacklist the IP
       └─ Switch to next-best from scan results
       └─ Log the failover event

Connection succeeds --> record_success(ip)
  └─ Resets failure counter
```

---

## Project Structure

```
SNISPF/
├── sni_spoofing/               # Main package
│   ├── __init__.py             # Version and metadata
│   ├── cli.py                  # Command-line interface and argument parsing
│   ├── forwarder.py            # Core async TCP forwarder with failover
│   ├── bypass/                 # Bypass strategy implementations
│   │   ├── __init__.py         # Exports all strategies
│   │   ├── base.py             # Abstract base class for strategies
│   │   ├── fragment.py         # TLS fragmentation bypass
│   │   ├── fake_sni.py         # Fake SNI bypass (with raw injection support)
│   │   ├── combined.py         # Combined (fragment + fake SNI) bypass
│   │   └── raw_injector.py     # AF_PACKET raw injection (seq_id trick)
│   ├── scanner/                # Cloudflare IP scanner and SNI provider
│   │   ├── __init__.py         # Package exports
│   │   ├── ip_ranges.py        # Cloudflare CIDR pool and random IP sampling
│   │   ├── probe.py            # TCP/TLS/download probe for single IPs
│   │   ├── engine.py           # Concurrent scan orchestrator with caching
│   │   ├── sni_provider.py     # SNI domain list management and rotation
│   │   └── domain_checker.py   # Bulk domain checker for Cloudflare CDN detection
│   ├── tls/                    # TLS packet handling
│   │   ├── __init__.py         # ClientHello builder and parser
│   │   └── fragment.py         # TLS record fragmentation logic
│   └── utils/                  # Utility functions
│       └── __init__.py         # Network helpers, platform detection
├── tests/
│   ├── test_tls.py             # Unit tests for TLS and bypass modules
│   └── test_scanner.py         # Unit tests for scanner and SNI modules
├── config.json                 # Default configuration file
├── run.py                      # Run without installing (python run.py)
├── pyproject.toml              # Python package configuration
├── Dockerfile                  # Docker support
├── LICENSE                     # MIT License
├── README.md                   # You are here
└── README_FA.md                # Persian tutorial (راهنمای فارسی)
```

---

## Running the Tests

```bash
cd SNISPF
python -m pytest tests/ -v
```

Or without pytest:

```bash
python -m unittest discover tests/ -v
```

---

## Changelog

### v1.6.0

- **Fixed `fake_sni` and `combined` methods on macOS and Android/Termux.** Previously, when `AF_PACKET` raw sockets were unavailable (anything that isn't Linux + root), both `fake_sni` and `combined` silently fell back to pure fragmentation -- identical to the `fragment` method. Now they automatically enable the **TTL trick**: a fake ClientHello is sent with a low IP TTL (tries 3, 5, 8 hops) so it reaches the DPI middlebox but expires before the real server, followed by the real ClientHello sent in fragments. This makes `combined` and `fake_sni` genuinely useful on macOS, Android/Termux, Windows, and unprivileged Linux.
- **Fixed `--sni` / `-s` flag being ignored when auto mode is active.** When the scanner's SNI provider was active, it would override the user's explicit `--sni` choice with a random domain from the built-in pool. The user-specified SNI is now injected into the provider with top priority so it is always used first.
- **Fixed `config.json` not being auto-loaded.** Previously, `config.json` in the current directory was ignored unless you explicitly passed `--config config.json`. Now, if no `--config` flag is given, SNISPF automatically loads `config.json` or `snispf.json` from the current directory (if present). CLI flags still override file values.
- **Improved TTL trick reliability.** The TTL trick now tries multiple TTL values (3, 5, 8) to cover different DPI placement distances in the network path, instead of only TTL=3. This increases the chance of the fake packet reaching the DPI on varied network topologies.
- Added 9 new unit tests for TTL trick flag propagation, strategy construction, SNI priority, and host:port parsing. Total: 113 tests.
- Bumped version to 1.6.0.

### v1.5.0

- **Massively expanded default SNI domain list to 150+ verified Cloudflare-backed domains.** Previously 30 domains; now covers infrastructure, developer tools, education, entertainment, business, fintech, security, AI/ML platforms, research, file sharing, and more. Every domain has been verified to resolve to Cloudflare IP ranges. Categories are prioritised so that Cloudflare infrastructure domains (almost never blocked) come first. This gives the rotation logic a much larger pool to fall back on when domains get blocked.
- **Expanded seed IP list from 100 to 180+ pre-resolved Cloudflare edge IPs.** Added IPs across 104.24.0.0/14, 197.234.240.0/22, and additional subnets in all existing ranges. New IPs include endpoints for chatgpt.com, proton.me, huggingface.co, metamask.io, etherscan.io, clickup.com, calendly.com, hcaptcha.com, and many more. The scanner now has more guaranteed starting points for DNS-poisoned networks.
- **Added bulk domain checker (`--check-domains`).** New feature inspired by community SNI scanner tools. Feed it a text file with domain names (one per line) and it checks each one: DNS resolution, Cloudflare IP range matching, TCP connectivity, and TLS handshake. Outputs a sorted table showing which domains are behind Cloudflare and usable as fake SNI targets. Supports `--output` to export the verified list, `--check-http` for deeper validation, configurable concurrency with `--check-workers`, and timeout with `--check-timeout`.
- **Added `domain_checker.py` module** with `DomainChecker`, `DomainResult`, and `is_cloudflare_ip()` for programmatic use. The checker runs DNS + IP range + TLS checks in parallel using a thread pool. Results include CDN identification, latency measurements, and a `usable_as_sni` property that combines all checks.
- **Added support for comments and URL prefixes in domain list files.** The domain checker handles `#` comments, blank lines, `http://`/`https://` prefixes, path stripping, and port stripping when loading domain files.
- Added 17 new unit tests for the domain checker, expanded seed IPs, expanded SNI list, and duplicate detection. Total: 104 tests.
- Bumped version to 1.5.0.

### v1.4.0

- **Fixed scanner false-positive bug: IPs/SNIs that were actually blocked were incorrectly marked as "alive".** The scanner previously only checked TCP connect + TLS handshake. A successful handshake does NOT prove the connection works -- DPI can allow the handshake but inject a block page, or a transparent MITM proxy can terminate TLS with its own certificate. The scanner now requires HTTP validation to pass before marking an IP as alive.
- **Added HTTP validation stage to the scanner probe pipeline.** Every probe now sends `GET /cdn-cgi/trace` after the TLS handshake and verifies the response contains Cloudflare markers (`fl=`, `h=`, `colo=`). This catches block pages, MITM proxy responses, and connections that get RST after application data is sent.
- **Added TLS certificate issuer checking for MITM detection.** The probe now extracts the server certificate issuer and checks it against known Cloudflare CA issuers (DigiCert, Google Trust Services, Let's Encrypt, etc.). Certificates from unknown issuers (censorship proxies, corporate MITM) are rejected immediately.
- **Fixed forwarder success tracking.** Previously, `mark_success()` was called right after the bypass strategy was applied, before the server had a chance to respond. Now success is only recorded after the first server response is received in the bidirectional relay. If the server never responds (DPI blocks data after handshake), the IP is marked as failed and failover is triggered.
- **Improved SNI provider domain health checking.** `check_domain()` now performs HTTP validation in addition to TLS handshake, ensuring that SNI domains marked as "alive" are actually usable and not intercepted.
- **Improved download test validation.** The download speed test now verifies that the response body contains Cloudflare markers, preventing fake speed measurements from block pages or MITM responses.
- **Changed User-Agent in scanner probes.** Scanner HTTP requests now use a standard browser User-Agent instead of `SNISPF` to avoid potential fingerprinting by DPI systems.
- Added `http_ok`, `http_ms`, and `tls_issuer` fields to `ProbeResult`.
- Added HTTP column to scan results table.
- Added 9 new unit tests for MITM detection, HTTP validation, and the new alive requirement. Total: 86 tests.
- Bumped version to 1.4.0.

### v1.3.0

- **Added 100+ pre-resolved Cloudflare seed IPs.** The scanner now ships with a built-in list of known-good Cloudflare edge IPs spread across all major prefixes. These are tested first during scans, so no DNS resolution is needed. This is critical for networks with DNS poisoning (like Iran) where DNS queries for Cloudflare domains return bogus results.
- **Fixed SNI domain list: removed 7 non-Cloudflare domains.** `dl.google.com`, `cdn.shopify.com`, `www.figma.com`, `fonts.googleapis.com`, `cdn.jsdelivr.net`, `www.notion.so`, and `www.zoom.us` were NOT behind Cloudflare and would fail TLS handshake when connected through Cloudflare IPs. They have been replaced with verified Cloudflare-only domains.
- **Expanded default SNI domains to 30+.** Added Cloudflare infrastructure domains (`challenges.cloudflare.com`, `workers.cloudflare.com`, `cloudflare-dns.com`, `radar.cloudflare.com`, `dash.cloudflare.com`) which are almost never blocked, plus popular verified Cloudflare sites (`www.crunchyroll.com`, `www.zendesk.com`, `www.hubspot.com`, `www.gitlab.com`, `www.patreon.com`, `www.coindesk.com`, `unpkg.com`, etc.).
- **Scanner uses seed IPs first.** `scan_once()` now calls `sample_with_seeds()` which returns pre-resolved IPs before falling back to random CIDR sampling. This eliminates DNS dependency during scanning.
- **Updated default CONNECT_IP and FAKE_SNI.** Default IP changed from `188.114.98.0` (a network address) to `104.18.38.202` (a real Cloudflare edge IP). Default SNI changed from `auth.vercel.com` to `cdnjs.cloudflare.com` (Cloudflare infrastructure, highest availability).
- Added 6 new unit tests: seed IP validation, sample_with_seeds behaviour, non-Cloudflare domain guard test, blacklist interaction with seeds. Total: 77 tests.
- Bumped version to 1.3.0.

### v1.2.0

- **Added internal Cloudflare IP scanner.** Scans random IPs from all official Cloudflare IPv4 ranges using a three-stage probe pipeline (TCP connect, TLS handshake, download speed). Probes run in parallel with configurable concurrency. Results are ranked by combined latency score.
- **Added auto mode** (`--auto`). Runs a scan at startup, picks the fastest clean IP, starts the proxy, and automatically fails over to the next-best IP when connections are blocked. Background rescanning keeps the IP list fresh.
- **Added SNI domain rotation.** Maintains a pool of Cloudflare-fronted domains with health tracking. Automatically rotates to a different SNI when one is blocked. Ships with a built-in list of 18 high-traffic domains. Users can override via `--sni-list` or `SNI_DOMAINS` in config.
- **Added failover connection tracker.** Monitors per-IP connection failures in a sliding window. When an IP hits 3 failures within 30 seconds, it's blacklisted and the proxy switches to the next available IP.
- **Added scan caching** (`--scan-cache`). Saves results to disk for instant startup on the next run.
- **Added live range fetching** (`--fetch-ranges`). Pulls the latest Cloudflare IPv4 ranges from cloudflare.com before scanning.
- **Fixed logging handler accumulation.** `setup_logging()` no longer adds duplicate handlers when called multiple times.
- **Fixed `fragment_data` off-by-one.** The last fragment now correctly includes all remaining data when `pos` advances past all specified sizes.
- **Fixed `parse_host_port` crash on non-numeric port.** Now validates port input and exits with a clear error message.
- Added `--scan`, `--scan-count`, `--scan-workers`, `--scan-timeout`, `--download`, `--rescan`, `--scan-cache`, `--sni-list`, `--ip-ranges`, `--fetch-ranges` CLI flags.
- Added 42 new unit tests for the scanner, SNI provider, probe, and failover modules.
- Bumped version to 1.2.0.

### v1.1.0

- **Fixed the seq_id problem** with `fake_sni` and `combined` methods. The old code sent the fake ClientHello as regular data on the same TCP stream, which the server would receive and try to parse as a real TLS record. This corrupted the handshake every time. Now on Linux with root, SNISPF uses `AF_PACKET` raw socket injection to send the fake ClientHello with an out-of-window TCP sequence number (`seq = ISN + 1 - len(fake)`). DPI parses it and whitelists the connection; the server drops it because the sequence number falls before its receive window. This is the same technique used by [patterniha's original tool](https://github.com/patterniha/SNI-Spoofing) and [the Go reimplementation](https://github.com/selfishblackberry177/sni-spoof).
- **Fixed `fake_sni` without raw sockets.** Previously it would send the fake ClientHello on the real TCP stream, breaking the TLS handshake. Now it falls back to fragmenting the real ClientHello at the SNI boundary instead of corrupting the connection.
- **Fixed `combined` without raw sockets.** Same issue -- no longer sends junk data on the real TCP stream. Falls back to fragmentation-only.
- **Fixed the `multi` fragment strategy timeout.** The old 5-byte chunk size produced 100+ fragments with 0.1s delay each, causing a 10+ second stall before the handshake could even complete. Bumped to 24-byte chunks (~22 fragments), which keeps the fragment count reasonable while still splitting the SNI across multiple packets.
- Added `raw_injector.py`: the raw packet sniffer and injector module. Monitors the TCP handshake via `AF_PACKET`, captures the SYN ISN and the 3rd ACK template, injects the fake ClientHello 1ms after the handshake completes, and confirms the server ignored it by watching for an ACK with `ack == ISN + 1`.
- Added `--no-raw` CLI flag to disable raw socket injection even when running as root.
- Platform capability detection now reports `af_packet` and `raw_injection` status.
- Bumped version to 1.1.0.

### v1.0.1

- Fixed `supported_versions` TLS extension in the fake ClientHello builder. The version list length byte was encoded as two bytes (`04 03`) instead of one (`04`), which shifted every extension after it by one byte. This corrupted `psk_key_exchange_modes`, `key_share`, and `padding`, making the fake ClientHello malformed. Strict TLS parsers and some DPI systems would reject it outright.
- Fixed the bidirectional relay task setup. The two relay directions (client-to-server and server-to-client) were referencing the wrong peer task during creation, which could cause one relay direction to fail to clean up when the other direction closed.
- Bumped version to 1.0.1.

---

## License

MIT License. See [LICENSE](LICENSE) for the full text.

---

## Acknowledgements

This project is a cross-platform conversion of [patterniha's original Windows-only SNI-Spoofing](https://github.com/patterniha/SNI-Spoofing) tool.

The raw socket injection logic (seq_id trick) was ported from [selfishblackberry177's Go reimplementation](https://github.com/selfishblackberry177/sni-spoof).

The scanner's probing methodology is inspired by [CFScanner](https://github.com/MortezaBashsiz/CFScanner) and [Cloudflare-Clean-IP-Scanner](https://github.com/bia-pain-bache/Cloudflare-Clean-IP-Scanner).

The DPI bypass techniques draw inspiration from the broader anti-censorship community, including [GoodbyeDPI](https://github.com/ValdikSS/GoodbyeDPI), [ByeDPI](https://github.com/hufrea/byedpi), [Zapret](https://github.com/bol-van/zapret), and [phantom-dpi](https://github.com/nickolaev/phantom-dpi).
