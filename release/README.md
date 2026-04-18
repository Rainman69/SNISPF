# SNISPF — Release Artifacts Guide

This folder contains everything needed to package SNISPF for end users
**without forcing them to install Python, pip, or any build tools**. Pick
whichever delivery format fits your audience.

```
release/
├── docker/
│   ├── Dockerfile.alpine      ← smallest image (~60 MB)
│   ├── Dockerfile.debian      ← best compatibility (default `latest`)
│   ├── Dockerfile.ubuntu      ← familiar Ubuntu environment
│   ├── Dockerfile.windows     ← Windows container hosts
│   └── docker-compose.yml     ← one-file stack, just `docker compose up`
├── scripts/
│   ├── build_binary.sh        ← build standalone binary on Linux/macOS
│   ├── build_binary.ps1       ← build standalone binary on Windows
│   ├── snispf.sh              ← double-clickable launcher (Linux/macOS)
│   ├── snispf.bat             ← double-clickable launcher (Windows cmd)
│   ├── snispf.ps1             ← launcher (Windows PowerShell)
│   ├── install.sh             ← one-line installer for Linux/macOS
│   └── install.ps1            ← one-line installer for Windows
└── systemd/
    └── snispf.service         ← Linux systemd unit
```

---

## 1. Docker images (zero install for the end user)

The user only needs Docker. Hand them **one** of the prebuilt tarballs and
they are done — no `docker build`, no Python, no pip.

### Build & export the tarball (you, the maintainer)

```bash
# Pick a flavor: alpine | debian | ubuntu
docker build -f release/docker/Dockerfile.alpine -t snispf:alpine .
docker save snispf:alpine | gzip > snispf-alpine.tar.gz
```

### Run on the user's machine (zero install)

```bash
# 1. Load the image
gunzip -c snispf-alpine.tar.gz | docker load

# 2. Run with default config
docker run --rm -p 40443:40443 snispf:alpine

# Or with a custom config
docker run --rm -p 40443:40443 \
  -v "$PWD/config.json:/app/config.json:ro" \
  snispf:alpine
```

### Or use docker-compose (single file)

Drop `release/docker/docker-compose.yml` into a folder and run:

```bash
docker compose up -d
```

The compose file pulls `ghcr.io/rainman69/snispf:latest`, so the user does
not even need a tarball — just one YAML file plus Docker.

| Flavor | Base image | Final size | Notes |
|--------|-----------|-----------|-------|
| `alpine` | `python:3.12-alpine` | ~60 MB | Smallest, musl libc |
| `debian` | `python:3.12-slim-bookworm` | ~140 MB | Default, glibc, best compat |
| `ubuntu` | `ubuntu:24.04` | ~250 MB | Familiar environment |
| `windows` | `mcr.microsoft.com/windows/servercore:ltsc2022` | ~5 GB | Windows container hosts only |

---

## 2. Standalone single-file binaries (no Python required)

Built with PyInstaller. The user gets **one executable file** they can
copy anywhere and run.

### Build locally

```bash
# Linux / macOS
bash release/scripts/build_binary.sh
# → dist/snispf-linux-x86_64   (or darwin-arm64, etc.)

# Windows (PowerShell)
.\release\scripts\build_binary.ps1
# → dist\snispf-windows-x86_64.exe
```

### Run on the user's machine

```bash
# Linux / macOS
chmod +x snispf-linux-x86_64
./snispf-linux-x86_64 --auto

# Windows (double-click or)
snispf-windows-x86_64.exe --auto
```

The CI workflow at `.github/workflows/release.yml` builds these for all
five OS/arch combos automatically when you push a `vX.Y.Z` tag.

---

## 3. Portable bundles

Each release also ships a `.tar.gz` (or `.zip` on Windows) that contains:

- the standalone binary,
- a default `config.json`,
- a launcher script (`snispf.sh` / `snispf.bat` / `snispf.ps1`),
- `README.md` and `LICENSE`.

The user just extracts the archive and double-clicks the launcher — no
PATH editing needed.

---

## 4. One-line installer scripts

For users who want a "system-installed" feel without dealing with pip:

```bash
# Linux / macOS
curl -fsSL https://raw.githubusercontent.com/Rainman69/SNISPF/main/release/scripts/install.sh | bash
```

```powershell
# Windows (PowerShell)
iwr -useb https://raw.githubusercontent.com/Rainman69/SNISPF/main/release/scripts/install.ps1 | iex
```

These scripts query the GitHub Releases API, download the matching
binary for the user's OS/arch, install it (and a default config), and
add it to `PATH` on Windows.

---

## 5. systemd service (Linux servers)

```bash
sudo cp release/systemd/snispf.service /etc/systemd/system/snispf.service
sudo mkdir -p /etc/snispf && sudo cp config.json /etc/snispf/config.json
sudo systemctl daemon-reload
sudo systemctl enable --now snispf
journalctl -u snispf -f
```

The unit grants `CAP_NET_RAW` + `CAP_NET_ADMIN` so the seq_id raw-packet
trick works without running as full root, and uses
`Restart=on-failure` so it survives DPI / network blips.

---

## 6. Cutting a release

1. Bump the version in `pyproject.toml` and `sni_spoofing/__init__.py`
   (keep them in sync).
2. Commit on `main`, then tag and push:
   ```bash
   git commit -am "release: v1.9.0"
   git tag v1.9.0
   git push origin main --tags
   ```
3. The `Release` workflow automatically:
   - builds 5 standalone binaries (Linux x64/arm64, macOS x64/arm64, Win x64),
   - builds 5 portable bundles (binary + launcher + config, tar.gz or zip),
   - builds Python wheel + sdist,
   - builds & pushes 3 multi-arch Docker images to GHCR
     (`alpine` / `debian` / `ubuntu`, `linux/amd64` + `linux/arm64`),
   - exports each Docker image as a loadable `.tar.gz`,
   - generates `SHA256SUMS.txt`,
   - publishes a GitHub Release with every artifact attached and
     auto-generated release notes.

No further manual work is required — end users just pick whichever file
they prefer from the Releases page.

### Re-running a release

If the workflow fails only at the "Publish" step (rare, but possible if
GitHub artifact storage hiccups), you can re-run **just the Publish job**
from the Actions tab — all previously built artifacts are reused, no
rebuild is needed.

### Dry-run / manual dispatch

You can also trigger the workflow manually from the Actions tab using
"Run workflow" on any branch. In that case, every job runs (so you can
verify the build is green) but **no GitHub Release is published** — the
publish step only fires for version tags (`refs/tags/v*`).
