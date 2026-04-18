#!/usr/bin/env bash
# One-line installer for SNISPF (Linux / macOS).
# Downloads the latest release binary that matches your OS+arch, installs it
# to /usr/local/bin/snispf, and drops a default config.json into ~/.config/snispf/.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/Rainman69/SNISPF/main/release/scripts/install.sh | bash
set -euo pipefail

REPO="Rainman69/SNISPF"
INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"
CONFIG_DIR="${CONFIG_DIR:-$HOME/.config/snispf}"

OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
ARCH="$(uname -m)"
case "$ARCH" in
  x86_64|amd64) ARCH=x86_64 ;;
  aarch64|arm64) ARCH=arm64 ;;
  *) echo "Unsupported arch: $ARCH" >&2; exit 1 ;;
esac

ASSET="snispf-${OS}-${ARCH}"
[[ "$OS" == *mingw* || "$OS" == *cygwin* || "$OS" == *msys* ]] && \
  { echo "Use install.ps1 on Windows."; exit 1; }

echo "[*] Looking up the latest SNISPF release..."
LATEST_TAG="$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" \
              | grep -o '"tag_name": *"[^"]*"' | head -n1 | cut -d'"' -f4)"
[[ -z "$LATEST_TAG" ]] && { echo "Failed to detect latest release." >&2; exit 1; }
URL="https://github.com/$REPO/releases/download/$LATEST_TAG/$ASSET"

echo "[*] Downloading $ASSET ($LATEST_TAG)..."
TMP="$(mktemp)"
curl -fL --progress-bar -o "$TMP" "$URL"

SUDO=""
[[ ! -w "$INSTALL_DIR" ]] && SUDO="sudo"
echo "[*] Installing to $INSTALL_DIR/snispf..."
$SUDO install -m 0755 "$TMP" "$INSTALL_DIR/snispf"
rm -f "$TMP"

mkdir -p "$CONFIG_DIR"
if [[ ! -f "$CONFIG_DIR/config.json" ]]; then
  curl -fsSL "https://raw.githubusercontent.com/$REPO/$LATEST_TAG/config.json" \
       -o "$CONFIG_DIR/config.json" || true
fi

echo
echo "[+] Installed: $(snispf --version 2>/dev/null || echo "$INSTALL_DIR/snispf")"
echo "    Default config: $CONFIG_DIR/config.json"
echo "    Try:  snispf --help"
