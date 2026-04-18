#!/usr/bin/env bash
# Build a standalone single-file SNISPF executable for the current OS/arch
# (Linux or macOS). Output ends up in ./dist/snispf[-os-arch].
#
# Usage:   bash release/scripts/build_binary.sh
# Needs:   python3 >= 3.8, pip
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$PROJECT_ROOT"

OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
ARCH="$(uname -m)"
case "$ARCH" in
  x86_64|amd64) ARCH=x86_64 ;;
  aarch64|arm64) ARCH=arm64 ;;
esac

OUT_NAME="snispf-${OS}-${ARCH}"
echo "[*] Building $OUT_NAME ..."

python3 -m pip install --upgrade pip wheel >/dev/null
python3 -m pip install --upgrade pyinstaller >/dev/null
python3 -m pip install . >/dev/null

python3 -m PyInstaller \
    --onefile \
    --name "$OUT_NAME" \
    --console \
    --clean \
    --noconfirm \
    --collect-all sni_spoofing \
    --add-data "config.json:." \
    run.py

echo
echo "[+] Done. Binary at: dist/$OUT_NAME"
echo "    Run with:  ./dist/$OUT_NAME --help"
