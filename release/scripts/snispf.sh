#!/usr/bin/env bash
# Convenience launcher for SNISPF on Linux / macOS.
# Place this script next to the snispf binary (or installed package) and
# double-click / run it. It will pick the best available entry point.
#
# Pass any extra CLI flags after the script name:
#     ./snispf.sh --auto -m combined
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$DIR"

CONFIG=""
if [[ -f "$DIR/config.json" ]]; then
  CONFIG=(--config "$DIR/config.json")
fi

# 1) Prefer the bundled standalone binary
for cand in snispf-linux-x86_64 snispf-linux-arm64 snispf-darwin-x86_64 snispf-darwin-arm64 snispf; do
  if [[ -x "$DIR/$cand" ]]; then
    exec "$DIR/$cand" "${CONFIG[@]}" "$@"
  fi
done

# 2) Fall back to a system-installed snispf
if command -v snispf >/dev/null 2>&1; then
  exec snispf "${CONFIG[@]}" "$@"
fi

# 3) Fall back to running from source
if [[ -f "$DIR/run.py" ]]; then
  exec python3 "$DIR/run.py" "${CONFIG[@]}" "$@"
fi

echo "ERROR: could not locate the snispf binary, package, or run.py" >&2
exit 1
