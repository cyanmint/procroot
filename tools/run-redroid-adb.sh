#!/usr/bin/env bash
set -eu

ROOTFS=${1:-/home/switch/redroid9}
PROOT=${PROOT:-"$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)/src/procroot"}
PORT=${ADB_PORT:-5555}

exec python3 "$(dirname -- "$0")/proot-adb-bridge.py" \
  --rootfs "$ROOTFS" \
  --procroot "$PROOT" \
  --port "$PORT"
