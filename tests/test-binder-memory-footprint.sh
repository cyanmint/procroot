#!/bin/sh
# SPDX-FileCopyrightText: NONE
# SPDX-License-Identifier: GPL-2.0-or-later
# Note: AI-generated contribution; no legal determination implied.
set -eu

BIN=${ROOT_RAW:-../src/procroot}
SIZE_TOOL=${SIZE_TOOL:-size}
MAX_BSS_BYTES=${BINDER_MAX_BSS_BYTES:-67108864}

OUTPUT=$("$SIZE_TOOL" -B "$BIN")
BSS_BYTES=$(printf '%s\n' "$OUTPUT" | awk 'NR == 2 { print $3 }')
case "$BSS_BYTES" in
    ''|*[!0-9]*)
        echo "BINDER_STATIC_BSS=FAIL unreadable-size"
        exit 1
        ;;
esac
if [ "$BSS_BYTES" -gt "$MAX_BSS_BYTES" ]; then
    echo "BINDER_STATIC_BSS=FAIL bytes=$BSS_BYTES limit=$MAX_BSS_BYTES"
    exit 1
fi
echo "BINDER_STATIC_BSS=PASS bytes=$BSS_BYTES limit=$MAX_BSS_BYTES"
