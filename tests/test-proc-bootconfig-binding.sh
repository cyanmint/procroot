#!/bin/sh
# SPDX-FileCopyrightText: NONE
# SPDX-License-Identifier: GPL-2.0-or-later
# Note: AI-generated contribution; no legal determination implied.
# A bound bootconfig must win over PID-virtualization's proc mirror.
set -eu

: "${PROOT:?set PROOT to the PRoot command}"
FIXTURE=$(mktemp "${TMPDIR:-/tmp}/proot-bootconfig.XXXXXX")
trap 'rm -f "$FIXTURE"' 0 1 2 15
printf 'androidboot.hardware = "test"\n' > "$FIXTURE"

$PROOT -N -B -b "$FIXTURE:/proc/bootconfig" cat /proc/bootconfig |
	cmp - "$FIXTURE"
printf 'PROC_BOOTCONFIG_BIND=PASS\n'
