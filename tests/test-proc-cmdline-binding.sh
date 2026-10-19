#!/bin/sh
set -eu

: "${PROOT:?PROOT must name the procroot executable}"
: "${ROOTFS:?ROOTFS must name the guest root filesystem}"

fixture=$(mktemp "${TMPDIR:-/tmp}/procroot-cmdline.XXXXXX")
trap 'rm -f "$fixture"' EXIT HUP INT TERM

expected='androidboot.hardware=qcom androidboot.fstab_suffix=default'
printf '%s\n' "$expected" > "$fixture"

guest_cat=/bin/cat
if [ -x "$ROOTFS/system/bin/cat" ]; then
	guest_cat=/system/bin/cat
fi

actual=$($PROOT -N -r "$ROOTFS" -b "$fixture:/proc/cmdline" "$guest_cat" /proc/cmdline)
if [ "$actual" != "$expected" ]; then
	printf 'FAIL: /proc/cmdline was <%s>, expected <%s>\n' "$actual" "$expected" >&2
	exit 1
fi

printf 'PASS: explicit /proc/cmdline binding is visible with PID virtualization\n'
