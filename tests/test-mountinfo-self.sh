# SPDX-FileCopyrightText: NONE
# SPDX-License-Identifier: GPL-2.0-or-later
# Note: AI-generated contribution; no legal determination implied.
TMP=$(mktemp -d) || exit 1
trap 'rm -rf "$TMP"' EXIT

PROOT_TMP_DIR="$TMP" ${PROOT} -B -r / -b "$TMP:/proot-mountinfo-test" sh -c \
    'grep -q " /proot-mountinfo-test " /proc/self/mountinfo || exit 1; grep -q " /proot-mountinfo-test " /proc/mounts || exit 2' || exit $?
printf '%s\n' 'PASS: runtime bindings appear in /proc/self/mountinfo and /proc/mounts'
