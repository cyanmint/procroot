# SPDX-FileCopyrightText: NONE
# SPDX-License-Identifier: GPL-2.0-or-later
# Note: AI-generated contribution; no legal determination implied.
TMP=$(mktemp -d) || exit 1
trap 'rm -rf "$TMP"' EXIT

PROOT_TMP_DIR="$TMP" ${PROOT} -B -r / -b "$TMP:/proot-mounts-pid1-test" sh -c \
    'found=0
     while read -r source mountpoint rest; do
         [ "$mountpoint" = "/proot-mounts-pid1-test" ] && found=1
     done < /proc/mounts
     [ "$found" -eq 0 ] || exit 1
     sh -c '\''found=0; while read -r source mountpoint rest; do [ "$mountpoint" = "/proot-mounts-pid1-test" ] && found=1; done < /proc/mounts; [ "$found" -eq 1 ]'\'' || exit 2' || exit $?
printf '%s\n' 'PASS: PID 1 uses native /proc/mounts; child sees runtime bindings'
