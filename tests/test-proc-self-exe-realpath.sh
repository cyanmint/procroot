# SPDX-FileCopyrightText: NONE
# SPDX-License-Identifier: GPL-2.0-or-later
# Note: AI-generated contribution; no legal determination implied.
if [ ! -x "${ROOTFS}/bin/test-proc-self-exe-realpath" ]; then
    exit 125
fi

${PROOT} -N -r "${ROOTFS}" /bin/test-proc-self-exe-realpath || exit $?
${PROOT} -B -r "${ROOTFS}" /bin/test-proc-self-exe-realpath || exit $?
${PROOT} -N -B -r "${ROOTFS}" /bin/test-proc-self-exe-realpath
