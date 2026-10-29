/*
 * SPDX-FileCopyrightText: NONE
 * SPDX-License-Identifier: GPL-2.0-or-later
 * Note: AI-generated contribution; no legal determination implied.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <stdint.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <linux/capability.h>
#include <linux/securebits.h>

int main(void)
{
	struct __user_cap_header_struct header = {
		.version = _LINUX_CAPABILITY_VERSION_3,
		.pid = 0,
	};
	struct __user_cap_data_struct data[_LINUX_CAPABILITY_U32S_3] = {{0}};
	unsigned long securebits;
	unsigned int cap_word = CAP_SETPCAP / 32;
	uint32_t cap_mask = 1U << (CAP_SETPCAP % 32);

	securebits = prctl(PR_GET_SECUREBITS, 0, 0, 0, 0);
	if ((long) securebits < 0) {
		perror("prctl(PR_GET_SECUREBITS)");
		return 1;
	}
	securebits |= SECBIT_KEEP_CAPS | SECBIT_KEEP_CAPS_LOCKED;
	if (prctl(PR_SET_SECUREBITS, securebits, 0, 0, 0) < 0) {
		perror("prctl(PR_SET_SECUREBITS)");
		return 2;
	}
	if (setresuid(9999, 9999, 9999) < 0) {
		perror("setresuid");
		return 3;
	}

	data[cap_word].effective = cap_mask;
	data[cap_word].permitted = cap_mask;
	if (syscall(SYS_capset, &header, data) < 0) {
		perror("capset(CAP_SETPCAP)");
		return 4;
	}

	errno = 0;
	if (setuid(0) != -1 || errno != EPERM) {
		fprintf(stderr, "CAP_SETUID remained active after CAP_SETPCAP-only capset\n");
		return 5;
	}
	if (prctl(PR_CAPBSET_DROP, CAP_CHOWN, 0, 0, 0) < 0) {
		perror("prctl(PR_CAPBSET_DROP)");
		return 6;
	}
	if (prctl(PR_CAPBSET_READ, CAP_CHOWN, 0, 0, 0) != 0) {
		fprintf(stderr, "dropped capability remained in the bounding set\n");
		return 7;
	}

	data[0] = (struct __user_cap_data_struct) { 0 };
	data[1] = (struct __user_cap_data_struct) { 0 };
	if (syscall(SYS_capset, &header, data) < 0) {
		perror("capset(empty)");
		return 8;
	}

	errno = 0;
	if (setuid(0) != -1 || errno != EPERM) {
		fprintf(stderr, "CAP_SETUID remained active after empty capset\n");
		return 9;
	}

	puts("capset and capability bounding-set emulation passed");
	return 0;
}
