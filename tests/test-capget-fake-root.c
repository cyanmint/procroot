/*
 * SPDX-FileCopyrightText: NONE
 * SPDX-License-Identifier: GPL-2.0-or-later
 * Note: AI-generated contribution; no legal determination implied.
 */
#define _GNU_SOURCE
#include <linux/capability.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

static int read_capability(unsigned int capability, int *effective,
			   int *permitted)
{
	struct __user_cap_header_struct header = {
		.version = _LINUX_CAPABILITY_VERSION_3,
		.pid = 0,
	};
	struct __user_cap_data_struct data[_LINUX_CAPABILITY_U32S_3] = {{0}};
	unsigned int word = capability / 32;
	uint32_t mask = 1U << (capability % 32);

	if (syscall(SYS_capget, &header, data) < 0) {
		perror("capget");
		return -1;
	}
	*effective = (data[word].effective & mask) != 0;
	*permitted = (data[word].permitted & mask) != 0;
	return 0;
}

static int read_cap_block_suspend(int *effective, int *permitted)
{
	return read_capability(CAP_BLOCK_SUSPEND, effective, permitted);
}

static int require_capability(int expected)
{
	int effective;
	int permitted;

	if (read_cap_block_suspend(&effective, &permitted) < 0)
		return -1;
	if (effective != expected || permitted != expected) {
		fprintf(stderr, "CAP_BLOCK_SUSPEND effective=%d permitted=%d expected=%d\n",
			effective, permitted, expected);
		return -1;
	}
	return 0;
}

static int set_system_capabilities(void)
{
	struct __user_cap_header_struct header = {
		.version = _LINUX_CAPABILITY_VERSION_3,
		.pid = 0,
	};
	struct __user_cap_data_struct data[_LINUX_CAPABILITY_U32S_3] = {{0}};
	uint64_t requested = (UINT64_C(1) << CAP_BLOCK_SUSPEND) |
		(UINT64_C(1) << CAP_SYS_NICE);
	unsigned int word;

	for (word = 0; word < _LINUX_CAPABILITY_U32S_3; word++) {
		uint32_t value = (uint32_t)(requested >> (word * 32));
		data[word].effective = value;
		data[word].permitted = value;
	}

	if (syscall(SYS_capset, &header, data) < 0) {
		perror("capset(system capabilities)");
		return -1;
	}
	return 0;
}

int main(int argc, char **argv)
{
	struct __user_cap_header_struct header = {
		.version = _LINUX_CAPABILITY_VERSION_3,
		.pid = 0,
	};
	struct __user_cap_data_struct empty[_LINUX_CAPABILITY_U32S_3] = {{0}};
	int expect_root;

	if (argc != 2 || (strcmp(argv[1], "root") != 0 &&
			  strcmp(argv[1], "nonroot") != 0 &&
			  strcmp(argv[1], "clear") != 0 &&
			  strcmp(argv[1], "drop") != 0 &&
			  strcmp(argv[1], "system") != 0)) {
		fprintf(stderr, "usage: %s root|nonroot|clear|drop|system\n", argv[0]);
		return 1;
	}
	expect_root = strcmp(argv[1], "nonroot") != 0;
	if ((getuid() == 0) != expect_root) {
		fprintf(stderr, "unexpected virtual uid: %u\n", (unsigned int) getuid());
		return 2;
	}
	if (strcmp(argv[1], "nonroot") == 0) {
		if (require_capability(0) < 0)
			return 3;
		puts("CAPGET_FAKE_ROOT_NONROOT=PASS");
		return 0;
	}
	if (require_capability(1) < 0)
		return 4;
	if (strcmp(argv[1], "system") == 0) {
		int effective;
		int permitted;

		if (setresuid(1000, 1000, 1000) < 0) {
			perror("setresuid(system)");
			return 9;
		}
		if (getuid() != 1000 || set_system_capabilities() < 0)
			return 10;
		if (require_capability(1) < 0 ||
		    read_capability(CAP_SYS_NICE, &effective, &permitted) < 0)
			return 11;
		if (effective || permitted) {
			fprintf(stderr, "CAP_SYS_NICE effective=%d permitted=%d expected=0\n",
				effective, permitted);
			return 12;
		}
		puts("CAPGET_FAKE_ROOT_SYSTEM_CAP_BLOCK_SUSPEND=PASS");
		return 0;
	}
	if (strcmp(argv[1], "clear") == 0) {
		if (syscall(SYS_capset, &header, empty) < 0) {
			perror("capset(empty)");
			return 5;
		}
		if (require_capability(0) < 0)
			return 6;
		puts("CAPGET_FAKE_ROOT_CAPSET_CLEAR=PASS");
		return 0;
	}
	if (strcmp(argv[1], "drop") == 0) {
		if (setresuid(9999, 9999, 9999) < 0) {
			perror("setresuid");
			return 7;
		}
		if (require_capability(0) < 0)
			return 8;
		puts("CAPGET_FAKE_ROOT_UID_DROP=PASS");
		return 0;
	}

	puts("CAPGET_FAKE_ROOT_ROOT=PASS");
	return 0;
}
