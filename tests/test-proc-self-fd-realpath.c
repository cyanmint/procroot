/*
 * SPDX-FileCopyrightText: NONE
 * SPDX-License-Identifier: GPL-2.0-or-later
 * Note: AI-generated contribution; no legal determination implied.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

int main(void)
{
	char resolved[PATH_MAX];
	char expected[PATH_MAX];
	struct stat status;
	int length;

	if (realpath("/proc/self/fd", resolved) == NULL) {
		fprintf(stderr, "PROC_SELF_FD_REALPATH=FAIL errno=%d (%s)\n",
			errno, strerror(errno));
		return 1;
	}

	length = snprintf(expected, sizeof(expected), "/proc/%ld/fd",
			  (long) getpid());
	if (length < 0 || (size_t) length >= sizeof(expected)) {
		fprintf(stderr, "PROC_SELF_FD_EXPECTED_PATH=FAIL\n");
		return 1;
	}
	if (strcmp(resolved, expected) != 0) {
		fprintf(stderr, "PROC_SELF_FD_PATH=FAIL expected=%s actual=%s\n",
			expected, resolved);
		return 1;
	}
	if (stat(resolved, &status) != 0 || !S_ISDIR(status.st_mode)) {
		fprintf(stderr, "PROC_SELF_FD_DIRECTORY=FAIL errno=%d (%s)\n",
			errno, strerror(errno));
		return 1;
	}

	puts("PROC_SELF_FD_REALPATH=PASS");
	return 0;
}
