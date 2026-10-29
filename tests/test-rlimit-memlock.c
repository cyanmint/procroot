/*
 * SPDX-FileCopyrightText: NONE
 * SPDX-License-Identifier: GPL-2.0-or-later
 * Note: AI-generated contribution; no legal determination implied.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <sys/resource.h>

static int check_limit(const char *operation, const struct rlimit *before,
		       const struct rlimit *after)
{
	if (after->rlim_cur > before->rlim_max ||
	    after->rlim_max > before->rlim_max ||
	    after->rlim_cur != before->rlim_max ||
	    after->rlim_max != before->rlim_max) {
		fprintf(stderr,
			"%s did not clamp to host hard limit: before=(%llu,%llu) "
			"after=(%llu,%llu)\n",
			operation,
			(unsigned long long) before->rlim_cur,
			(unsigned long long) before->rlim_max,
			(unsigned long long) after->rlim_cur,
			(unsigned long long) after->rlim_max);
		return -1;
	}
	return 0;
}

int main(void)
{
	struct rlimit before;
	struct rlimit requested = {
		.rlim_cur = RLIM_INFINITY,
		.rlim_max = RLIM_INFINITY,
	};
	struct rlimit after;
	struct rlimit previous;

	if (getrlimit(RLIMIT_MEMLOCK, &before) < 0) {
		perror("getrlimit before");
		return 1;
	}
	if (setrlimit(RLIMIT_MEMLOCK, &requested) < 0) {
		perror("setrlimit(RLIMIT_MEMLOCK, infinity)");
		return 2;
	}
	if (getrlimit(RLIMIT_MEMLOCK, &after) < 0) {
		perror("getrlimit after setrlimit");
		return 3;
	}
	if (check_limit("setrlimit", &before, &after) < 0)
		return 4;

	if (getrlimit(RLIMIT_MEMLOCK, &before) < 0) {
		perror("getrlimit before prlimit");
		return 5;
	}
	if (prlimit(0, RLIMIT_MEMLOCK, &requested, &previous) < 0) {
		perror("prlimit(RLIMIT_MEMLOCK, infinity)");
		return 6;
	}
	if (previous.rlim_cur != before.rlim_cur ||
	    previous.rlim_max != before.rlim_max) {
		fprintf(stderr, "prlimit returned incorrect old memlock limit\n");
		return 7;
	}
	if (getrlimit(RLIMIT_MEMLOCK, &after) < 0) {
		perror("getrlimit after prlimit");
		return 8;
	}
	if (check_limit("prlimit", &before, &after) < 0)
		return 9;

	puts("RLIMIT_MEMLOCK_HOST_LIMIT_CLAMP=PASS");
	return 0;
}
