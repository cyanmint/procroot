/*
 * SPDX-FileCopyrightText: NONE
 * SPDX-License-Identifier: GPL-2.0-or-later
 * Note: AI-generated contribution; no legal determination implied.
 */
#define _GNU_SOURCE
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char *argv[])
{
	char expected[PATH_MAX];
	char actual[PATH_MAX];

	if (argc != 1 || argv[0] == NULL) {
		fprintf(stderr, "unexpected arguments\n");
		return EXIT_FAILURE;
	}

	if (realpath(argv[0], expected) == NULL) {
		perror("realpath(argv[0])");
		return EXIT_FAILURE;
	}
	if (realpath("/proc/self/exe", actual) == NULL) {
		perror("realpath(/proc/self/exe)");
		return EXIT_FAILURE;
	}
	if (strcmp(expected, actual) != 0) {
		fprintf(stderr, "realpath mismatch: argv[0]=%s /proc/self/exe=%s\n",
			expected, actual);
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}
