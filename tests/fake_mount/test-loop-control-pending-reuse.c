/*
 * SPDX-FileCopyrightText: NONE
 * SPDX-License-Identifier: GPL-2.0-or-later
 * Note: AI-generated contribution; no legal determination implied.
 */
#include <errno.h>
#include <fcntl.h>
#include <linux/loop.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define ITERATIONS 80

static int probe(int iteration)
{
	int fd;
	int number;

	fd = open("/dev/loop-control", O_RDWR);
	if (fd < 0) {
		fprintf(stderr,
			"LOOP_CTL_PENDING_REUSE_FAIL iteration=%d stage=open errno=%d (%s)\n",
			iteration, errno, strerror(errno));
		return 1;
	}

	number = ioctl(fd, LOOP_CTL_GET_FREE);
	if (number < 0) {
		fprintf(stderr,
			"LOOP_CTL_PENDING_REUSE_FAIL iteration=%d stage=ioctl errno=%d (%s)\n",
			iteration, errno, strerror(errno));
		return 1;
	}
	if (close(fd) < 0) {
		fprintf(stderr,
			"LOOP_CTL_PENDING_REUSE_FAIL iteration=%d stage=close errno=%d (%s)\n",
			iteration, errno, strerror(errno));
		return 1;
	}
	return 0;
}

int main(int argc, char **argv)
{
	int iteration;

	if (argc == 3 && strcmp(argv[1], "--probe") == 0) {
		char *end;
		long value;

		errno = 0;
		value = strtol(argv[2], &end, 10);
		if (errno != 0 || end == argv[2] || *end != '\0' ||
		    value < 0 || value >= ITERATIONS) {
			fprintf(stderr, "invalid iteration: %s\n", argv[2]);
			return 2;
		}
		return probe((int)value);
	}
	if (argc != 1) {
		fprintf(stderr, "usage: %s\n", argv[0]);
		return 2;
	}

	for (iteration = 0; iteration < ITERATIONS; iteration++) {
		pid_t child;
		int status;
		char iteration_text[16];

		child = fork();
		if (child < 0) {
			fprintf(stderr, "fork failed errno=%d (%s)\n", errno,
				strerror(errno));
			return 1;
		}
		if (child == 0) {
			char *child_argv[4];

			snprintf(iteration_text, sizeof(iteration_text), "%d", iteration);
			child_argv[0] = argv[0];
			child_argv[1] = "--probe";
			child_argv[2] = iteration_text;
			child_argv[3] = NULL;
			execv(argv[0], child_argv);
			fprintf(stderr, "execv %s failed errno=%d (%s)\n", argv[0],
				errno, strerror(errno));
			_exit(127);
		}
		if (waitpid(child, &status, 0) != child) {
			fprintf(stderr, "waitpid failed errno=%d (%s)\n", errno,
				strerror(errno));
			return 1;
		}
		if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
			fprintf(stderr, "LOOP_CTL_PENDING_REUSE_PARENT_FAIL iteration=%d\n",
				iteration);
			return 1;
		}
	}

	printf("LOOP_CTL_PENDING_REUSE_PASS iterations=%d\n", ITERATIONS);
	return 0;
}
