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
#include <unistd.h>

static int after_exec(const char *fd_text)
{
	char *end;
	long fd;
	int number;

	errno = 0;
	fd = strtol(fd_text, &end, 10);
	if (errno != 0 || end == fd_text || *end != '\0' || fd < 0 || fd > 0x7fffffff) {
		fprintf(stderr, "invalid inherited fd: %s\n", fd_text);
		return 2;
	}

	number = ioctl((int)fd, LOOP_CTL_GET_FREE);
	if (number < 0) {
		fprintf(stderr, "LOOP_CTL_GET_FREE_AFTER_EXEC_FAIL errno=%d (%s)\n",
			errno, strerror(errno));
		return 1;
	}

	printf("LOOP_CTL_GET_FREE_AFTER_EXEC_PASS index=%d\n", number);
	return 0;
}

int main(int argc, char **argv)
{
	int fd;
	char fd_text[32];
	char *child_argv[4];

	if (argc == 3 && strcmp(argv[1], "--after-exec") == 0)
		return after_exec(argv[2]);
	if (argc != 1) {
		fprintf(stderr, "usage: %s\n", argv[0]);
		return 2;
	}

	fd = open("/dev/loop-control", O_RDWR);
	if (fd < 0) {
		fprintf(stderr, "open /dev/loop-control failed errno=%d (%s)\n",
			errno, strerror(errno));
		return 1;
	}
	printf("LOOP_CONTROL_OPEN_BEFORE_EXEC_PASS fd=%d\n", fd);
	if (fflush(stdout) != 0) {
		perror("fflush");
		return 1;
	}

	if (snprintf(fd_text, sizeof(fd_text), "%d", fd) >= (int)sizeof(fd_text)) {
		fprintf(stderr, "fd string is too long\n");
		return 1;
	}
	child_argv[0] = argv[0];
	child_argv[1] = "--after-exec";
	child_argv[2] = fd_text;
	child_argv[3] = NULL;
	execv(argv[0], child_argv);
	fprintf(stderr, "execv %s failed errno=%d (%s)\n", argv[0], errno,
		strerror(errno));
	return 1;
}
