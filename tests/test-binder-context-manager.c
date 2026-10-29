/*
 * SPDX-FileCopyrightText: NONE
 * SPDX-License-Identifier: GPL-2.0-or-later
 * Note: AI-generated contribution; no legal determination implied.
 */
#include <errno.h>
#include <fcntl.h>
#include <linux/ioctl.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define BINDER_SET_CONTEXT_MGR _IOW('b', 7, uint32_t)

static int claim_context_manager(void)
{
	uint32_t value = 0;
	int fd = open("/dev/binder", O_RDONLY | O_CLOEXEC);

	if (fd < 0) {
		perror("open /dev/binder");
		return -1;
	}
	if (ioctl(fd, BINDER_SET_CONTEXT_MGR, &value) < 0) {
		perror("BINDER_SET_CONTEXT_MGR");
		close(fd);
		return -1;
	}
	close(fd);
	return 0;
}

int main(void)
{
	pid_t child;
	int status;

	child = fork();
	if (child < 0) {
		perror("fork");
		return 1;
	}
	if (child == 0)
		_exit(claim_context_manager() == 0 ? 0 : 2);

	if (waitpid(child, &status, 0) != child) {
		perror("waitpid");
		return 3;
	}
	if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
		fprintf(stderr, "child context manager failed: status=%#x\n", status);
		return 4;
	}
	puts("CONTEXT_MANAGER_CHILD=PASS");

	if (claim_context_manager() < 0)
		return 5;
	puts("CONTEXT_MANAGER_RECLAIM=PASS");
	return 0;
}
