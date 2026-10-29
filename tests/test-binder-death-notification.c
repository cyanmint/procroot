/*
 * SPDX-FileCopyrightText: NONE
 * SPDX-License-Identifier: GPL-2.0-or-later
 * Note: AI-generated contribution; no legal determination implied.
 */
/* Verify clearing a live Binder death notification returns its completion. */
#define _GNU_SOURCE
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <unistd.h>

struct binder_handle_cookie {
	uint32_t handle;
	uint64_t cookie;
} __attribute__((packed));

struct binder_write_read {
	uint64_t write_size;
	uint64_t write_consumed;
	uint64_t write_buffer;
	uint64_t read_size;
	uint64_t read_consumed;
	uint64_t read_buffer;
};

#define BINDER_SET_CONTEXT_MGR _IOW('b', 7, uint32_t)
#define BINDER_WRITE_READ _IOWR('b', 1, struct binder_write_read)
#define BC_REQUEST_DEATH_NOTIFICATION \
	_IOW('c', 14, struct binder_handle_cookie)
#define BC_CLEAR_DEATH_NOTIFICATION \
	_IOW('c', 15, struct binder_handle_cookie)
#define BR_CLEAR_DEATH_NOTIFICATION_DONE _IOR('r', 16, uint64_t)

static int run_client(int inherited_fd)
{
	const struct binder_handle_cookie notification = {
		.handle = 0,
		.cookie = 0x123456789abcdef0ULL,
	};
	uint32_t commands[] = {
		(uint32_t)BC_REQUEST_DEATH_NOTIFICATION,
		(uint32_t)BC_CLEAR_DEATH_NOTIFICATION,
	};
	uint8_t writes[sizeof(commands) + 2 * sizeof(notification)];
	uint8_t reads[sizeof(uint32_t) + sizeof(uint64_t)] = {};
	struct binder_write_read bwr = {};
	uint32_t response;
	uint64_t cookie;
	int fd;

	close(inherited_fd);
	fd = open("/dev/binder", O_RDWR | O_CLOEXEC);
	if (fd < 0) {
		perror("client open /dev/binder");
		return 10;
	}
	memcpy(writes, &commands[0], sizeof(commands[0]));
	memcpy(writes + sizeof(commands[0]), &notification,
	       sizeof(notification));
	memcpy(writes + sizeof(commands[0]) + sizeof(notification),
	       &commands[1], sizeof(commands[1]));
	memcpy(writes + 2 * sizeof(commands[0]) + sizeof(notification),
	       &notification, sizeof(notification));
	bwr = (struct binder_write_read) {
		.write_size = sizeof(writes),
		.write_buffer = (uint64_t)(uintptr_t)writes,
		.read_size = sizeof(reads),
		.read_buffer = (uint64_t)(uintptr_t)reads,
	};
	if (ioctl(fd, BINDER_WRITE_READ, &bwr) < 0) {
		perror("BINDER_WRITE_READ death notification");
		close(fd);
		return 11;
	}
	if (bwr.write_consumed != sizeof(writes)) {
		fprintf(stderr, "death write_consumed=%llu expected=%lu\n",
			(unsigned long long)bwr.write_consumed,
			(unsigned long)sizeof(writes));
		close(fd);
		return 12;
	}
	if (bwr.read_consumed != sizeof(reads)) {
		fprintf(stderr, "clear completion read_consumed=%llu expected=%lu\n",
			(unsigned long long)bwr.read_consumed,
			(unsigned long)sizeof(reads));
		close(fd);
		return 13;
	}
	memcpy(&response, reads, sizeof(response));
	memcpy(&cookie, reads + sizeof(response), sizeof(cookie));
	if (response != (uint32_t)BR_CLEAR_DEATH_NOTIFICATION_DONE ||
	    cookie != notification.cookie) {
		fprintf(stderr, "unexpected clear response=%#x cookie=%#llx\n",
			response, (unsigned long long)cookie);
		close(fd);
		return 14;
	}
	close(fd);
	puts("BINDER_CLEAR_DEATH_NOTIFICATION_DONE=PASS");
	fflush(stdout);
	return 0;
}

int main(void)
{
	uint32_t context_manager = 0;
	pid_t child;
	int status;
	int fd = open("/dev/binder", O_RDWR | O_CLOEXEC);

	if (fd < 0) {
		perror("open /dev/binder");
		return 1;
	}
	if (ioctl(fd, BINDER_SET_CONTEXT_MGR, &context_manager) < 0) {
		perror("BINDER_SET_CONTEXT_MGR");
		close(fd);
		return 2;
	}
	child = fork();
	if (child < 0) {
		perror("fork");
		close(fd);
		return 3;
	}
	if (child == 0)
		_exit(run_client(fd));
	if (waitpid(child, &status, 0) != child) {
		perror("waitpid");
		close(fd);
		return 4;
	}
	close(fd);
	if (!WIFEXITED(status))
		return 5;
	return WEXITSTATUS(status);
}
