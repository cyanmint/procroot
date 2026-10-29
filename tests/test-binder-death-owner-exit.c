/*
 * SPDX-FileCopyrightText: NONE
 * SPDX-License-Identifier: GPL-2.0-or-later
 * Note: AI-generated contribution; no legal determination implied.
 */
/* Verify a death notification is delivered when its owner exits. */
#define _GNU_SOURCE
#include <fcntl.h>
#include <poll.h>
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
#define BC_DEAD_BINDER_DONE _IOW('c', 16, uint64_t)
#define BR_DEAD_BINDER _IOR('r', 15, uint64_t)

static int write_byte(int fd)
{
	char byte = 'x';
	return write(fd, &byte, sizeof(byte)) == sizeof(byte) ? 0 : -1;
}

static int read_byte(int fd)
{
	char byte;
	return read(fd, &byte, sizeof(byte)) == sizeof(byte) ? 0 : -1;
}

static int manager_process(int ready_fd, int stop_fd)
{
	uint32_t context_manager = 0;
	int fd = open("/dev/binder", O_RDWR | O_CLOEXEC);

	if (fd < 0) {
		perror("manager open /dev/binder");
		return 10;
	}
	if (ioctl(fd, BINDER_SET_CONTEXT_MGR, &context_manager) < 0) {
		perror("BINDER_SET_CONTEXT_MGR");
		close(fd);
		return 11;
	}
	if (write_byte(ready_fd) < 0 || read_byte(stop_fd) < 0) {
		perror("manager synchronization");
		close(fd);
		return 12;
	}
	close(fd);
	return 0;
}

static int client_process(int start_fd, int registered_fd)
{
	const struct binder_handle_cookie notification = {
		.handle = 0,
		.cookie = 0x123456789abcdef0ULL,
	};
	uint32_t command = (uint32_t)BC_REQUEST_DEATH_NOTIFICATION;
	uint8_t writes[sizeof(command) + sizeof(notification)];
	uint8_t reads[sizeof(uint32_t) + sizeof(uint64_t)] = {};
	struct binder_write_read bwr = {};
	struct pollfd poll_fd;
	uint32_t response;
	uint64_t cookie;
	int fd;

	if (read_byte(start_fd) < 0) {
		perror("client start synchronization");
		return 20;
	}
	close(start_fd);
	fd = open("/dev/binder", O_RDWR | O_CLOEXEC);
	if (fd < 0) {
		perror("client open /dev/binder");
		return 21;
	}
	memcpy(writes, &command, sizeof(command));
	memcpy(writes + sizeof(command), &notification, sizeof(notification));
	bwr.write_size = sizeof(writes);
	bwr.write_buffer = (uint64_t)(uintptr_t)writes;
	if (ioctl(fd, BINDER_WRITE_READ, &bwr) < 0 ||
	    bwr.write_consumed != sizeof(writes)) {
		perror("BC_REQUEST_DEATH_NOTIFICATION");
		close(fd);
		return 22;
	}
	if (write_byte(registered_fd) < 0) {
		perror("client registration synchronization");
		close(fd);
		return 23;
	}
	close(registered_fd);

	poll_fd = (struct pollfd) { .fd = fd, .events = POLLIN };
	if (poll(&poll_fd, 1, 5000) != 1 ||
	    (poll_fd.revents & POLLIN) == 0) {
		fprintf(stderr, "death notification was not made readable\n");
		close(fd);
		return 24;
	}
	bwr = (struct binder_write_read) {
		.read_size = sizeof(reads),
		.read_buffer = (uint64_t)(uintptr_t)reads,
	};
	if (ioctl(fd, BINDER_WRITE_READ, &bwr) < 0) {
		perror("BINDER_WRITE_READ BR_DEAD_BINDER");
		close(fd);
		return 25;
	}
	if (bwr.read_consumed != sizeof(reads)) {
		fprintf(stderr, "death read_consumed=%llu expected=%lu\n",
			(unsigned long long)bwr.read_consumed,
			(unsigned long)sizeof(reads));
		close(fd);
		return 26;
	}
	memcpy(&response, reads, sizeof(response));
	memcpy(&cookie, reads + sizeof(response), sizeof(cookie));
	if (response != (uint32_t)BR_DEAD_BINDER ||
	    cookie != notification.cookie) {
		fprintf(stderr, "unexpected death response=%#x cookie=%#llx\n",
			response, (unsigned long long)cookie);
		close(fd);
		return 27;
	}
	command = (uint32_t)BC_DEAD_BINDER_DONE;
	memcpy(writes, &command, sizeof(command));
	memcpy(writes + sizeof(command), &cookie, sizeof(cookie));
	bwr = (struct binder_write_read) {
		.write_size = sizeof(command) + sizeof(cookie),
		.write_buffer = (uint64_t)(uintptr_t)writes,
	};
	if (ioctl(fd, BINDER_WRITE_READ, &bwr) < 0 ||
	    bwr.write_consumed != sizeof(command) + sizeof(cookie)) {
		perror("BC_DEAD_BINDER_DONE");
		close(fd);
		return 28;
	}
	close(fd);
	puts("BINDER_DEAD_BINDER_OWNER_EXIT=PASS");
	fflush(stdout);
	return 0;
}

int main(void)
{
	int ready[2], stop[2], start[2], registered[2];
	pid_t manager, client;
	int manager_status, client_status;

	if (pipe(ready) < 0 || pipe(stop) < 0 || pipe(start) < 0 ||
	    pipe(registered) < 0) {
		perror("pipe");
		return 1;
	}
	manager = fork();
	if (manager < 0) {
		perror("fork manager");
		return 2;
	}
	if (manager == 0) {
		close(ready[0]);
		close(stop[1]);
		close(start[0]);
		close(start[1]);
		close(registered[0]);
		close(registered[1]);
		_exit(manager_process(ready[1], stop[0]));
	}
	close(ready[1]);
	close(stop[0]);
	if (read_byte(ready[0]) < 0) {
		perror("manager ready synchronization");
		return 3;
	}
	close(ready[0]);

	client = fork();
	if (client < 0) {
		perror("fork client");
		return 4;
	}
	if (client == 0) {
		close(stop[1]);
		close(start[1]);
		close(registered[0]);
		_exit(client_process(start[0], registered[1]));
	}
	close(start[0]);
	close(registered[1]);
	if (write_byte(start[1]) < 0 || read_byte(registered[0]) < 0) {
		perror("client registration synchronization");
		return 5;
	}
	close(start[1]);
	close(registered[0]);
	if (write_byte(stop[1]) < 0) {
		perror("manager stop synchronization");
		return 6;
	}
	close(stop[1]);
	if (waitpid(manager, &manager_status, 0) != manager ||
	    waitpid(client, &client_status, 0) != client) {
		perror("waitpid");
		return 7;
	}
	if (!WIFEXITED(manager_status) || WEXITSTATUS(manager_status) != 0)
		return 8;
	if (!WIFEXITED(client_status))
		return 9;
	return WEXITSTATUS(client_status);
}
