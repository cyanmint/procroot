/*
 * SPDX-FileCopyrightText: NONE
 * SPDX-License-Identifier: GPL-2.0-or-later
 * Note: AI-generated contribution; no legal determination implied.
 */
/* A server reply to a caller that exited after delivery must complete cleanly. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

struct binder_transaction_data {
	uint64_t target;
	uint64_t cookie;
	uint32_t code;
	uint32_t flags;
	int32_t sender_pid;
	uint32_t sender_euid;
	uint64_t data_size;
	uint64_t offsets_size;
	uint64_t data_buffer;
	uint64_t offsets_buffer;
};

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
#define BC_TRANSACTION _IOW('c', 0, struct binder_transaction_data)
#define BC_REPLY _IOW('c', 1, struct binder_transaction_data)
#define BR_TRANSACTION _IOR('r', 2, struct binder_transaction_data)
#define BR_TRANSACTION_COMPLETE _IO('r', 6)
#define BR_NOOP _IO('r', 0)
#define REQUEST_CODE UINT32_C(0x5eed)
#define READ_SIZE 256
#define IO_TIMEOUT_MS 5000

static int send_command(int fd, uint32_t command,
		const struct binder_transaction_data *transaction)
{
	struct binder_write_read bwr;
	uint8_t writes[sizeof(command) + sizeof(*transaction)];

	memcpy(writes, &command, sizeof(command));
	memcpy(writes + sizeof(command), transaction, sizeof(*transaction));
	bwr = (struct binder_write_read) {
		.write_size = sizeof(writes),
		.write_buffer = (uint64_t)(uintptr_t)writes,
	};
	if (ioctl(fd, BINDER_WRITE_READ, &bwr) < 0)
		return -1;
	return bwr.write_consumed == sizeof(writes) ? 0 : -1;
}

static int wait_for_token(int fd, char *token)
{
	struct pollfd pfd = { .fd = fd, .events = POLLIN };
	int result = poll(&pfd, 1, IO_TIMEOUT_MS);

	if (result <= 0)
		return -1;
	return read(fd, token, 1) == 1 ? 0 : -1;
}

static int receive_request(int fd, struct binder_transaction_data *request)
{
	for (int attempt = 0; attempt < 20; attempt++) {
		struct pollfd pfd = { .fd = fd, .events = POLLIN };
		uint8_t reads[READ_SIZE] = {};
		struct binder_write_read bwr = {
			.read_size = sizeof(reads),
			.read_buffer = (uint64_t)(uintptr_t)reads,
		};
		int ready = poll(&pfd, 1, IO_TIMEOUT_MS / 20);
		size_t offset = 0;

		if (ready < 0 && errno == EINTR) {
			attempt--;
			continue;
		}
		if (ready <= 0)
			continue;
		if (ioctl(fd, BINDER_WRITE_READ, &bwr) < 0)
			return -1;
		while (offset + sizeof(uint32_t) <= bwr.read_consumed) {
			uint32_t command;

			memcpy(&command, reads + offset, sizeof(command));
			offset += sizeof(command);
			if (command == BR_TRANSACTION) {
				if (offset + sizeof(*request) > bwr.read_consumed)
					return -2;
				memcpy(request, reads + offset, sizeof(*request));
				return 0;
			}
			if (command != BR_TRANSACTION_COMPLETE && command != BR_NOOP)
				return -3;
		}
	}
	return -4;
}

static int send_reply_and_receive_complete(
		int fd, const struct binder_transaction_data *transaction)
{
	uint32_t command = BC_REPLY;
	uint8_t writes[sizeof(command) + sizeof(*transaction)];
	uint8_t reads[READ_SIZE] = {};
	struct binder_write_read bwr;
	size_t offset = 0;

	memcpy(writes, &command, sizeof(command));
	memcpy(writes + sizeof(command), transaction, sizeof(*transaction));
	bwr = (struct binder_write_read) {
		.write_size = sizeof(writes),
		.write_buffer = (uint64_t)(uintptr_t)writes,
		.read_size = sizeof(reads),
		.read_buffer = (uint64_t)(uintptr_t)reads,
	};
	if (ioctl(fd, BINDER_WRITE_READ, &bwr) < 0)
		return -1;
	if (bwr.write_consumed != sizeof(writes))
		return -2;
	while (offset + sizeof(uint32_t) <= bwr.read_consumed) {
		uint32_t reply_command;

		memcpy(&reply_command, reads + offset, sizeof(reply_command));
		offset += sizeof(reply_command);
		if (reply_command == BR_TRANSACTION_COMPLETE)
			return 0;
		if (reply_command != BR_NOOP)
			return -3;
	}
	return -4;
}

static int wait_for_child(pid_t child, int *status)
{
	struct timespec delay = { .tv_nsec = 10000000 };

	for (int attempt = 0; attempt < IO_TIMEOUT_MS / 10; attempt++) {
		pid_t result = waitpid(child, status, WNOHANG);

		if (result == child)
			return 0;
		if (result < 0 && errno != EINTR)
			return -1;
		nanosleep(&delay, NULL);
	}
	return -1;
}

int main(void)
{
	int ready_pipe[2] = { -1, -1 };
	int release_pipe[2] = { -1, -1 };
	uint32_t manager = 0;
	struct binder_transaction_data request = {
		.target = 0,
		.code = REQUEST_CODE,
	};
	int server_fd = open("/dev/binder", O_RDWR | O_CLOEXEC);
	pid_t client;
	char token;
	int status;
	int result = 1;

	if (server_fd < 0 || ioctl(server_fd, BINDER_SET_CONTEXT_MGR, &manager) < 0) {
		perror("Binder context-manager setup");
		goto done;
	}
	if (pipe(ready_pipe) < 0 || pipe(release_pipe) < 0) {
		perror("pipe");
		goto done;
	}
	client = fork();
	if (client < 0) {
		perror("fork");
		goto done;
	}
	if (client == 0) {
		int fd;

		close(server_fd);
		close(ready_pipe[0]);
		close(release_pipe[1]);
		fd = open("/dev/binder", O_RDWR | O_CLOEXEC);
		if (fd < 0 || send_command(fd, BC_TRANSACTION, &request) < 0)
			_exit(10);
		token = 'r';
		if (write(ready_pipe[1], &token, 1) != 1 ||
		    read(release_pipe[0], &token, 1) != 1)
			_exit(11);
		close(fd);
		_exit(0);
	}
	close(ready_pipe[1]);
	ready_pipe[1] = -1;
	close(release_pipe[0]);
	release_pipe[0] = -1;

	if (wait_for_token(ready_pipe[0], &token) < 0) {
		fprintf(stderr, "client did not submit its transaction\n");
		goto stop_child;
	}
	if (receive_request(server_fd, &request) < 0) {
		fprintf(stderr, "server did not receive the client transaction\n");
		goto stop_child;
	}
	if (request.code != REQUEST_CODE) {
		fprintf(stderr, "unexpected Binder request code: %#x\n", request.code);
		goto stop_child;
	}
	if (write(release_pipe[1], "x", 1) != 1 ||
	    wait_for_child(client, &status) < 0 || !WIFEXITED(status) ||
	    WEXITSTATUS(status) != 0) {
		fprintf(stderr, "client did not exit after request delivery\n");
		goto stop_child;
	}
	request.target = UINT64_MAX;
	request.cookie = 0;
	request.flags = 0;
	request.data_size = 0;
	request.offsets_size = 0;
	request.data_buffer = 0;
	request.offsets_buffer = 0;
	status = send_reply_and_receive_complete(server_fd, &request);
	if (status < 0) {
		if (status == -1)
			perror("BC_REPLY after caller exit");
		fprintf(stderr, "dead-caller reply did not complete (status=%d)\n",
			status);
		goto done;
	}
	puts("dead-caller Binder reply passed");
	result = 0;
	goto done;

stop_child:
	if (release_pipe[1] >= 0)
		(void)write(release_pipe[1], "x", 1);
	(void)kill(client, SIGKILL);
	(void)waitpid(client, &status, 0);
done:
	if (ready_pipe[0] >= 0)
		close(ready_pipe[0]);
	if (ready_pipe[1] >= 0)
		close(ready_pipe[1]);
	if (release_pipe[0] >= 0)
		close(release_pipe[0]);
	if (release_pipe[1] >= 0)
		close(release_pipe[1]);
	if (server_fd >= 0)
		close(server_fd);
	return result;
}
