/*
 * SPDX-FileCopyrightText: NONE
 * SPDX-License-Identifier: GPL-2.0-or-later
 * Note: AI-generated contribution; no legal determination implied.
 */
/* Ensure queued synchronous requests keep their reply identities. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <unistd.h>

struct binder_transaction_data {
	uint64_t target, cookie;
	uint32_t code, flags;
	int32_t sender_pid;
	uint32_t sender_euid;
	uint64_t data_size, offsets_size, data_buffer, offsets_buffer;
};

struct binder_write_read {
	uint64_t write_size, write_consumed, write_buffer;
	uint64_t read_size, read_consumed, read_buffer;
};

#define BINDER_SET_CONTEXT_MGR _IOW('b', 7, uint32_t)
#define BINDER_WRITE_READ _IOWR('b', 1, struct binder_write_read)
#define BC_TRANSACTION _IOW('c', 0, struct binder_transaction_data)
#define BC_REPLY _IOW('c', 1, struct binder_transaction_data)
#define BC_FREE_BUFFER _IOW('c', 3, uint64_t)
#define BR_TRANSACTION _IOR('r', 2, struct binder_transaction_data)
#define BR_REPLY _IOR('r', 3, struct binder_transaction_data)
#define BR_TRANSACTION_COMPLETE _IO('r', 6)
#define BR_NOOP _IO('r', 12)
#define BC_ENTER_LOOPER _IO('c', 12)
#define REQUEST_BASE UINT32_C(0x7300)
#define RESPONSE_BASE UINT32_C(0x5a000000)
#define READ_SIZE 256
#define CLIENT_COUNT 2

static volatile sig_atomic_t timed_out;

static void on_alarm(int signal_number)
{
	(void)signal_number;
	timed_out = 1;
}

static int send_command(int fd, uint32_t command,
		const struct binder_transaction_data *transaction)
{
	uint8_t writes[sizeof(command) + sizeof(*transaction)];
	struct binder_write_read bwr = {};

	memcpy(writes, &command, sizeof(command));
	memcpy(writes + sizeof(command), transaction, sizeof(*transaction));
	bwr.write_size = sizeof(writes);
	bwr.write_buffer = (uint64_t)(uintptr_t)writes;
	if (ioctl(fd, BINDER_WRITE_READ, &bwr) < 0 ||
	    bwr.write_consumed != bwr.write_size)
		return -1;
	return 0;
}

static int free_buffer(int fd, uint64_t address)
{
	uint8_t writes[sizeof(uint32_t) + sizeof(address)];
	struct binder_write_read bwr = {};
	uint32_t command = BC_FREE_BUFFER;

	memcpy(writes, &command, sizeof(command));
	memcpy(writes + sizeof(command), &address, sizeof(address));
	bwr.write_size = sizeof(writes);
	bwr.write_buffer = (uint64_t)(uintptr_t)writes;
	if (ioctl(fd, BINDER_WRITE_READ, &bwr) < 0 ||
	    bwr.write_consumed != bwr.write_size)
		return -1;
	return 0;
}

static int read_transaction(int fd, uint32_t expected_command,
		struct binder_transaction_data *transaction)
{
	while (!timed_out) {
		struct pollfd pfd = { .fd = fd, .events = POLLIN };
		uint8_t reads[READ_SIZE] = {};
		struct binder_write_read bwr = {
			.read_size = sizeof(reads),
			.read_buffer = (uint64_t)(uintptr_t)reads,
		};
		size_t position = 0;

		if (poll(&pfd, 1, 500) <= 0)
			continue;
		if (ioctl(fd, BINDER_WRITE_READ, &bwr) < 0) {
			if (errno == EINTR && !timed_out)
				continue;
			return -1;
		}
		while (position + sizeof(uint32_t) <= bwr.read_consumed) {
			uint32_t command;

			memcpy(&command, reads + position, sizeof(command));
			position += sizeof(command);
			if (command == BR_TRANSACTION_COMPLETE || command == BR_NOOP)
				continue;
			if (command == expected_command) {
				if (position + sizeof(*transaction) > bwr.read_consumed)
					return -1;
				memcpy(transaction, reads + position,
					sizeof(*transaction));
				return 0;
			}
			return -1;
		}
	}
	return -1;
}

static int try_read_transaction(int fd,
		struct binder_transaction_data *transaction)
{
	uint32_t enter_looper = BC_ENTER_LOOPER;
	uint8_t writes[sizeof(enter_looper)];
	uint8_t reads[READ_SIZE] = {};
	struct binder_write_read bwr = {
		.write_size = sizeof(writes),
		.read_size = sizeof(reads),
		.write_buffer = (uint64_t)(uintptr_t)writes,
		.read_buffer = (uint64_t)(uintptr_t)reads,
	};
	size_t position = 0;

	memcpy(writes, &enter_looper, sizeof(enter_looper));
	if (ioctl(fd, BINDER_WRITE_READ, &bwr) < 0 ||
	    bwr.write_consumed != bwr.write_size)
		return -1;
	while (position + sizeof(uint32_t) <= bwr.read_consumed) {
		uint32_t command;

		memcpy(&command, reads + position, sizeof(command));
		position += sizeof(command);
		if (command == BR_TRANSACTION_COMPLETE || command == BR_NOOP)
			continue;
		if (command == BR_TRANSACTION) {
			if (position + sizeof(*transaction) > bwr.read_consumed)
				return -1;
			memcpy(transaction, reads + position, sizeof(*transaction));
			return 1;
		}
		return -1;
	}
	return 0;
}

static int client_run(unsigned int index, int inherited_fd, int ready_fd)
{
	struct binder_transaction_data request = {
		.target = 0,
		.code = REQUEST_BASE + index,
	};
	struct binder_transaction_data reply = {};
	uint32_t response;
	int fd = -1;
	int status = 1;

	close(inherited_fd);
	alarm(15);
	fd = open("/dev/binder", O_RDWR | O_CLOEXEC);
	if (fd < 0 || send_command(fd, BC_TRANSACTION, &request) < 0)
		goto done;
	{
		char ready = (char)index;
		if (write(ready_fd, &ready, sizeof(ready)) != sizeof(ready))
			goto done;
		close(ready_fd);
	}
	if (read_transaction(fd, BR_REPLY, &reply) < 0)
		goto done;
	if (reply.code != request.code || reply.data_size != sizeof(response) ||
	    reply.data_buffer == 0)
		goto free_reply;
	memcpy(&response, (const void *)(uintptr_t)reply.data_buffer,
		sizeof(response));
	status = response == RESPONSE_BASE + index ? 0 : 1;
free_reply:
	if (reply.data_buffer != 0 && free_buffer(fd, reply.data_buffer) < 0)
		status = 1;
done:
	if (fd >= 0)
		close(fd);
	return status;
}

int main(void)
{
	struct binder_transaction_data requests[CLIENT_COUNT] = {};
	pid_t clients[CLIENT_COUNT];
	int ready_pipe[2];
	uint32_t manager = 0;
	int fd = open("/dev/binder", O_RDWR | O_CLOEXEC);
	int statuses[CLIENT_COUNT] = {};
	int early_delivery = 0;
	bool pass = true;

	if (fd < 0 || ioctl(fd, BINDER_SET_CONTEXT_MGR, &manager) < 0) {
		perror("Binder context-manager setup");
		return 1;
	}
	if (pipe(ready_pipe) < 0) {
		perror("pipe");
		close(fd);
		return 2;
	}
	signal(SIGALRM, on_alarm);
	alarm(15);
	for (unsigned int i = 0; i < CLIENT_COUNT; i++) {
		clients[i] = fork();
		if (clients[i] < 0) {
			perror("fork");
			return 3;
		}
		if (clients[i] == 0) {
			close(ready_pipe[0]);
			_exit(client_run(i, fd, ready_pipe[1]));
		}
	}
	close(ready_pipe[1]);
	for (unsigned int i = 0; i < CLIENT_COUNT; i++) {
		char ready;
		if (read(ready_pipe[0], &ready, sizeof(ready)) != sizeof(ready)) {
			fprintf(stderr, "client did not queue its request\n");
			return 4;
		}
	}
	if (read_transaction(fd, BR_TRANSACTION, &requests[0]) < 0 ||
	    requests[0].code < REQUEST_BASE ||
	    requests[0].code >= REQUEST_BASE + CLIENT_COUNT) {
		fprintf(stderr, "failed to receive first queued request\n");
		return 5;
	}
	if (requests[0].data_buffer != 0 &&
	    free_buffer(fd, requests[0].data_buffer) < 0) {
		fprintf(stderr, "failed to release first request buffer\n");
		return 6;
	}
	{
		int status = try_read_transaction(fd, &requests[1]);
		if (status < 0 || (status == 1 &&
		    (requests[1].code < REQUEST_BASE ||
		     requests[1].code >= REQUEST_BASE + CLIENT_COUNT))) {
			fprintf(stderr, "failed to probe for an extra transaction\n");
			return 7;
		}
		early_delivery = status == 1;
	}
	for (unsigned int i = 0; i < CLIENT_COUNT; i++) {
		struct binder_transaction_data reply = requests[i];
		uint32_t response = RESPONSE_BASE +
			(requests[i].code - REQUEST_BASE);

		if (i == 1 && !early_delivery) {
			if (read_transaction(fd, BR_TRANSACTION, &requests[i]) < 0 ||
			    requests[i].code < REQUEST_BASE ||
			    requests[i].code >= REQUEST_BASE + CLIENT_COUNT) {
				fprintf(stderr, "failed to receive transaction after reply\n");
				return 8;
			}
			if (requests[i].data_buffer != 0 &&
			    free_buffer(fd, requests[i].data_buffer) < 0)
				return 9;
			reply = requests[i];
			response = RESPONSE_BASE +
				(requests[i].code - REQUEST_BASE);
		}
		reply.target = UINT64_MAX;
		reply.cookie = 0;
		reply.flags = 0;
		reply.data_size = sizeof(response);
		reply.offsets_size = 0;
		reply.data_buffer = (uint64_t)(uintptr_t)&response;
		reply.offsets_buffer = 0;
		if (send_command(fd, BC_REPLY, &reply) < 0) {
			perror("send reply in receive order");
			return 10;
		}
	}
	for (unsigned int i = 0; i < CLIENT_COUNT; i++) {
		if (waitpid(clients[i], &statuses[i], 0) < 0 ||
		    !WIFEXITED(statuses[i]) || WEXITSTATUS(statuses[i]) != 0)
			pass = false;
	}
	alarm(0);
	close(ready_pipe[0]);
	close(fd);
	printf("EARLY_TRANSACTION_DELIVERY=%d\n", early_delivery);
	puts(pass && !early_delivery ? "BINDER_QUEUED_REPLY_IDENTITY=PASS" :
		"BINDER_QUEUED_REPLY_IDENTITY=FAIL");
	return pass && !early_delivery ? 0 : 11;
}
