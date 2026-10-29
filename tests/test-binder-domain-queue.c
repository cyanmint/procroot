/*
 * SPDX-FileCopyrightText: NONE
 * SPDX-License-Identifier: GPL-2.0-or-later
 * Note: AI-generated contribution; no legal determination implied.
 */
/* Ensure Binder transactions are delivered only through their domain fd. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>

#define MAPPING_SIZE 65536
#define MARKER_CODE 0x48575155

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
#define BC_ENTER_LOOPER _IO('c', 12)
#define BR_TRANSACTION _IOR('r', 2, struct binder_transaction_data)
#define BR_TRANSACTION_COMPLETE _IO('r', 6)

static int open_binder(const char *path)
{
	int fd = open(path, O_RDWR | O_CLOEXEC);
	void *mapping;

	if (fd < 0)
		return -1;
	mapping = mmap(NULL, MAPPING_SIZE, PROT_READ, MAP_PRIVATE, fd, 0);
	if (mapping == MAP_FAILED) {
		close(fd);
		return -1;
	}
	return fd;
}

static int send_marker(int fd)
{
	struct binder_transaction_data transaction = {
		.code = MARKER_CODE,
		.flags = 0x01,
	};
	uint8_t writes[sizeof(uint32_t) + sizeof(transaction)];
	struct binder_write_read bwr = {};
	uint32_t command = BC_TRANSACTION;

	memcpy(writes, &command, sizeof(command));
	memcpy(writes + sizeof(command), &transaction, sizeof(transaction));
	bwr.write_size = sizeof(writes);
	bwr.write_buffer = (uint64_t)(uintptr_t)writes;
	return ioctl(fd, BINDER_WRITE_READ, &bwr) < 0 ||
		bwr.write_consumed != bwr.write_size ? -1 : 0;
}

static int try_read_transaction(int fd,
		struct binder_transaction_data *transaction, bool *received)
{
	uint8_t reads[sizeof(uint32_t) + sizeof(*transaction) + 64] = {};
	uint32_t command = BC_ENTER_LOOPER;
	struct binder_write_read bwr = {
		.write_size = sizeof(command),
		.write_buffer = (uint64_t)(uintptr_t)&command,
		.read_size = sizeof(reads),
		.read_buffer = (uint64_t)(uintptr_t)reads,
	};
	size_t position = 0;

	*received = false;
	if (ioctl(fd, BINDER_WRITE_READ, &bwr) < 0)
		return -1;
	while (position + sizeof(uint32_t) <= bwr.read_consumed) {
		uint32_t command;

		memcpy(&command, reads + position, sizeof(command));
		position += sizeof(command);
		if (command == BR_TRANSACTION_COMPLETE)
			continue;
		if (command != BR_TRANSACTION ||
		    position + sizeof(*transaction) > bwr.read_consumed)
			return -1;
		memcpy(transaction, reads + position, sizeof(*transaction));
		*received = true;
		return 0;
	}
	return 0;
}

int main(void)
{
	struct binder_transaction_data transaction;
	uint32_t context_manager = 0;
	int submitted[2];
	int release[2];
	pid_t client;
	int client_status;
	char token;
	bool received;
	int binder_fd = open_binder("/dev/binder");
	int hwbinder_fd = open_binder("/dev/hwbinder");

	if (binder_fd < 0 || hwbinder_fd < 0) {
		perror("open Binder domain fd");
		return 1;
	}
	if (ioctl(hwbinder_fd, BINDER_SET_CONTEXT_MGR, &context_manager) < 0) {
		perror("BINDER_SET_CONTEXT_MGR hwbinder");
		return 2;
	}
	if (pipe(submitted) < 0 || pipe(release) < 0)
		return 3;
	client = fork();
	if (client < 0)
		return 4;
	if (client == 0) {
		int fd;

		close(submitted[0]);
		close(release[1]);
		close(binder_fd);
		close(hwbinder_fd);
		fd = open_binder("/dev/hwbinder");
		if (fd < 0 || send_marker(fd) < 0)
			_exit(10);
		token = 'x';
		if (write(submitted[1], &token, sizeof(token)) != sizeof(token))
			_exit(11);
		if (read(release[0], &token, sizeof(token)) != sizeof(token))
			_exit(12);
		close(fd);
		_exit(0);
	}
	close(submitted[1]);
	close(release[0]);
	if (read(submitted[0], &token, sizeof(token)) != sizeof(token) ||
	    token != 'x') {
		fprintf(stderr, "CLIENT_SUBMISSION_FAILED\n");
		return 5;
	}
	if (try_read_transaction(binder_fd, &transaction, &received) < 0) {
		perror("read binder fd");
		return 6;
	}
	if (received) {
		fprintf(stderr, "CROSS_DOMAIN_QUEUE_DELIVERED_ON_BINDER_FD\n");
		token = 'x';
		write(release[1], &token, sizeof(token));
		waitpid(client, &client_status, 0);
		return 7;
	}
	if (try_read_transaction(hwbinder_fd, &transaction, &received) < 0 ||
	    !received || transaction.code != MARKER_CODE) {
		fprintf(stderr, "HWBINDER_QUEUE_MISSING_OR_INVALID\n");
		token = 'x';
		write(release[1], &token, sizeof(token));
		waitpid(client, &client_status, 0);
		return 8;
	}
	token = 'x';
	if (write(release[1], &token, sizeof(token)) != sizeof(token))
		return 9;
	waitpid(client, &client_status, 0);
	if (!WIFEXITED(client_status) || WEXITSTATUS(client_status) != 0)
		return 10;
	puts("BINDER_DOMAIN_QUEUE=PASS");
	return 0;
}