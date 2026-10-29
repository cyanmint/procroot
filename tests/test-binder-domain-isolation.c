/*
 * SPDX-FileCopyrightText: NONE
 * SPDX-License-Identifier: GPL-2.0-or-later
 * Note: AI-generated contribution; no legal determination implied.
 */
/* Reject Binder handles when they are used with another Binder domain. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>

#define MAPPING_SIZE 65536
#define GET_HANDLE_CODE 0x48444f4e
#define BINDER_TYPE_BINDER 0x73622a85
#define BINDER_TYPE_HANDLE 0x73682a85

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

struct flat_binder_object {
	uint32_t type;
	uint32_t flags;
	union {
		uint64_t binder;
		uint32_t handle;
	} object;
	uint64_t cookie;
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
#define BC_FREE_BUFFER _IOW('c', 3, uint64_t)
#define BR_TRANSACTION _IOR('r', 2, struct binder_transaction_data)
#define BR_REPLY _IOR('r', 3, struct binder_transaction_data)
#define BR_TRANSACTION_COMPLETE _IO('r', 6)

static int manager_fd = -1;
static volatile sig_atomic_t alarm_expired;

static void ignore_alarm(int signal_number)
{
	(void)signal_number;
	alarm_expired = 1;
}

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

static int send_transaction(int fd, uint32_t command,
		struct binder_transaction_data *transaction)
{
	uint8_t writes[sizeof(uint32_t) + sizeof(*transaction)];
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

static int read_transaction(int fd, uint32_t expected_command,
		struct binder_transaction_data *transaction)
{
	for (;;) {
		uint8_t reads[sizeof(uint32_t) + sizeof(*transaction) + 64] = {};
		struct binder_write_read bwr = {};
		size_t position = 0;

		bwr.read_size = sizeof(reads);
		bwr.read_buffer = (uint64_t)(uintptr_t)reads;
		if (ioctl(fd, BINDER_WRITE_READ, &bwr) < 0)
			return -1;
		while (position + sizeof(uint32_t) <= bwr.read_consumed) {
			uint32_t command;

			memcpy(&command, reads + position, sizeof(command));
			position += sizeof(command);
			if (command == BR_TRANSACTION_COMPLETE)
				continue;
			if (command != expected_command ||
			    position + sizeof(*transaction) > bwr.read_consumed)
				return -1;
			memcpy(transaction, reads + position, sizeof(*transaction));
			return 0;
		}
		if (alarm_expired)
			return -1;
		(void)usleep(1000);
	}
}

static int free_buffer(int fd, uint64_t buffer)
{
	uint32_t command = BC_FREE_BUFFER;
	uint8_t writes[sizeof(command) + sizeof(buffer)];
	struct binder_write_read bwr = {};

	memcpy(writes, &command, sizeof(command));
	memcpy(writes + sizeof(command), &buffer, sizeof(buffer));
	bwr.write_size = sizeof(writes);
	bwr.write_buffer = (uint64_t)(uintptr_t)writes;
	return ioctl(fd, BINDER_WRITE_READ, &bwr);
}

static int client_process(int start_fd)
{
	struct binder_transaction_data transaction = {};
	struct binder_transaction_data reply;
	struct flat_binder_object object;
	char token;
	int hwbinder_fd;
	int fd;

	close(manager_fd);
	if (read(start_fd, &token, sizeof(token)) != sizeof(token))
		return 20;
	fd = open_binder("/dev/binder");
	if (fd < 0)
		return 21;
	transaction.code = GET_HANDLE_CODE;
	if (send_transaction(fd, BC_TRANSACTION, &transaction) < 0)
		return 22;
	alarm(30);
	if (read_transaction(fd, BR_REPLY, &reply) < 0 ||
	    reply.data_size < sizeof(object))
		return 23;
	memcpy(&object, (void *)(uintptr_t)reply.data_buffer, sizeof(object));
	if (object.type != BINDER_TYPE_HANDLE || object.object.handle == 0)
		return 24;
	free_buffer(fd, reply.data_buffer);

	hwbinder_fd = open_binder("/dev/hwbinder");
	if (hwbinder_fd < 0) {
		perror("open /dev/hwbinder");
		return 25;
	}
	transaction = (struct binder_transaction_data) {
		.target = object.object.handle,
		.code = GET_HANDLE_CODE,
	};
	if (send_transaction(hwbinder_fd, BC_TRANSACTION, &transaction) == 0) {
		fprintf(stderr, "CROSS_DOMAIN_HANDLE_ACCEPTED\n");
		close(hwbinder_fd);
		return 26;
	}
	if (errno != EINVAL) {
		fprintf(stderr, "CROSS_DOMAIN_HANDLE_ERRNO=%d\n", errno);
		close(hwbinder_fd);
		return 27;
	}
	fprintf(stderr, "CROSS_DOMAIN_HANDLE_REJECTED=EINVAL\n");
	close(hwbinder_fd);
	close(fd);
	return 0;
}

static int reply_with_handle(int fd, const struct flat_binder_object *object)
{
	uint64_t offset = 0;
	struct binder_transaction_data reply = {
		.data_size = sizeof(*object),
		.offsets_size = sizeof(offset),
		.data_buffer = (uint64_t)(uintptr_t)object,
		.offsets_buffer = (uint64_t)(uintptr_t)&offset,
	};

	return send_transaction(fd, BC_REPLY, &reply);
}

int main(void)
{
	struct binder_transaction_data transaction;
	struct flat_binder_object object = {
		.type = BINDER_TYPE_BINDER,
		.flags = 0x7f,
		.object.binder = 0x12345678,
		.cookie = 0x87654321,
	};
	struct sigaction action = { .sa_handler = ignore_alarm };
	uint32_t context_manager = 0;
	int start[2];
	pid_t client;
	int client_status;
	char token = 's';
	int fd = open_binder("/dev/binder");

	if (fd < 0) {
		perror("open /dev/binder");
		return 1;
	}
	if (ioctl(fd, BINDER_SET_CONTEXT_MGR, &context_manager) < 0) {
		perror("BINDER_SET_CONTEXT_MGR");
		return 2;
	}
	manager_fd = fd;
	if (sigaction(SIGALRM, &action, NULL) < 0)
		return 3;
	if (pipe(start) < 0)
		return 4;
	client = fork();
	if (client < 0)
		return 5;
	if (client == 0)
		_exit(client_process(start[0]));
	close(start[0]);
	alarm(30);
	if (write(start[1], &token, sizeof(token)) != sizeof(token))
		return 6;
	if (read_transaction(fd, BR_TRANSACTION, &transaction) < 0 ||
	    transaction.code != GET_HANDLE_CODE)
		return 7;
	free_buffer(fd, transaction.data_buffer);
	if (reply_with_handle(fd, &object) < 0)
		return 8;
	alarm(0);
	waitpid(client, &client_status, 0);
	close(start[1]);
	close(fd);
	if (!WIFEXITED(client_status) || WEXITSTATUS(client_status) != 0) {
		fprintf(stderr, "client_status=%#x\n", client_status);
		fprintf(stderr, "BINDER_DOMAIN_ISOLATION=FAIL\n");
		return 9;
	}
	puts("BINDER_DOMAIN_ISOLATION=PASS");
	return 0;
}