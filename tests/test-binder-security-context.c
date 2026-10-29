/*
 * SPDX-FileCopyrightText: NONE
 * SPDX-License-Identifier: GPL-2.0-or-later
 * Note: AI-generated contribution; no legal determination implied.
 */
/* Verify Binder returns requested transaction security contexts. */
#define _GNU_SOURCE
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
#define READ_SIZE 256
#define TRANSACTION_CODE 0x53454354
#define BINDER_TYPE_BINDER 0x73622a85u
#define FLAT_BINDER_FLAG_TXN_SECURITY_CTX 0x1000u
#define BINDER_TF_ONE_WAY 0x01u

struct flat_binder_object {
	uint32_t type;
	uint32_t flags;
	union {
		uint32_t handle;
		uint64_t binder;
	} object;
	uint64_t cookie;
};

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

struct binder_transaction_data_secctx {
	struct binder_transaction_data transaction_data;
	uint64_t secctx;
};

struct binder_write_read {
	uint64_t write_size;
	uint64_t write_consumed;
	uint64_t write_buffer;
	uint64_t read_size;
	uint64_t read_consumed;
	uint64_t read_buffer;
};

#define BINDER_SET_CONTEXT_MGR_EXT \
	_IOW('b', 13, struct flat_binder_object)
#define BINDER_WRITE_READ _IOWR('b', 1, struct binder_write_read)
#define BC_TRANSACTION _IOW('c', 0, struct binder_transaction_data)
#define BC_FREE_BUFFER _IOW('c', 3, uint64_t)
#define BR_NOOP _IO('r', 12)
#define BR_TRANSACTION _IOR('r', 2, struct binder_transaction_data)
#define BR_TRANSACTION_SEC_CTX \
	_IOR('r', 2, struct binder_transaction_data_secctx)

static void ignore_alarm(int signal_number)
{
	(void)signal_number;
}

static int send_transaction(int fd)
{
	struct binder_transaction_data transaction = {
		.target = 0,
		.code = TRANSACTION_CODE,
		.flags = BINDER_TF_ONE_WAY,
	};
	uint8_t writes[sizeof(uint32_t) + sizeof(transaction)];
	uint32_t command = BC_TRANSACTION;
	struct binder_write_read bwr = {};

	memcpy(writes, &command, sizeof(command));
	memcpy(writes + sizeof(command), &transaction, sizeof(transaction));
	bwr.write_size = sizeof(writes);
	bwr.write_buffer = (uint64_t)(uintptr_t)writes;
	if (ioctl(fd, BINDER_WRITE_READ, &bwr) < 0 ||
	    bwr.write_consumed != bwr.write_size)
		return -1;
	return 0;
}

static int receive_transaction(int fd, const void *mapping,
		struct binder_transaction_data *transaction, uint64_t *secctx)
{
	uint8_t reads[READ_SIZE] = {};
	struct binder_write_read bwr = {
		.read_size = sizeof(reads),
		.read_buffer = (uint64_t)(uintptr_t)reads,
	};
	size_t position = 0;
	uintptr_t start = (uintptr_t)mapping;
	uintptr_t end = start + MAPPING_SIZE;

	if (ioctl(fd, BINDER_WRITE_READ, &bwr) < 0)
		return -1;
	while (position + sizeof(uint32_t) <= bwr.read_consumed) {
		uint32_t command;

		memcpy(&command, reads + position, sizeof(command));
		position += sizeof(command);
		if (command == BR_NOOP)
			continue;
		if (command == BR_TRANSACTION) {
			fprintf(stderr, "transaction lacked BR_TRANSACTION_SEC_CTX\n");
			return -2;
		}
		if (command != BR_TRANSACTION_SEC_CTX ||
		    position + sizeof(struct binder_transaction_data_secctx) >
			    bwr.read_consumed)
			return -3;
		{
			struct binder_transaction_data_secctx received;

			memcpy(&received, reads + position, sizeof(received));
			*transaction = received.transaction_data;
			*secctx = received.secctx;
			if (*secctx < start || *secctx >= end ||
			    end - *secctx < sizeof("u:r:su:s0"))
				return -4;
			if (strcmp((const char *)(uintptr_t)*secctx,
				   "u:r:su:s0") != 0)
				return -5;
			if (transaction->code != TRANSACTION_CODE ||
			    transaction->data_buffer < start ||
			    transaction->data_buffer >= end)
				return -6;
		}
		return 0;
	}
	return -7;
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

int main(void)
{
	int ready[2] = { -1, -1 };
	int release[2] = { -1, -1 };
	struct flat_binder_object manager = {
		.type = BINDER_TYPE_BINDER,
		.flags = FLAT_BINDER_FLAG_TXN_SECURITY_CTX,
		.object.binder = 0x12340000,
		.cookie = 0x56780000,
	};
	pid_t child;
	int manager_fd = open("/dev/binder", O_RDWR | O_CLOEXEC);
	void *mapping;
	int test_status = 0;
	int child_status;
	char token;

	if (manager_fd < 0) {
		perror("open /dev/binder");
		return 1;
	}
	mapping = mmap(NULL, MAPPING_SIZE, PROT_READ, MAP_PRIVATE, manager_fd, 0);
	if (mapping == MAP_FAILED) {
		perror("mmap /dev/binder");
		close(manager_fd);
		return 2;
	}
	if (ioctl(manager_fd, BINDER_SET_CONTEXT_MGR_EXT, &manager) < 0) {
		perror("BINDER_SET_CONTEXT_MGR_EXT");
		munmap(mapping, MAPPING_SIZE);
		close(manager_fd);
		return 3;
	}
	if (pipe(ready) < 0 || pipe(release) < 0) {
		perror("pipe");
		return 4;
	}
	child = fork();
	if (child < 0) {
		perror("fork");
		return 5;
	}
	if (child == 0) {
		int client_fd;

		close(ready[0]);
		close(release[1]);
		close(manager_fd);
		client_fd = open("/dev/binder", O_RDWR | O_CLOEXEC);
		if (client_fd < 0)
			_exit(6);
		token = 'r';
		if (write(ready[1], &token, 1) != 1 ||
		    send_transaction(client_fd) < 0 ||
		    read(release[0], &token, 1) != 1)
			_exit(7);
		close(client_fd);
		_exit(0);
	}

	close(ready[1]);
	close(release[0]);
	if (read(ready[0], &token, 1) != 1) {
		perror("wait for client");
		test_status = 8;
	} else {
		struct binder_transaction_data transaction = {};
		uint64_t secctx = 0;
		int receive_status;

		signal(SIGALRM, ignore_alarm);
		alarm(5);
		receive_status = receive_transaction(manager_fd, mapping,
			&transaction, &secctx);
		alarm(0);
		if (receive_status < 0) {
			fprintf(stderr, "security context receive failed: %d\n",
				receive_status);
			test_status = 9;
		} else if (free_buffer(manager_fd, transaction.data_buffer) < 0) {
			perror("BC_FREE_BUFFER");
			test_status = 10;
		}
	}
	token = 'x';
	if (write(release[1], &token, 1) != 1)
		test_status = 11;
	if (waitpid(child, &child_status, 0) < 0) {
		perror("waitpid");
		test_status = 12;
	} else if (!WIFEXITED(child_status) || WEXITSTATUS(child_status) != 0) {
		fprintf(stderr, "client exited with status %#x\n", child_status);
		test_status = 13;
	}
	close(ready[0]);
	close(release[1]);
	munmap(mapping, MAPPING_SIZE);
	close(manager_fd);
	if (test_status != 0) {
		fprintf(stderr, "BINDER_SECURITY_CONTEXT=FAIL status=%d\n",
			test_status);
		return test_status;
	}
	puts("BINDER_SECURITY_CONTEXT=PASS");
	return 0;
}
