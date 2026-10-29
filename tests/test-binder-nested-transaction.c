/*
 * SPDX-FileCopyrightText: NONE
 * SPDX-License-Identifier: GPL-2.0-or-later
 * Note: AI-generated contribution; no legal determination implied.
 */
/* Verify nested synchronous Binder calls preserve multiple live buffers. */
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
#include <time.h>
#include <unistd.h>

#define MAPPING_SIZE 65536
#define OUTER_CODE 0x4e535431u
#define NESTED_CODE 0x4e535432u
#define NESTED_REPLY_CODE 0x4e535433u
#define OUTER_REPLY_CODE 0x4e535434u
#define SECOND_NESTED_CODE 0x4e535435u
#define SECOND_NESTED_REPLY_CODE 0x4e535436u
#define FIRST_PAYLOAD_SIZE 116u
#define SECOND_PAYLOAD_SIZE 92u
#define BINDER_TYPE_BINDER 0x73622a85u
#define BINDER_TYPE_HANDLE 0x73682a85u
#define BR_TRANSACTION_COMPLETE _IO('r', 6)
#define BR_NOOP _IO('r', 12)

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
	uint64_t binder;
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

struct binder_ptr_cookie {
	uint64_t ptr;
	uint64_t cookie;
};

#define BINDER_SET_CONTEXT_MGR _IOW('b', 7, uint32_t)
#define BINDER_WRITE_READ _IOWR('b', 1, struct binder_write_read)
#define BC_TRANSACTION _IOW('c', 0, struct binder_transaction_data)
#define BC_REPLY _IOW('c', 1, struct binder_transaction_data)
#define BC_FREE_BUFFER _IOW('c', 3, uint64_t)
#define BC_INCREFS_DONE _IOW('c', 8, struct binder_ptr_cookie)
#define BC_ACQUIRE_DONE _IOW('c', 9, struct binder_ptr_cookie)
#define BR_TRANSACTION _IOR('r', 2, struct binder_transaction_data)
#define BR_REPLY _IOR('r', 3, struct binder_transaction_data)
#define BR_INCREFS _IOR('r', 7, struct binder_ptr_cookie)
#define BR_ACQUIRE _IOR('r', 8, struct binder_ptr_cookie)
#define BR_RELEASE _IOR('r', 9, struct binder_ptr_cookie)
#define BR_DECREFS _IOR('r', 10, struct binder_ptr_cookie)

static volatile sig_atomic_t timed_out;

static void on_alarm(int signal_number)
{
	(void)signal_number;
	timed_out = 1;
}

static int open_binder(void)
{
	int fd = open("/dev/binder", O_RDWR | O_CLOEXEC);
	void *mapping;

	if (fd < 0)
		return -1;
	mapping = mmap(NULL, MAPPING_SIZE, PROT_READ, MAP_PRIVATE, fd, 0);
	if (mapping == MAP_FAILED) {
		close(fd);
		return -1;
	}
	(void)mapping;
	return fd;
}

static int send_transaction(int fd, uint32_t command,
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

static int send_free_buffer(int fd, uint64_t address)
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

static int acknowledge_reference(int fd, uint32_t command,
				const struct binder_ptr_cookie *reference)
{
	struct binder_write_read bwr = {};
	uint8_t writes[sizeof(command) + sizeof(*reference)];

	memcpy(writes, &command, sizeof(command));
	memcpy(writes + sizeof(command), reference, sizeof(*reference));
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
		uint8_t reads[256] = {};
		struct binder_write_read bwr = {
			.read_size = sizeof(reads),
			.read_buffer = (uint64_t)(uintptr_t)reads,
		};
		size_t position = 0;

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
			if (command == BR_INCREFS || command == BR_ACQUIRE ||
			    command == BR_RELEASE || command == BR_DECREFS) {
				struct binder_ptr_cookie reference;

				if (position + sizeof(reference) > bwr.read_consumed)
					return -1;
				memcpy(&reference, reads + position, sizeof(reference));
				position += sizeof(reference);
				if (command == BR_INCREFS &&
				    acknowledge_reference(fd, BC_INCREFS_DONE,
						  &reference) < 0)
					return -1;
				if (command == BR_ACQUIRE &&
				    acknowledge_reference(fd, BC_ACQUIRE_DONE,
						  &reference) < 0)
					return -1;
				continue;
			}
			if (command == BR_TRANSACTION || command == BR_REPLY) {
				if (position + sizeof(*transaction) > bwr.read_consumed)
					return -1;
				memcpy(transaction, reads + position, sizeof(*transaction));
				position += sizeof(*transaction);
				if (command == expected_command)
					return 0;
				fprintf(stderr, "unexpected Binder transaction command=%#x code=%#x\n",
					command, transaction->code);
				return -1;
			}
			fprintf(stderr, "unexpected Binder read command=%#x\n", command);
			return -1;
		}
		if (timed_out)
			return -1;
	}
}

static int client_process(int inherited_fd)
{
	struct flat_binder_object callback = {
		.type = BINDER_TYPE_BINDER,
		.flags = 0x7f,
		.binder = 0x12345678u,
		.cookie = 0x87654321u,
	};
	struct binder_transaction_data transaction = {};
	struct binder_transaction_data received;
	uint64_t offset = 0;
	uint64_t first_buffer;
	uint64_t second_buffer;
	uint32_t nested_reply = NESTED_REPLY_CODE;
	uint32_t second_nested_reply = SECOND_NESTED_REPLY_CODE;
	uint32_t outer_reply;
	size_t i;
	int fd;

	close(inherited_fd);
	fd = open_binder();
	if (fd < 0)
		return 10;
	transaction.code = OUTER_CODE;
	transaction.data_size = sizeof(callback);
	transaction.offsets_size = sizeof(offset);
	transaction.data_buffer = (uint64_t)(uintptr_t)&callback;
	transaction.offsets_buffer = (uint64_t)(uintptr_t)&offset;
	if (send_transaction(fd, BC_TRANSACTION, &transaction) < 0)
		return 11;
	if (read_transaction(fd, BR_TRANSACTION, &received) < 0) {
		fprintf(stderr, "CLIENT_NESTED_TRANSACTION_READ_FAIL errno=%d\n", errno);
		return 12;
	}
	if (received.code != NESTED_CODE || received.target != callback.binder ||
	    received.cookie != callback.cookie ||
	    received.data_size != FIRST_PAYLOAD_SIZE) {
		fprintf(stderr, "CLIENT_NESTED_TARGET code=%#x target=%#llx cookie=%#llx\n",
			received.code, (unsigned long long)received.target,
			(unsigned long long)received.cookie);
		return 13;
	}
	first_buffer = received.data_buffer;
	for (i = 0; i < FIRST_PAYLOAD_SIZE; i++)
		if (((const uint8_t *)(uintptr_t)first_buffer)[i] != 0x5a)
			return 14;
	transaction = (struct binder_transaction_data) {
		.code = NESTED_REPLY_CODE,
		.data_size = sizeof(nested_reply),
		.data_buffer = (uint64_t)(uintptr_t)&nested_reply,
	};
	if (send_transaction(fd, BC_REPLY, &transaction) < 0)
		return 15;
	if (read_transaction(fd, BR_TRANSACTION, &received) < 0) {
		fprintf(stderr, "CLIENT_SECOND_BUFFER_READ_FAIL errno=%d\n", errno);
		return 20;
	}
	if (received.code != SECOND_NESTED_CODE ||
	    received.target != callback.binder ||
	    received.cookie != callback.cookie ||
	    received.data_size != SECOND_PAYLOAD_SIZE)
		return 21;
	second_buffer = received.data_buffer;
	for (i = 0; i < SECOND_PAYLOAD_SIZE; i++)
		if (((const uint8_t *)(uintptr_t)second_buffer)[i] != 0xa5)
			return 22;
	if (send_free_buffer(fd, first_buffer) < 0 ||
	    send_free_buffer(fd, second_buffer) < 0)
		return 23;
	transaction = (struct binder_transaction_data) {
		.code = SECOND_NESTED_REPLY_CODE,
		.data_size = sizeof(second_nested_reply),
		.data_buffer = (uint64_t)(uintptr_t)&second_nested_reply,
	};
	if (send_transaction(fd, BC_REPLY, &transaction) < 0)
		return 24;
	if (read_transaction(fd, BR_REPLY, &received) < 0) {
		fprintf(stderr, "CLIENT_OUTER_REPLY_READ_FAIL errno=%d\n", errno);
		return 16;
	}
	if (received.code != OUTER_REPLY_CODE ||
	    received.data_size != sizeof(outer_reply))
		return 17;
	memcpy(&outer_reply, (void *)(uintptr_t)received.data_buffer,
	       sizeof(outer_reply));
	if (send_free_buffer(fd, received.data_buffer) < 0)
		return 18;
	close(fd);
	return outer_reply == OUTER_REPLY_CODE ? 0 : 19;
}

int main(void)
{
	struct sigaction action = { .sa_handler = on_alarm };
	struct flat_binder_object callback;
	struct binder_transaction_data transaction;
	struct binder_transaction_data reply;
	uint32_t context_manager = 0;
	uint32_t nested_reply;
	uint32_t second_nested_reply;
	uint32_t outer_reply = OUTER_REPLY_CODE;
	uint8_t first_payload[FIRST_PAYLOAD_SIZE];
	uint8_t second_payload[SECOND_PAYLOAD_SIZE];
	pid_t client;
	size_t i;
	int status;
	int fd = open_binder();

	if (fd < 0) {
		perror("open or mmap /dev/binder");
		return 1;
	}
	for (i = 0; i < FIRST_PAYLOAD_SIZE; i++)
		first_payload[i] = 0x5a;
	for (i = 0; i < SECOND_PAYLOAD_SIZE; i++)
		second_payload[i] = 0xa5;
	if (ioctl(fd, BINDER_SET_CONTEXT_MGR, &context_manager) < 0) {
		perror("BINDER_SET_CONTEXT_MGR");
		close(fd);
		return 2;
	}
	if (sigaction(SIGALRM, &action, NULL) < 0)
		return 3;
	client = fork();
	if (client < 0) {
		perror("fork");
		return 4;
	}
	if (client == 0)
		_exit(client_process(fd));

	alarm(10);
	if (read_transaction(fd, BR_TRANSACTION, &transaction) < 0 ||
	    transaction.code != OUTER_CODE ||
	    transaction.data_size < sizeof(callback)) {
		fprintf(stderr, "SERVER_OUTER_TRANSACTION_READ_FAIL errno=%d\n", errno);
		kill(client, SIGKILL);
		waitpid(client, &status, 0);
		close(fd);
		return 5;
	}
	memcpy(&callback, (void *)(uintptr_t)transaction.data_buffer,
	       sizeof(callback));
	if (send_free_buffer(fd, transaction.data_buffer) < 0 ||
	    callback.type != BINDER_TYPE_HANDLE || callback.binder == 0) {
		fprintf(stderr, "SERVER_CALLBACK_HANDLE type=%#x handle=%llu\n",
			callback.type, (unsigned long long)callback.binder);
		kill(client, SIGKILL);
		waitpid(client, &status, 0);
		close(fd);
		return 6;
	}

	transaction = (struct binder_transaction_data) {
		.target = callback.binder,
		.code = NESTED_CODE,
		.data_size = sizeof(first_payload),
		.data_buffer = (uint64_t)(uintptr_t)first_payload,
	};
	if (send_transaction(fd, BC_TRANSACTION, &transaction) < 0 ||
	    read_transaction(fd, BR_REPLY, &reply) < 0 ||
	    reply.code != NESTED_REPLY_CODE ||
	    reply.data_size != sizeof(nested_reply)) {
		fprintf(stderr, "SERVER_NESTED_REPLY_FAIL errno=%d\n", errno);
		kill(client, SIGKILL);
		waitpid(client, &status, 0);
		close(fd);
		return 7;
	}
	memcpy(&nested_reply, (void *)(uintptr_t)reply.data_buffer,
	       sizeof(nested_reply));
	if (send_free_buffer(fd, reply.data_buffer) < 0 ||
	    nested_reply != NESTED_REPLY_CODE) {
		kill(client, SIGKILL);
		waitpid(client, &status, 0);
		close(fd);
		return 8;
	}

	transaction = (struct binder_transaction_data) {
		.target = callback.binder,
		.code = SECOND_NESTED_CODE,
		.data_size = sizeof(second_payload),
		.data_buffer = (uint64_t)(uintptr_t)second_payload,
	};
	if (send_transaction(fd, BC_TRANSACTION, &transaction) < 0 ||
	    read_transaction(fd, BR_REPLY, &reply) < 0 ||
	    reply.code != SECOND_NESTED_REPLY_CODE ||
	    reply.data_size != sizeof(second_nested_reply)) {
		fprintf(stderr, "SERVER_SECOND_NESTED_REPLY_FAIL errno=%d\n", errno);
		kill(client, SIGKILL);
		waitpid(client, &status, 0);
		close(fd);
		return 12;
	}
	memcpy(&second_nested_reply, (void *)(uintptr_t)reply.data_buffer,
	       sizeof(second_nested_reply));
	if (send_free_buffer(fd, reply.data_buffer) < 0 ||
	    second_nested_reply != SECOND_NESTED_REPLY_CODE) {
		kill(client, SIGKILL);
		waitpid(client, &status, 0);
		close(fd);
		return 13;
	}

	reply = (struct binder_transaction_data) {
		.code = OUTER_REPLY_CODE,
		.data_size = sizeof(outer_reply),
		.data_buffer = (uint64_t)(uintptr_t)&outer_reply,
	};
	if (send_transaction(fd, BC_REPLY, &reply) < 0) {
		perror("send outer BC_REPLY");
		kill(client, SIGKILL);
		waitpid(client, &status, 0);
		close(fd);
		return 9;
	}
	if (waitpid(client, &status, 0) < 0) {
		int wait_error = errno;

		alarm(0);
		kill(client, SIGKILL);
		waitpid(client, &status, 0);
		if (wait_error == EINTR && timed_out)
			fprintf(stderr, "CLIENT_OUTER_REPLY_TIMEOUT\n");
		else
			errno = wait_error, perror("waitpid client");
		fprintf(stderr, "BINDER_NESTED_SYNC_REPLY=FAIL\n");
		close(fd);
		return 10;
	}
	alarm(0);
	if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
		fprintf(stderr, "CLIENT_STATUS=%#x\n", status);
		close(fd);
		return 11;
	}
	close(fd);
	puts("BINDER_NESTED_SYNC_REPLY=PASS");
	return 0;
}
