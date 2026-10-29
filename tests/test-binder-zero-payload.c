/*
 * SPDX-FileCopyrightText: NONE
 * SPDX-License-Identifier: GPL-2.0-or-later
 * Note: AI-generated contribution; no legal determination implied.
 */
/* Verify empty Binder transactions still return a freeable mmap buffer. */
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
#define READ_SIZE 256
#define TRANSACTION_CODE 0x5a70

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
#define BC_FREE_BUFFER _IOW('c', 3, uint64_t)
#define BR_TRANSACTION _IOR('r', 2, struct binder_transaction_data)

static void handle_alarm(int signal_number)
{
	(void)signal_number;
}

static int send_empty_transaction(int fd)
{
	struct binder_transaction_data transaction = {
		.target = 0,
		.code = TRANSACTION_CODE,
	};
	struct binder_write_read bwr;
	uint8_t writes[sizeof(uint32_t) + sizeof(transaction)];
	uint8_t reads[READ_SIZE] = {};
	uint32_t command = BC_TRANSACTION;

	memcpy(writes, &command, sizeof(command));
	memcpy(writes + sizeof(command), &transaction, sizeof(transaction));
	bwr = (struct binder_write_read) {
		.write_size = sizeof(writes),
		.write_buffer = (uint64_t)(uintptr_t)writes,
		.read_size = sizeof(reads),
		.read_buffer = (uint64_t)(uintptr_t)reads,
	};
	if (ioctl(fd, BINDER_WRITE_READ, &bwr) < 0)
		return -1;
	return bwr.write_consumed == sizeof(writes) ? 0 : -1;
}

static int receive_and_free(int fd, const void *mapping)
{
	struct binder_transaction_data transaction;
	struct binder_write_read bwr;
	uint8_t reads[READ_SIZE] = {};
	uint8_t writes[sizeof(uint32_t) + sizeof(uint64_t)];
	uint32_t command;
	uint32_t free_command = BC_FREE_BUFFER;
	uintptr_t start = (uintptr_t)mapping;
	uintptr_t end = start + MAPPING_SIZE;

	bwr = (struct binder_write_read) {
		.read_size = sizeof(reads),
		.read_buffer = (uint64_t)(uintptr_t)reads,
	};
	if (ioctl(fd, BINDER_WRITE_READ, &bwr) < 0 ||
	    bwr.read_consumed < sizeof(command) + sizeof(transaction))
		return -1;
	memcpy(&command, reads, sizeof(command));
	memcpy(&transaction, reads + sizeof(command), sizeof(transaction));
	if (command != BR_TRANSACTION || transaction.code != TRANSACTION_CODE ||
	    transaction.data_size != 0 || transaction.offsets_size != 0 ||
	    transaction.data_buffer < start || transaction.data_buffer >= end) {
		fprintf(stderr, "empty transaction has invalid buffer %#llx\n",
			(unsigned long long)transaction.data_buffer);
		return -1;
	}

	memcpy(writes, &free_command, sizeof(free_command));
	memcpy(writes + sizeof(free_command), &transaction.data_buffer,
	       sizeof(transaction.data_buffer));
	bwr = (struct binder_write_read) {
		.write_size = sizeof(writes),
		.write_buffer = (uint64_t)(uintptr_t)writes,
	};
	return ioctl(fd, BINDER_WRITE_READ, &bwr);
}

int main(void)
{
	int ready[2] = { -1, -1 };
	int release[2] = { -1, -1 };
	uint32_t context_manager = 0;
	pid_t child;
	int binder_fd = open("/dev/binder", O_RDWR | O_CLOEXEC);
	void *mapping;
	int child_status;
	int test_result = 0;
	char token;

	if (binder_fd < 0) {
		perror("open /dev/binder");
		return 1;
	}
	mapping = mmap(NULL, MAPPING_SIZE, PROT_READ, MAP_PRIVATE, binder_fd, 0);
	if (mapping == MAP_FAILED) {
		perror("mmap /dev/binder");
		close(binder_fd);
		return 2;
	}
	if (ioctl(binder_fd, BINDER_SET_CONTEXT_MGR, &context_manager) < 0) {
		perror("BINDER_SET_CONTEXT_MGR");
		munmap(mapping, MAPPING_SIZE);
		close(binder_fd);
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
		close(binder_fd);
		client_fd = open("/dev/binder", O_RDWR | O_CLOEXEC);
		if (client_fd < 0)
			_exit(6);
		token = 'r';
		if (write(ready[1], &token, 1) != 1)
			_exit(7);
		usleep(100000);
		if (send_empty_transaction(client_fd) < 0 ||
		    read(release[0], &token, 1) != 1)
			_exit(8);
		close(client_fd);
		_exit(0);
	}

	close(ready[1]);
	close(release[0]);
	if (read(ready[0], &token, 1) != 1) {
		perror("wait for client");
		return 6;
	}
	signal(SIGALRM, handle_alarm);
	alarm(5);
	if (receive_and_free(binder_fd, mapping) < 0) {
		fprintf(stderr, "empty Binder transaction could not be freed\n");
		test_result = 9;
	}
	alarm(0);
	token = 'x';
	if (write(release[1], &token, 1) != 1)
		test_result = 10;
	if (waitpid(child, &child_status, 0) < 0) {
		perror("waitpid");
		test_result = 11;
	}
	else if (!WIFEXITED(child_status) || WEXITSTATUS(child_status) != 0) {
		fprintf(stderr, "client exited with status %#x\n", child_status);
		test_result = 12;
	}
	close(ready[0]);
	close(release[1]);
	munmap(mapping, MAPPING_SIZE);
	close(binder_fd);
	if (test_result != 0) {
		fprintf(stderr, "BINDER_ZERO_PAYLOAD=FAIL status=%d\n", test_result);
		return test_result;
	}
	puts("BINDER_ZERO_PAYLOAD=PASS");
	return 0;
}
