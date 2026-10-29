/*
 * SPDX-FileCopyrightText: NONE
 * SPDX-License-Identifier: GPL-2.0-or-later
 * Note: AI-generated contribution; no legal determination implied.
 */
/* Verify queued Binder transactions wake pollers on the target endpoint. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
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
#define BR_TRANSACTION _IOR('r', 2, struct binder_transaction_data)
#define READ_SIZE 256

static void handle_alarm(int signal_number)
{
	(void)signal_number;
}

static int send_transaction(int fd)
{
	struct binder_transaction_data transaction = {
		.target = 0,
		.code = 0x5450,
	};
	struct binder_write_read bwr;
	uint8_t writes[sizeof(uint32_t) + sizeof(transaction)];
	uint32_t command = BC_TRANSACTION;

	memcpy(writes, &command, sizeof(command));
	memcpy(writes + sizeof(command), &transaction, sizeof(transaction));
	bwr = (struct binder_write_read) {
		.write_size = sizeof(writes),
		.write_buffer = (uint64_t)(uintptr_t)writes,
	};
	return ioctl(fd, BINDER_WRITE_READ, &bwr);
}

static int receive_transaction(int fd)
{
	struct binder_transaction_data transaction;
	struct binder_write_read bwr;
	uint8_t reads[READ_SIZE] = {};
	uint32_t command;

	bwr = (struct binder_write_read) {
		.read_size = sizeof(reads),
		.read_buffer = (uint64_t)(uintptr_t)reads,
	};
	if (ioctl(fd, BINDER_WRITE_READ, &bwr) < 0)
		return -1;
	if (bwr.read_consumed < sizeof(command) + sizeof(transaction))
		return -1;
	memcpy(&command, reads, sizeof(command));
	memcpy(&transaction, reads + sizeof(command), sizeof(transaction));
	return command == BR_TRANSACTION && transaction.code == 0x5450 ? 0 : -1;
}

int main(void)
{
	int ready[2] = { -1, -1 };
	int release[2] = { -1, -1 };
	uint32_t context_manager = 0;
	pid_t child;
	int binder_fd = open("/dev/binder", O_RDWR | O_CLOEXEC);
	int child_status;
	int test_result = 0;
	char token;

	if (binder_fd < 0) {
		perror("open /dev/binder");
		return 1;
	}
	if (ioctl(binder_fd, BINDER_SET_CONTEXT_MGR, &context_manager) < 0) {
		perror("BINDER_SET_CONTEXT_MGR");
		close(binder_fd);
		return 2;
	}
	if (pipe(ready) < 0 || pipe(release) < 0) {
		perror("pipe");
		close(binder_fd);
		return 3;
	}

	child = fork();
	if (child < 0) {
		perror("fork");
		return 4;
	}
	if (child == 0) {
		int client_fd;

		close(ready[0]);
		close(release[1]);
		client_fd = open("/dev/binder", O_RDWR | O_CLOEXEC);
		if (client_fd < 0)
			_exit(5);
		token = 'r';
		if (write(ready[1], &token, 1) != 1)
			_exit(6);
		usleep(100000);
		if (send_transaction(client_fd) < 0 ||
		    read(release[0], &token, 1) != 1)
			_exit(6);
		close(client_fd);
		_exit(0);
	}

	close(ready[1]);
	close(release[0]);
	if (read(ready[0], &token, 1) != 1) {
		perror("wait for transaction");
		return 5;
	}
	signal(SIGALRM, handle_alarm);
	alarm(5);
	if (receive_transaction(binder_fd) < 0) {
		fprintf(stderr, "blocking Binder read returned without a transaction\n");
		test_result = 8;
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
	close(binder_fd);

	if (test_result != 0) {
		fprintf(stderr, "BINDER_POLL_TRANSACTION=FAIL status=%d\n", test_result);
		return test_result;
	}
	puts("BINDER_POLL_TRANSACTION=PASS");
	return 0;
}
