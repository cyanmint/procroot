/*
 * SPDX-FileCopyrightText: NONE
 * SPDX-License-Identifier: GPL-2.0-or-later
 * Note: AI-generated contribution; no legal determination implied.
 */
/* A queued reply must survive the server accepting its next request. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <time.h>
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
#define BR_TRANSACTION _IOR('r', 2, struct binder_transaction_data)
#define BR_REPLY _IOR('r', 3, struct binder_transaction_data)
#define BR_TRANSACTION_COMPLETE _IO('r', 6)
#define CLIENTS 2
#define READ_SIZE 256
#define CODE_BASE 0x6200u

struct pipes { int ready[2], release[2], early[2]; };

static int write_transaction(int fd, uint32_t command, uint32_t code)
{
	struct binder_transaction_data txn = { .target = 0, .code = code };
	struct binder_write_read bwr;
	uint8_t bytes[sizeof(command) + sizeof(txn)];
	memcpy(bytes, &command, sizeof(command));
	memcpy(bytes + sizeof(command), &txn, sizeof(txn));
	bwr = (struct binder_write_read) {
		.write_size = sizeof(bytes), .write_buffer = (uint64_t)(uintptr_t)bytes,
	};
	if (ioctl(fd, BINDER_WRITE_READ, &bwr) < 0)
		return -1;
	return bwr.write_consumed == sizeof(bytes) ? 0 : -1;
}

static int receive_transaction(int fd, struct binder_transaction_data *txn)
{
	for (int attempt = 0; attempt < 20; attempt++) {
		struct pollfd pfd = { .fd = fd, .events = POLLIN };
		uint8_t reads[READ_SIZE] = {};
		struct binder_write_read bwr = {
			.read_size = sizeof(reads),
			.read_buffer = (uint64_t)(uintptr_t)reads,
		};
		if (poll(&pfd, 1, 500) <= 0)
			continue;
		if (ioctl(fd, BINDER_WRITE_READ, &bwr) < 0)
			return -1;
		if (bwr.read_consumed < sizeof(uint32_t))
			continue;
		uint32_t command;
		memcpy(&command, reads, sizeof(command));
		if (command == BR_TRANSACTION) {
			if (bwr.read_consumed < sizeof(command) + sizeof(*txn))
				return -2;
			memcpy(txn, reads + sizeof(command), sizeof(*txn));
			return 0;
		}
		if (command != BR_TRANSACTION_COMPLETE)
			return -3;
	}
	return -4;
}

static int receive_reply(int fd, uint32_t code, unsigned int timeout_ms)
{
	struct timespec start;
	clock_gettime(CLOCK_MONOTONIC, &start);
	for (;;) {
		struct pollfd pfd = { .fd = fd, .events = POLLIN };
		uint8_t reads[READ_SIZE] = {};
		struct binder_write_read bwr = {
			.read_size = sizeof(reads),
			.read_buffer = (uint64_t)(uintptr_t)reads,
		};
		int ready = poll(&pfd, 1, 10);
		if (ready < 0 && errno != EINTR)
			return -1;
		if (ready > 0 && ioctl(fd, BINDER_WRITE_READ, &bwr) < 0)
			return -2;
		if (ready > 0 && bwr.read_consumed >= sizeof(uint32_t)) {
			uint32_t command;
			memcpy(&command, reads, sizeof(command));
			if (command == BR_REPLY) {
				struct binder_transaction_data reply;
				if (bwr.read_consumed < sizeof(command) + sizeof(reply))
					return -3;
				memcpy(&reply, reads + sizeof(command), sizeof(reply));
				return reply.code == code ? 0 : -4;
			}
			if (command != BR_TRANSACTION_COMPLETE)
				return -5;
		}
		struct timespec now;
		clock_gettime(CLOCK_MONOTONIC, &now);
		uint64_t elapsed = (uint64_t)(now.tv_sec - start.tv_sec) * 1000;
		if (now.tv_nsec >= start.tv_nsec)
			elapsed += (uint64_t)(now.tv_nsec - start.tv_nsec) / 1000000;
		else
			elapsed -= (uint64_t)(start.tv_nsec - now.tv_nsec) / 1000000;
		if (elapsed >= timeout_ms)
			return 1;
	}
}

static void child_run(int index, int server_fd, struct pipes p[CLIENTS])
{
	for (int j = 0; j < CLIENTS; j++) {
		close(p[j].ready[0]); close(p[j].release[1]); close(p[j].early[0]);
		if (j != index) {
			close(p[j].ready[1]); close(p[j].release[0]); close(p[j].early[1]);
		}
	}
	close(server_fd);
	int fd = open("/dev/binder", O_RDWR | O_CLOEXEC);
	uint32_t code = CODE_BASE + (uint32_t)index;
	char token = 'x';
	if (fd < 0 || write_transaction(fd, (uint32_t)BC_TRANSACTION, code) < 0)
		_exit(10);
	if (write(p[index].ready[1], &token, 1) != 1 ||
	    read(p[index].release[0], &token, 1) != 1)
		_exit(11);
	int early = receive_reply(fd, code, 1200);
	token = early == 0 ? '0' : '1';
	if (write(p[index].early[1], &token, 1) != 1)
		_exit(12);
	int final = early == 0 ? 0 : receive_reply(fd, code, 8000);
	close(fd);
	_exit(final == 0 ? 0 : 13);
}

int main(void)
{
	int server_fd = open("/dev/binder", O_RDWR | O_CLOEXEC);
	uint32_t manager = 0;
	struct pipes p[CLIENTS];
	pid_t clients[CLIENTS];
	struct binder_transaction_data first, second;
	char token = 'r';
	int first_id, second_id, early, status[CLIENTS] = {};
	bool pass;

	if (server_fd < 0 || ioctl(server_fd, BINDER_SET_CONTEXT_MGR, &manager) < 0) {
		perror("Binder context-manager setup"); return 1;
	}
	for (int i = 0; i < CLIENTS; i++)
		if (pipe(p[i].ready) || pipe(p[i].release) || pipe(p[i].early)) {
			perror("pipe"); return 2;
		}
	for (int i = 0; i < CLIENTS; i++) {
		clients[i] = fork();
		if (clients[i] < 0) { perror("fork"); return 3; }
		if (clients[i] == 0) child_run(i, server_fd, p);
	}
	for (int i = 0; i < CLIENTS; i++) {
		close(p[i].ready[1]); close(p[i].release[0]); close(p[i].early[1]);
		if (read(p[i].ready[0], &token, 1) != 1) return 4;
	}
	if (receive_transaction(server_fd, &first) < 0 ||
	    first.code < CODE_BASE || first.code >= CODE_BASE + CLIENTS)
		return 5;
	first_id = (int)(first.code - CODE_BASE);
	if (write_transaction(server_fd, (uint32_t)BC_REPLY, first.code) < 0)
		return 6;
	if (receive_transaction(server_fd, &second) < 0 ||
	    second.code < CODE_BASE || second.code >= CODE_BASE + CLIENTS ||
	    second.code == first.code)
		return 7;
	second_id = (int)(second.code - CODE_BASE);
	if (write(p[first_id].release[1], &token, 1) != 1 ||
	    read(p[first_id].early[0], &token, 1) != 1)
		return 8;
	early = token == '0' ? 0 : 1;
	if (write_transaction(server_fd, (uint32_t)BC_REPLY, second.code) < 0 ||
	    write(p[second_id].release[1], &token, 1) != 1)
		return 9;
	for (int i = 0; i < CLIENTS; i++)
		if (waitpid(clients[i], &status[i], 0) < 0) return 10;
	pass = early == 0;
	for (int i = 0; i < CLIENTS; i++)
		pass = pass && WIFEXITED(status[i]) && WEXITSTATUS(status[i]) == 0;
	printf("EARLY_REPLY_RECEIVED=%d CLIENT0_STATUS=%#x CLIENT1_STATUS=%#x\n",
		early == 0, status[0], status[1]);
	close(server_fd);
	for (int i = 0; i < CLIENTS; i++) {
		close(p[i].ready[0]); close(p[i].release[1]); close(p[i].early[0]);
	}
	puts(pass ? "BINDER_DEFERRED_REPLY_FRAME=PASS" :
		"BINDER_DEFERRED_REPLY_FRAME=FAIL");
	return pass ? 0 : 11;
}
