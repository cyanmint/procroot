/*
 * SPDX-FileCopyrightText: NONE
 * SPDX-License-Identifier: GPL-2.0-or-later
 * Note: AI-generated contribution; no legal determination implied.
 */
/* Verify Binder transactions can reach any thread in a process. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
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
#define BR_REPLY _IOR('r', 3, struct binder_transaction_data)
#define MAX_READ_SIZE 256

struct test_state {
	int fd;
	pthread_mutex_t mutex;
	pthread_cond_t condition;
	int result;
};

static void set_result(struct test_state *state, int result)
{
	pthread_mutex_lock(&state->mutex);
	state->result = result;
	pthread_cond_broadcast(&state->condition);
	pthread_mutex_unlock(&state->mutex);
}

static int send_reply(int fd)
{
	struct binder_transaction_data transaction = { .code = 0x5453 };
	struct binder_write_read bwr;
	uint8_t writes[sizeof(uint32_t) + sizeof(transaction)];
	uint32_t command = BC_REPLY;

	memcpy(writes, &command, sizeof(command));
	memcpy(writes + sizeof(command), &transaction, sizeof(transaction));
	bwr = (struct binder_write_read) {
		.write_size = sizeof(writes),
		.write_buffer = (uint64_t)(uintptr_t)writes,
	};
	return ioctl(fd, BINDER_WRITE_READ, &bwr);
}

static void *receive_transaction(void *argument)
{
	struct test_state *state = argument;
	struct timespec start;
	struct timespec now;

	if (clock_gettime(CLOCK_MONOTONIC, &start) < 0) {
		set_result(state, -1);
		return NULL;
	}
	for (;;) {
		uint8_t reads[MAX_READ_SIZE] = {};
		struct binder_write_read bwr = {
			.read_size = sizeof(reads),
			.read_buffer = (uint64_t)(uintptr_t)reads,
		};
		uint32_t command;

		if (ioctl(state->fd, BINDER_WRITE_READ, &bwr) < 0) {
			set_result(state, -1);
			return NULL;
		}
		if (bwr.read_consumed >= sizeof(command)) {
			memcpy(&command, reads, sizeof(command));
			if (command == BR_TRANSACTION) {
				if (send_reply(state->fd) < 0) {
					set_result(state, -1);
					return NULL;
				}
				set_result(state, 1);
				return NULL;
			}
		}
		if (clock_gettime(CLOCK_MONOTONIC, &now) < 0) {
			set_result(state, -1);
			return NULL;
		}
		if (now.tv_sec - start.tv_sec >= 2) {
			set_result(state, -2);
			return NULL;
		}
	}
}

int main(void)
{
	struct test_state state = { .fd = -1 };
	struct binder_transaction_data transaction = { .target = 0, .code = 0x5452 };
	struct binder_write_read bwr;
	struct timespec deadline;
	uint8_t writes[sizeof(uint32_t) + sizeof(transaction)];
	uint8_t reads[MAX_READ_SIZE] = {};
	uint32_t context_manager = 0;
	uint32_t command = BC_TRANSACTION;
	uint32_t returned_command;
	struct binder_transaction_data returned_transaction;
	pthread_t worker;
	int wait_status = 0;	
	int result;

	state.fd = open("/dev/binder", O_RDWR | O_CLOEXEC);
	if (state.fd < 0) {
		perror("open /dev/binder");
		return 1;
	}
	if (ioctl(state.fd, BINDER_SET_CONTEXT_MGR, &context_manager) < 0) {
		perror("BINDER_SET_CONTEXT_MGR");
		close(state.fd);
		return 2;
	}
	if (pthread_mutex_init(&state.mutex, NULL) != 0 ||
	    pthread_cond_init(&state.condition, NULL) != 0) {
		fprintf(stderr, "failed to initialize synchronization\n");
		close(state.fd);
		return 3;
	}
	state.result = 0;
	if (pthread_create(&worker, NULL, receive_transaction, &state) != 0) {
		fprintf(stderr, "failed to create Binder receiver thread\n");
		close(state.fd);
		return 4;
	}

	memcpy(writes, &command, sizeof(command));
	memcpy(writes + sizeof(command), &transaction, sizeof(transaction));
	bwr = (struct binder_write_read) {
		.write_size = sizeof(writes),
		.write_buffer = (uint64_t)(uintptr_t)writes,
	};
	if (ioctl(state.fd, BINDER_WRITE_READ, &bwr) < 0) {
		perror("BINDER_WRITE_READ transaction");
		set_result(&state, -1);
	}

	clock_gettime(CLOCK_REALTIME, &deadline);
	deadline.tv_sec += 3;
	pthread_mutex_lock(&state.mutex);
	while (state.result == 0 && wait_status == 0)
		wait_status = pthread_cond_timedwait(&state.condition, &state.mutex,
						     &deadline);
	result = state.result;
	pthread_mutex_unlock(&state.mutex);
	pthread_join(worker, NULL);
	if (result == 1) {
		bwr = (struct binder_write_read) {
			.read_size = sizeof(reads),
			.read_buffer = (uint64_t)(uintptr_t)reads,
		};
		if (ioctl(state.fd, BINDER_WRITE_READ, &bwr) < 0 ||
		    bwr.read_consumed < sizeof(returned_command) +
					 sizeof(returned_transaction)) {
			result = -3;
		}
		else {
			memcpy(&returned_command, reads, sizeof(returned_command));
			memcpy(&returned_transaction, reads + sizeof(returned_command),
			       sizeof(returned_transaction));
			if (returned_command != BR_REPLY ||
			    returned_transaction.code != 0x5453)
				result = -4;
		}
	}
	pthread_cond_destroy(&state.condition);
	pthread_mutex_destroy(&state.mutex);
	close(state.fd);

	if (result != 1) {
		fprintf(stderr, "transaction was not delivered to another Binder thread (result=%d)\n",
			result);
		return 5;
	}
	puts("BINDER_CROSS_THREAD_ROUNDTRIP=PASS");
	return 0;
}
