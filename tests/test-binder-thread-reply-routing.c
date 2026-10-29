/*
 * SPDX-FileCopyrightText: NONE
 * SPDX-License-Identifier: GPL-2.0-or-later
 * Note: AI-generated contribution; no legal determination implied.
 */
/* Verify Binder replies are routed to the originating thread. */
#define _GNU_SOURCE
#include <fcntl.h>
#include <pthread.h>
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
#define BR_REPLY _IOR('r', 3, struct binder_transaction_data)
#define MAX_READ_SIZE 256
#define CLIENT_COUNT 2
#define MAX_READ_ATTEMPTS 400

struct test_state {
	int fd;
	pthread_mutex_t mutex;
	pthread_cond_t condition;
	int received;
	int replies;
	int failed;
};

struct worker_argument {
	struct test_state *state;
};

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
	return ioctl(fd, BINDER_WRITE_READ, &bwr);
}

static int send_reply(int fd,
		const struct binder_transaction_data *transaction)
{
	struct binder_transaction_data reply = *transaction;
	uint32_t response = UINT32_C(0x52455000) +
		(transaction->code - UINT32_C(0x5450));

	reply.target = UINT64_MAX;
	reply.cookie = 0;
	reply.flags = 0;
	reply.data_size = sizeof(response);
	reply.offsets_size = 0;
	reply.data_buffer = (uint64_t)(uintptr_t)&response;
	reply.offsets_buffer = 0;
	return send_command(fd, BC_REPLY, &reply);
}

static int client_roundtrip(int fd, int signal_fd, uint32_t code)
{
	struct binder_transaction_data transaction = { .target = 0, .code = code };
	char token;
	int attempt;

	if (read(signal_fd, &token, 1) != 1)
		return 10;
	if (send_command(fd, BC_TRANSACTION, &transaction) < 0)
		return 11;
	for (attempt = 0; attempt < MAX_READ_ATTEMPTS; attempt++) {
		uint8_t reads[MAX_READ_SIZE] = {};
		struct binder_write_read bwr = {
			.read_size = sizeof(reads),
			.read_buffer = (uint64_t)(uintptr_t)reads,
		};
		uint32_t command;
		struct binder_transaction_data reply;

		if (ioctl(fd, BINDER_WRITE_READ, &bwr) < 0)
			return 12;
		if (bwr.read_consumed < sizeof(command) + sizeof(reply))
			continue;
		memcpy(&command, reads, sizeof(command));
		if (command != BR_REPLY)
			continue;
		memcpy(&reply, reads + sizeof(command), sizeof(reply));
		if (reply.code != code || reply.data_size != sizeof(uint32_t) ||
		    reply.data_buffer == 0)
			return 13;
		{
			uint32_t response;
			uint32_t expected = UINT32_C(0x52455000) +
				(code - UINT32_C(0x5450));

			memcpy(&response,
				(const void *)(uintptr_t)reply.data_buffer,
				sizeof(response));
			return response == expected ? 0 : 15;
		}
	}
	return 14;
}

static void *receive_and_reply(void *argument)
{
	struct worker_argument *worker = argument;
	struct test_state *state = worker->state;
	struct timespec deadline;
	int attempt;

	clock_gettime(CLOCK_REALTIME, &deadline);
	deadline.tv_sec += 4;
	for (attempt = 0; attempt < MAX_READ_ATTEMPTS; attempt++) {
		uint8_t reads[MAX_READ_SIZE] = {};
		struct binder_write_read bwr = {
			.read_size = sizeof(reads),
			.read_buffer = (uint64_t)(uintptr_t)reads,
		};
		uint32_t command;
		struct binder_transaction_data request;
		int wait_status = 0;
		int failed;

		if (ioctl(state->fd, BINDER_WRITE_READ, &bwr) < 0) {
			pthread_mutex_lock(&state->mutex);
			state->failed = 1;
			pthread_cond_broadcast(&state->condition);
			pthread_mutex_unlock(&state->mutex);
			return NULL;
		}
		if (bwr.read_consumed < sizeof(command) + sizeof(request))
			continue;
		memcpy(&command, reads, sizeof(command));
		if (command != BR_TRANSACTION)
			continue;
		memcpy(&request, reads + sizeof(command), sizeof(request));

		pthread_mutex_lock(&state->mutex);
		state->received++;
		pthread_cond_broadcast(&state->condition);
		while (state->received < CLIENT_COUNT && !state->failed &&
		       wait_status == 0)
			wait_status = pthread_cond_timedwait(&state->condition,
						     &state->mutex, &deadline);
		if (wait_status != 0 || state->failed)
			state->failed = 1;
		failed = state->failed;
		pthread_cond_broadcast(&state->condition);
		pthread_mutex_unlock(&state->mutex);
		if (failed)
			return NULL;

		request.target = UINT64_C(0xffffffff);
		if (send_reply(state->fd, &request) < 0) {
			pthread_mutex_lock(&state->mutex);
			state->failed = 1;
			pthread_cond_broadcast(&state->condition);
			pthread_mutex_unlock(&state->mutex);
			return NULL;
		}
		pthread_mutex_lock(&state->mutex);
		state->replies++;
		pthread_cond_broadcast(&state->condition);
		pthread_mutex_unlock(&state->mutex);
		return NULL;
	}

	pthread_mutex_lock(&state->mutex);
	state->failed = 1;
	pthread_cond_broadcast(&state->condition);
	pthread_mutex_unlock(&state->mutex);
	return NULL;
}

int main(void)
{
	struct test_state state = { .fd = -1 };
	struct worker_argument worker_argument = { .state = &state };
	pthread_t workers[CLIENT_COUNT];
	pid_t clients[CLIENT_COUNT];
	int pipes[CLIENT_COUNT][2] = { { -1, -1 }, { -1, -1 } };
	int statuses[CLIENT_COUNT] = {};
	uint32_t context_manager = 0;
	int i;

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

	for (i = 0; i < CLIENT_COUNT; i++) {
		if (pipe(pipes[i]) < 0) {
			perror("pipe");
			return 4;
		}
		clients[i] = fork();
		if (clients[i] < 0) {
			perror("fork");
			return 5;
		}
		if (clients[i] == 0) {
			int j;

			for (j = 0; j <= i; j++) {
				if (j != i) {
					close(pipes[j][0]);
					close(pipes[j][1]);
				}
				else
					close(pipes[j][1]);
			}
			_exit(client_roundtrip(state.fd, pipes[i][0],
					       0x5450u + (uint32_t)i));
		}
	}
	for (i = 0; i < CLIENT_COUNT; i++)
		close(pipes[i][0]);

	for (i = 0; i < CLIENT_COUNT; i++) {
		if (pthread_create(&workers[i], NULL, receive_and_reply,
				   &worker_argument) != 0) {
			fprintf(stderr, "failed to create Binder receiver thread\n");
			return 6;
		}
	}
	for (i = 0; i < CLIENT_COUNT; i++) {
		char token = 'x';

		if (write(pipes[i][1], &token, 1) != 1) {
			perror("write client start");
			return 7;
		}
		close(pipes[i][1]);
	}

	for (i = 0; i < CLIENT_COUNT; i++) {
		if (waitpid(clients[i], &statuses[i], 0) < 0) {
			perror("waitpid");
			return 8;
		}
	}
	for (i = 0; i < CLIENT_COUNT; i++)
		pthread_join(workers[i], NULL);

	pthread_mutex_lock(&state.mutex);
	i = state.received == CLIENT_COUNT && state.replies == CLIENT_COUNT &&
		!state.failed;
	fprintf(stderr, "received=%d replies=%d failed=%d\n", state.received,
		state.replies, state.failed);
	pthread_mutex_unlock(&state.mutex);
	for (int j = 0; j < CLIENT_COUNT; j++) {
		if (WIFEXITED(statuses[j]))
			fprintf(stderr, "client%d_exit=%d\n", j,
				WEXITSTATUS(statuses[j]));
		else
			fprintf(stderr, "client%d_status=0x%x\n", j, statuses[j]);
		i = i && WIFEXITED(statuses[j]) && WEXITSTATUS(statuses[j]) == 0;
	}
	pthread_cond_destroy(&state.condition);
	pthread_mutex_destroy(&state.mutex);
	close(state.fd);

	if (!i) {
		fprintf(stderr,
			"concurrent Binder replies were not routed to their callers\n");
		return 9;
	}
	puts("BINDER_CROSS_THREAD_REPLY_ROUTING=PASS");
	puts("BINDER_CROSS_THREAD_REPLY_PAYLOAD=PASS");
	return 0;
}
