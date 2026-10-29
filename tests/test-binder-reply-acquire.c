/*
 * SPDX-FileCopyrightText: NONE
 * SPDX-License-Identifier: GPL-2.0-or-later
 * Note: AI-generated contribution; no legal determination implied.
 */
/* Verify reply-transferred Binder objects are acquired before delivery. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>

#define MAPPING_SIZE 65536
#define REGISTER_CODE 0x52414351
#define EXPORT_CODE 0x52414352
#define FIRST_BINDER 0x12345678
#define FIRST_COOKIE 0x87654321
#define REPLY_BINDER 0x23456789
#define REPLY_COOKIE 0x98765432
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

struct binder_ptr_cookie {
	uint64_t ptr;
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
#define BC_ACQUIRE_DONE _IOW('c', 9, struct binder_ptr_cookie)
#define BR_TRANSACTION _IOR('r', 2, struct binder_transaction_data)
#define BR_REPLY _IOR('r', 3, struct binder_transaction_data)
#define BR_TRANSACTION_COMPLETE _IO('r', 6)
#define BR_ACQUIRE _IOR('r', 8, struct binder_ptr_cookie)
#define BR_RELEASE _IOR('r', 9, struct binder_ptr_cookie)

static int inherited_manager_fd = -1;

static void ignore_alarm(int signal_number)
{
	(void)signal_number;
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
	return fd;
}

static int write_command(int fd, uint32_t command,
		const void *payload, size_t payload_size)
{
	uint8_t writes[sizeof(command) + sizeof(struct binder_transaction_data)];
	struct binder_write_read bwr = {};
	size_t write_size = sizeof(command) + payload_size;

	if (write_size > sizeof(writes))
		return -1;
	memcpy(writes, &command, sizeof(command));
	if (payload_size != 0)
		memcpy(writes + sizeof(command), payload, payload_size);
	bwr.write_size = write_size;
	bwr.write_buffer = (uint64_t)(uintptr_t)writes;
	return ioctl(fd, BINDER_WRITE_READ, &bwr) < 0 ||
		bwr.write_consumed != write_size ? -1 : 0;
}

static int send_transaction(int fd, uint32_t command,
		struct binder_transaction_data *transaction)
{
	return write_command(fd, command, transaction, sizeof(*transaction));
}

static size_t event_payload_size(uint32_t command)
{
	switch (command) {
	case BR_TRANSACTION:
	case BR_REPLY:
		return sizeof(struct binder_transaction_data);
	case BR_ACQUIRE:
	case BR_RELEASE:
		return sizeof(struct binder_ptr_cookie);
	case BR_TRANSACTION_COMPLETE:
		return 0;
	default:
		return SIZE_MAX;
	}
}

static int read_event(int fd, int timeout_ms, size_t max_payload,
		uint32_t *command_out, void *payload_out, size_t payload_capacity)
{
	struct pollfd poll_fd = { .fd = fd, .events = POLLIN };
	uint8_t reads[sizeof(uint32_t) + sizeof(struct binder_transaction_data)];
	struct binder_write_read bwr = {};
	int ready;

	if (max_payload > sizeof(struct binder_transaction_data))
		return -1;
	ready = poll(&poll_fd, 1, timeout_ms);
	if (ready <= 0)
		return ready;
	bwr.read_size = sizeof(uint32_t) + max_payload;
	bwr.read_buffer = (uint64_t)(uintptr_t)reads;
	if (ioctl(fd, BINDER_WRITE_READ, &bwr) < 0)
		return -1;
	if (bwr.read_consumed < sizeof(uint32_t))
		return -1;
	memcpy(command_out, reads, sizeof(*command_out));
	if (*command_out == BR_TRANSACTION_COMPLETE)
		return 2;
	{
		size_t payload_size = event_payload_size(*command_out);

		if (payload_size == SIZE_MAX || payload_size > max_payload ||
		    payload_size > payload_capacity ||
		    bwr.read_consumed < sizeof(uint32_t) + payload_size)
			return -1;
		if (payload_size != 0)
			memcpy(payload_out, reads + sizeof(uint32_t), payload_size);
	}
	return 1;
}

static int send_acquire_done(int fd,
		const struct binder_ptr_cookie *pair)
{
	return write_command(fd, (uint32_t)BC_ACQUIRE_DONE,
		pair, sizeof(*pair));
}

static int free_buffer(int fd, uint64_t buffer)
{
	return write_command(fd, (uint32_t)BC_FREE_BUFFER,
		&buffer, sizeof(buffer));
}

static int wait_for_pipe_event(int fd, int timeout_ms, char *event)
{
	struct pollfd poll_fd = { .fd = fd, .events = POLLIN };

	if (poll(&poll_fd, 1, timeout_ms) != 1 ||
	    read(fd, event, sizeof(*event)) != sizeof(*event))
		return -1;
	return 0;
}

static int read_expected_event(int fd, int timeout_ms, uint32_t expected,
		void *payload, size_t payload_size)
{
	for (;;) {
		uint32_t command;
		int status = read_event(fd, timeout_ms, payload_size,
			&command, payload, payload_size);

		if (status <= 0)
			return status;
		if (status == 2)
			continue;
		return command == expected ? 1 : -1;
	}
}

static int send_pipe_event(int fd, char event)
{
	return write(fd, &event, sizeof(event)) == sizeof(event) ? 0 : -1;
}

static int service_process(int events_fd)
{
	struct flat_binder_object local_object = {
		.type = BINDER_TYPE_BINDER,
		.flags = 0x7f,
		.object.binder = FIRST_BINDER,
		.cookie = FIRST_COOKIE,
	};
	struct binder_transaction_data registration = {
		.code = REGISTER_CODE,
		.flags = 1,
		.data_size = sizeof(local_object),
		.offsets_size = sizeof(uint64_t),
		.data_buffer = (uint64_t)(uintptr_t)&local_object,
	};
	struct binder_transaction_data request;
	struct flat_binder_object reply_object = {
		.type = BINDER_TYPE_BINDER,
		.flags = 0x7f,
		.object.binder = REPLY_BINDER,
		.cookie = REPLY_COOKIE,
	};
	struct binder_transaction_data reply = {
		.data_size = sizeof(reply_object),
		.offsets_size = sizeof(uint64_t),
		.data_buffer = (uint64_t)(uintptr_t)&reply_object,
	};
	uint64_t offset = 0;
	int fd;

	if (inherited_manager_fd >= 0)
		close(inherited_manager_fd);
	fd = open_binder();
	if (fd < 0)
		return 10;
	registration.offsets_buffer = (uint64_t)(uintptr_t)&offset;
	if (send_transaction(fd, (uint32_t)BC_TRANSACTION, &registration) < 0)
		return 11;
	for (;;) {
		uint32_t command;
		struct binder_ptr_cookie pair;
		int status = read_event(fd, 2500, sizeof(pair), &command,
			&pair, sizeof(pair));

		if (status == 0)
			continue;
		if (status < 0)
			return 12;
		if (status == 2)
			continue;
		if (command == BR_RELEASE && pair.ptr == FIRST_BINDER &&
		    pair.cookie == FIRST_COOKIE)
			continue;
		if (command != BR_ACQUIRE || pair.ptr != FIRST_BINDER ||
		    pair.cookie != FIRST_COOKIE ||
		    send_acquire_done(fd, &pair) < 0)
			return 13;
		break;
	}
	if (send_pipe_event(events_fd, 'A') < 0)
		return 14;
	for (;;) {
		uint32_t command;
		int status = read_event(fd, 5000, sizeof(request), &command,
			&request, sizeof(request));

		if (status == 0)
			continue;
		if (status < 0)
			return 15;
		if (status == 2)
			continue;
		if (command == BR_RELEASE)
			continue;
		if (command != BR_TRANSACTION || request.code != EXPORT_CODE)
			return 16;
		break;
	}
	if (free_buffer(fd, request.data_buffer) < 0)
		return 17;
	reply.offsets_buffer = (uint64_t)(uintptr_t)&offset;
	if (send_transaction(fd, (uint32_t)BC_REPLY, &reply) < 0)
		return 18;
	for (;;) {
		uint32_t command;
		struct binder_ptr_cookie pair;
		int status = read_event(fd, 2500, sizeof(pair), &command,
			&pair, sizeof(pair));

		if (status == 0) {
			if (send_pipe_event(events_fd, 'M') < 0)
				return 19;
			return 20;
		}
		if (status < 0)
			return 21;
		if (status == 2)
			continue;
		if (command == BR_ACQUIRE && pair.ptr == REPLY_BINDER &&
		    pair.cookie == REPLY_COOKIE) {
			if (send_acquire_done(fd, &pair) < 0 ||
			    send_pipe_event(events_fd, 'E') < 0)
				return 22;
			break;
		}
		if (command == BR_RELEASE && pair.ptr == FIRST_BINDER &&
		    pair.cookie == FIRST_COOKIE)
			continue;
		return 23;
	}
	for (;;) {
		uint32_t command;
		struct binder_ptr_cookie pair;
		int status = read_event(fd, 5000, sizeof(pair), &command,
			&pair, sizeof(pair));

		if (status == 0)
			continue;
		if (status < 0)
			return 24;
		if (status == 2)
			continue;
		if (command == BR_RELEASE && pair.ptr == REPLY_BINDER &&
		    pair.cookie == REPLY_COOKIE)
			break;
	}
	if (send_pipe_event(events_fd, 'R') < 0)
		return 25;
	close(fd);
	return 0;
}

int main(void)
{
	struct sigaction action = { .sa_handler = ignore_alarm };
	struct binder_transaction_data transaction;
	struct flat_binder_object object;
	struct flat_binder_object returned;
	uint32_t context_manager = 0;
	int events[2];
	int fd = open_binder();
	pid_t service;
	int service_status;
	char event = 0;

	if (fd < 0) {
		perror("open or mmap /dev/binder");
		return 1;
	}
	if (ioctl(fd, BINDER_SET_CONTEXT_MGR, &context_manager) < 0) {
		perror("BINDER_SET_CONTEXT_MGR");
		close(fd);
		return 2;
	}
	if (sigaction(SIGALRM, &action, NULL) < 0 || pipe(events) < 0)
		return 3;
	inherited_manager_fd = fd;
	service = fork();
	if (service < 0)
		return 4;
	if (service == 0) {
		close(events[0]);
		alarm(15);
		_exit(service_process(events[1]));
	}
	close(events[1]);
	alarm(15);
	if (read_expected_event(fd, 5000, BR_TRANSACTION,
			&transaction, sizeof(transaction)) <= 0) {
		fprintf(stderr, "REPLY_ACQUIRE_REGISTRATION_MISSING\n");
		goto fail;
	}
	if (transaction.code != REGISTER_CODE ||
	    transaction.data_size < sizeof(object)) {
		fprintf(stderr, "REPLY_ACQUIRE_REGISTRATION_INVALID\n");
		goto fail;
	}
	memcpy(&object, (void *)(uintptr_t)transaction.data_buffer, sizeof(object));
	if (object.type != BINDER_TYPE_HANDLE || object.object.handle == 0) {
		fprintf(stderr, "REPLY_ACQUIRE_HANDLE_INVALID\n");
		goto fail;
	}
	if (wait_for_pipe_event(events[0], 6000, &event) < 0 || event != 'A') {
		fprintf(stderr, "REPLY_ACQUIRE_INITIAL_ACQUIRE_MISSING\n");
		goto fail;
	}
	if (free_buffer(fd, transaction.data_buffer) < 0) {
		perror("BC_FREE_BUFFER registration");
		goto fail;
	}
	{
		uint32_t request_payload = EXPORT_CODE;
		transaction = (struct binder_transaction_data) {
		.target = object.object.handle,
		.code = EXPORT_CODE,
		.data_size = sizeof(request_payload),
		.data_buffer = (uint64_t)(uintptr_t)&request_payload,
	};
		if (send_transaction(fd, (uint32_t)BC_TRANSACTION, &transaction) < 0) {
		perror("BC_TRANSACTION export request");
		goto fail;
	}
	}
	if (wait_for_pipe_event(events[0], 6000, &event) < 0 || event != 'E') {
		if (event == 'M')
			fprintf(stderr, "REPLY_ACQUIRE_EARLY_ACQUIRE_MISSING\n");
		else
			fprintf(stderr, "REPLY_ACQUIRE_SERVICE_DID_NOT_CONFIRM\n");
		goto fail;
	}
	if (read_expected_event(fd, 5000, BR_REPLY,
			&transaction, sizeof(transaction)) <= 0 ||
	    transaction.data_size < sizeof(returned)) {
		fprintf(stderr, "REPLY_ACQUIRE_REPLY_MISSING\n");
		goto fail;
	}
	memcpy(&returned, (void *)(uintptr_t)transaction.data_buffer,
		sizeof(returned));
	if (returned.type != BINDER_TYPE_HANDLE || returned.object.handle == 0) {
		fprintf(stderr, "REPLY_ACQUIRE_REPLY_HANDLE_INVALID\n");
		goto fail;
	}
	if (free_buffer(fd, transaction.data_buffer) < 0) {
		perror("BC_FREE_BUFFER reply");
		goto fail;
	}
	if (wait_for_pipe_event(events[0], 6000, &event) < 0 || event != 'R') {
		fprintf(stderr, "REPLY_ACQUIRE_RELEASE_MISSING\n");
		goto fail;
	}
	alarm(0);
	waitpid(service, &service_status, 0);
	close(events[0]);
	close(fd);
	if (!WIFEXITED(service_status) || WEXITSTATUS(service_status) != 0) {
		fprintf(stderr, "REPLY_ACQUIRE_SERVICE_STATUS=%#x\n", service_status);
		return 5;
	}
	puts("BINDER_REPLY_EARLY_ACQUIRE=PASS");
	return 0;

fail:
	alarm(0);
	kill(service, SIGKILL);
	waitpid(service, &service_status, 0);
	close(events[0]);
	close(fd);
	return 6;
}
