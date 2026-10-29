/*
 * SPDX-FileCopyrightText: NONE
 * SPDX-License-Identifier: GPL-2.0-or-later
 * Note: AI-generated contribution; no legal determination implied.
 */
/* Verify Binder object transfers hold references until BC_FREE_BUFFER. */
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
#define REGISTER_CODE 0x54524652
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
#define BC_FREE_BUFFER _IOW('c', 3, uint64_t)
#define BC_INCREFS_DONE _IOW('c', 8, struct binder_ptr_cookie)
#define BC_ACQUIRE_DONE _IOW('c', 9, struct binder_ptr_cookie)
#define BR_TRANSACTION _IOR('r', 2, struct binder_transaction_data)
#define BR_TRANSACTION_COMPLETE _IO('r', 6)
#define BR_INCREFS _IOR('r', 7, struct binder_ptr_cookie)
#define BR_ACQUIRE _IOR('r', 8, struct binder_ptr_cookie)
#define BR_RELEASE _IOR('r', 9, struct binder_ptr_cookie)
#define BR_DECREFS _IOR('r', 10, struct binder_ptr_cookie)

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

static int send_transaction(int fd,
		struct binder_transaction_data *transaction)
{
	uint32_t command = (uint32_t)BC_TRANSACTION;
	uint8_t writes[sizeof(command) + sizeof(*transaction)];
	struct binder_write_read bwr = {};

	memcpy(writes, &command, sizeof(command));
	memcpy(writes + sizeof(command), transaction, sizeof(*transaction));
	bwr.write_size = sizeof(writes);
	bwr.write_buffer = (uint64_t)(uintptr_t)writes;
	return ioctl(fd, BINDER_WRITE_READ, &bwr) < 0 ||
		bwr.write_consumed != sizeof(writes) ? -1 : 0;
}

static int read_registration(int fd,
		struct binder_transaction_data *transaction)
{
	for (;;) {
		uint8_t reads[sizeof(uint32_t) + sizeof(*transaction) + 64] = {};
		struct binder_write_read bwr = {
			.read_size = sizeof(reads),
			.read_buffer = (uint64_t)(uintptr_t)reads,
		};
		size_t position = 0;

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
			return 0;
		}
	}
}

static int send_reference_done(int fd, uint32_t command,
		const struct binder_ptr_cookie *pair)
{
	uint8_t writes[sizeof(command) + sizeof(*pair)];
	struct binder_write_read bwr = {};

	memcpy(writes, &command, sizeof(command));
	memcpy(writes + sizeof(command), pair, sizeof(*pair));
	bwr.write_size = sizeof(writes);
	bwr.write_buffer = (uint64_t)(uintptr_t)writes;
	return ioctl(fd, BINDER_WRITE_READ, &bwr) < 0 ||
		bwr.write_consumed != sizeof(writes) ? -1 : 0;
}

static int read_reference(int fd, uint32_t expected)
{
	for (;;) {
		uint8_t reads[sizeof(uint32_t) + sizeof(struct binder_ptr_cookie) + 64] = {};
		struct pollfd poll_fd = { .fd = fd, .events = POLLIN };
		struct binder_write_read bwr = {
			.read_size = sizeof(reads),
			.read_buffer = (uint64_t)(uintptr_t)reads,
		};
		size_t position = 0;
		int ready = poll(&poll_fd, 1, 250);

		if (ready <= 0)
			return ready;
		if (ioctl(fd, BINDER_WRITE_READ, &bwr) < 0)
			return -1;
		while (position + sizeof(uint32_t) <= bwr.read_consumed) {
			struct binder_ptr_cookie pair;
			uint32_t command;

			memcpy(&command, reads + position, sizeof(command));
			position += sizeof(command);
			if (command == BR_TRANSACTION_COMPLETE)
				continue;
			if ((command != BR_INCREFS && command != BR_ACQUIRE &&
			     command != BR_RELEASE && command != BR_DECREFS) ||
			    position + sizeof(pair) > bwr.read_consumed)
				return -1;
			memcpy(&pair, reads + position, sizeof(pair));
			position += sizeof(pair);
			if (pair.ptr != 0x12345678 || pair.cookie != 0x87654321)
				return -1;
			if (command == BR_INCREFS || command == BR_ACQUIRE) {
				uint32_t done = command == BR_INCREFS ?
					(uint32_t)BC_INCREFS_DONE :
					(uint32_t)BC_ACQUIRE_DONE;

				if (send_reference_done(fd, done, &pair) < 0)
					return -1;
			}
			if (command == expected)
				return 1;
		}
	}
}

static int wait_for_event(int fd, char expected)
{
	struct pollfd poll_fd = { .fd = fd, .events = POLLIN };
	char event;

	if (poll(&poll_fd, 1, 2500) != 1 ||
	    read(fd, &event, sizeof(event)) != sizeof(event) ||
	    event != expected)
		return -1;
	return 0;
}

static int free_buffer(int fd, uint64_t buffer)
{
	uint32_t command = (uint32_t)BC_FREE_BUFFER;
	uint8_t writes[sizeof(command) + sizeof(buffer)];
	struct binder_write_read bwr = {};

	memcpy(writes, &command, sizeof(command));
	memcpy(writes + sizeof(command), &buffer, sizeof(buffer));
	bwr.write_size = sizeof(writes);
	bwr.write_buffer = (uint64_t)(uintptr_t)writes;
	return ioctl(fd, BINDER_WRITE_READ, &bwr) < 0 ||
		bwr.write_consumed != sizeof(writes) ? -1 : 0;
}

static int service_process(int events_fd)
{
	struct flat_binder_object object = {
		.type = BINDER_TYPE_BINDER,
		.flags = 0x7f,
		.object.binder = 0x12345678,
		.cookie = 0x87654321,
	};
	struct binder_transaction_data registration = {
		.code = REGISTER_CODE,
		.flags = 1,
		.data_size = sizeof(object),
		.offsets_size = sizeof(uint64_t),
		.data_buffer = (uint64_t)(uintptr_t)&object,
	};
	uint64_t offset = 0;
	int fd = open_binder();

	if (fd < 0)
		return 10;
	registration.offsets_buffer = (uint64_t)(uintptr_t)&offset;
	if (send_transaction(fd, &registration) < 0)
		return 11;
	for (;;) {
		int status = read_reference(fd, BR_ACQUIRE);

		if (status < 0)
			return 12;
		if (status > 0)
			break;
	}
	if (write(events_fd, "A", 1) != 1)
		return 13;
	for (;;) {
		int status = read_reference(fd, BR_RELEASE);

		if (status < 0)
			return 14;
		if (status > 0)
			break;
	}
	if (write(events_fd, "R", 1) != 1)
		return 15;
	close(fd);
	return 0;
}

int main(void)
{
	struct binder_transaction_data transaction;
	struct flat_binder_object object;
	struct sigaction action = { .sa_handler = ignore_alarm };
	uint32_t context_manager = 0;
	int events[2];
	int fd = open_binder();
	pid_t service;
	int service_status;

	if (fd < 0) {
		perror("open or mmap /dev/binder");
		return 1;
	}
	if (ioctl(fd, BINDER_SET_CONTEXT_MGR, &context_manager) < 0) {
		perror("BINDER_SET_CONTEXT_MGR");
		close(fd);
		return 2;
	}
	if (sigaction(SIGALRM, &action, NULL) < 0)
		return 5;
	if (pipe(events) < 0)
		return 3;
	service = fork();
	if (service < 0)
		return 4;
	if (service == 0) {
		close(events[0]);
		_exit(service_process(events[1]));
	}
	close(events[1]);
	alarm(10);
	if (read_registration(fd, &transaction) < 0 ||
	    transaction.code != REGISTER_CODE ||
	    transaction.data_size < sizeof(object)) {
		fprintf(stderr, "TRANSFER_REGISTRATION_MISSING\n");
		kill(service, SIGKILL);
		waitpid(service, &service_status, 0);
		close(fd);
		return 5;
	}
	memcpy(&object, (void *)(uintptr_t)transaction.data_buffer, sizeof(object));
	if (object.type != BINDER_TYPE_HANDLE || object.object.handle == 0) {
		fprintf(stderr, "TRANSFER_HANDLE_INVALID\n");
		kill(service, SIGKILL);
		waitpid(service, &service_status, 0);
		close(fd);
		return 6;
	}
	if (wait_for_event(events[0], 'A') < 0) {
		fprintf(stderr, "TRANSFER_ACQUIRE_MISSING\n");
		kill(service, SIGKILL);
		waitpid(service, &service_status, 0);
		close(fd);
		return 7;
	}
	if (free_buffer(fd, transaction.data_buffer) < 0) {
		perror("BC_FREE_BUFFER");
		kill(service, SIGKILL);
		waitpid(service, &service_status, 0);
		close(fd);
		return 8;
	}
	if (wait_for_event(events[0], 'R') < 0) {
		fprintf(stderr, "TRANSFER_RELEASE_MISSING\n");
		kill(service, SIGKILL);
		waitpid(service, &service_status, 0);
		close(fd);
		return 9;
	}
	waitpid(service, &service_status, 0);
	close(events[0]);
	close(fd);
	if (!WIFEXITED(service_status) || WEXITSTATUS(service_status) != 0) {
		fprintf(stderr, "TRANSFER_SERVICE_STATUS=%#x\n", service_status);
		return 10;
	}
	puts("BINDER_TRANSFER_REFCOUNT=PASS");
	return 0;
}
