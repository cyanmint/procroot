/*
 * SPDX-FileCopyrightText: NONE
 * SPDX-License-Identifier: GPL-2.0-or-later
 * Note: AI-generated contribution; no legal determination implied.
 */
/* Verify dead Binder handles remain reserved until all refs are released. */
#define _GNU_SOURCE
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
#define REGISTER_CODE 0x44484c46
#define REQUEST_CODE 0x44484c52
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

struct binder_handle_cookie {
	uint32_t handle;
	uint64_t cookie;
} __attribute__((packed));

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
#define BC_INCREFS _IOW('c', 4, uint32_t)
#define BC_ACQUIRE _IOW('c', 5, uint32_t)
#define BC_RELEASE _IOW('c', 6, uint32_t)
#define BC_DECREFS _IOW('c', 7, uint32_t)
#define BC_REQUEST_DEATH_NOTIFICATION \
	_IOW('c', 14, struct binder_handle_cookie)
#define BC_DEAD_BINDER_DONE _IOW('c', 16, uint64_t)
#define BR_TRANSACTION _IOR('r', 2, struct binder_transaction_data)
#define BR_REPLY _IOR('r', 3, struct binder_transaction_data)
#define BR_TRANSACTION_COMPLETE _IO('r', 6)
#define BR_DEAD_BINDER _IOR('r', 15, uint64_t)
#define BR_DEAD_REPLY _IO('r', 5)
#define BR_FAILED_REPLY _IO('r', 17)

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

static int send_registration(int fd)
{
	struct flat_binder_object object = {
		.type = BINDER_TYPE_BINDER,
		.flags = 0x7f,
		.object.binder = 0x12345678,
		.cookie = 0x87654321,
	};
	struct binder_transaction_data transaction = {
		.code = REGISTER_CODE,
		.flags = 1,
		.data_size = sizeof(object),
		.offsets_size = sizeof(uint64_t),
		.data_buffer = (uint64_t)(uintptr_t)&object,
	};
	uint64_t offset = 0;
	uint32_t command = (uint32_t)BC_TRANSACTION;
	uint8_t writes[sizeof(command) + sizeof(transaction)];
	struct binder_write_read bwr = {};

	transaction.offsets_buffer = (uint64_t)(uintptr_t)&offset;
	memcpy(writes, &command, sizeof(command));
	memcpy(writes + sizeof(command), &transaction, sizeof(transaction));
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

static int read_object_handle(int fd, uint32_t *handle,
		uint64_t *buffer)
{
	struct binder_transaction_data transaction;
	struct flat_binder_object object;

	if (read_registration(fd, &transaction) < 0 ||
	    transaction.code != REGISTER_CODE ||
	    transaction.data_size < sizeof(object))
		return -1;
	memcpy(&object, (void *)(uintptr_t)transaction.data_buffer,
	       sizeof(object));
	if (object.type != BINDER_TYPE_HANDLE || object.object.handle == 0)
		return -1;
	*handle = object.object.handle;
	*buffer = transaction.data_buffer;
	return 0;
}

static int owner_process(int inherited_fd, int control_fd)
{
	char byte;
	int fd;

	close(inherited_fd);
	fd = open_binder();
	if (fd < 0 || send_registration(fd) < 0)
		return 10;
	if (read(control_fd, &byte, sizeof(byte)) != sizeof(byte))
		return 11;
	close(control_fd);
	close(fd);
	return 0;
}

static int start_owner(int manager_fd, pid_t *pid, int *control_fd,
		uint32_t *handle, uint64_t *buffer)
{
	int control[2];
	pid_t child;

	if (pipe(control) < 0)
		return -1;
	child = fork();
	if (child < 0) {
		close(control[0]);
		close(control[1]);
		return -1;
	}
	if (child == 0) {
		int status;

		close(control[1]);
		status = owner_process(manager_fd, control[0]);
		_exit(status);
	}
	close(control[0]);
	*pid = child;
	*control_fd = control[1];
	if (read_object_handle(manager_fd, handle, buffer) < 0) {
		close(*control_fd);
		(void)kill(child, SIGKILL);
		(void)waitpid(child, NULL, 0);
		return -1;
	}
	return 0;
}

static int stop_owner(pid_t pid, int control_fd)
{
	char byte = 'x';
	int status;

	if (write(control_fd, &byte, sizeof(byte)) != sizeof(byte)) {
		close(control_fd);
		(void)kill(pid, SIGKILL);
		(void)waitpid(pid, NULL, 0);
		return -1;
	}
	close(control_fd);
	if (waitpid(pid, &status, 0) != pid || !WIFEXITED(status) ||
	    WEXITSTATUS(status) != 0)
		return -1;
	return 0;
}

static int send_handle_command(int fd, uint32_t command, uint32_t handle)
{
	uint8_t writes[sizeof(command) + sizeof(handle)];
	struct binder_write_read bwr = {};

	memcpy(writes, &command, sizeof(command));
	memcpy(writes + sizeof(command), &handle, sizeof(handle));
	bwr.write_size = sizeof(writes);
	bwr.write_buffer = (uint64_t)(uintptr_t)writes;
	return ioctl(fd, BINDER_WRITE_READ, &bwr) < 0 ||
		bwr.write_consumed != sizeof(writes) ? -1 : 0;
}

static int send_transaction_error(int fd, uint32_t handle,
		uint32_t expected_error)
{
	struct binder_transaction_data transaction = {
		.target = handle,
		.code = REGISTER_CODE,
		.flags = 0x11,
	};
	uint32_t command = (uint32_t)BC_TRANSACTION;
	uint8_t writes[sizeof(command) + sizeof(transaction)];
	uint32_t reads[2] = {};
	struct binder_write_read bwr = {};
	size_t i;

	memcpy(writes, &command, sizeof(command));
	memcpy(writes + sizeof(command), &transaction, sizeof(transaction));
	bwr.write_size = sizeof(writes);
	bwr.write_buffer = (uint64_t)(uintptr_t)writes;
	bwr.read_size = sizeof(reads);
	bwr.read_buffer = (uint64_t)(uintptr_t)reads;
	if (ioctl(fd, BINDER_WRITE_READ, &bwr) < 0 ||
	    bwr.write_consumed != sizeof(writes) ||
	    bwr.read_consumed == 0 || bwr.read_consumed > sizeof(reads))
		return -1;
	for (i = 0; i < bwr.read_consumed / sizeof(reads[0]); i++) {
		if (reads[i] == expected_error)
			return 0;
		if (reads[i] != (uint32_t)BR_TRANSACTION_COMPLETE)
			return -1;
	}
	return -1;
}

static int free_buffer(int fd, uint64_t buffer);

static int send_context_request(int fd)
{
	struct binder_transaction_data transaction = {
		.code = REQUEST_CODE,
	};
	uint32_t command = (uint32_t)BC_TRANSACTION;
	uint8_t writes[sizeof(command) + sizeof(transaction)];
	struct binder_write_read bwr = {};

	memcpy(writes, &command, sizeof(command));
	memcpy(writes + sizeof(command), &transaction, sizeof(transaction));
	bwr.write_size = sizeof(writes);
	bwr.write_buffer = (uint64_t)(uintptr_t)writes;
	return ioctl(fd, BINDER_WRITE_READ, &bwr) < 0 ||
		bwr.write_consumed != sizeof(writes) ? -1 : 0;
}

static int send_dead_handle_reply(int fd, uint32_t handle)
{
	struct flat_binder_object object = {
		.type = BINDER_TYPE_HANDLE,
		.object.handle = handle,
	};
	uint8_t payload[52] = {};
	uint64_t offset = 20;
	struct binder_transaction_data transaction = {
		.target = UINT64_MAX,
		.code = REQUEST_CODE,
		.data_size = sizeof(payload),
		.offsets_size = sizeof(offset),
		.data_buffer = (uint64_t)(uintptr_t)payload,
		.offsets_buffer = (uint64_t)(uintptr_t)&offset,
	};
	uint32_t command = (uint32_t)BC_REPLY;
	uint8_t writes[sizeof(command) + sizeof(transaction)];
	struct binder_write_read bwr = {};

	memcpy(payload + offset, &object, sizeof(object));
	memcpy(writes, &command, sizeof(command));
	memcpy(writes + sizeof(command), &transaction, sizeof(transaction));
	bwr.write_size = sizeof(writes);
	bwr.write_buffer = (uint64_t)(uintptr_t)writes;
	return ioctl(fd, BINDER_WRITE_READ, &bwr) < 0 ||
		bwr.write_consumed != sizeof(writes) ? -1 : 0;
}

static int read_dead_handle_reply(int fd, uint32_t *handle,
		uint64_t *buffer)
{
	struct pollfd poll_fd = { .fd = fd, .events = POLLIN };

	for (;;) {
		uint8_t reads[sizeof(uint32_t) + sizeof(struct binder_transaction_data)];
		struct binder_write_read bwr = {
			.read_size = sizeof(reads),
			.read_buffer = (uint64_t)(uintptr_t)reads,
		};
		size_t position = 0;

		if (poll(&poll_fd, 1, 5000) != 1 ||
		    (poll_fd.revents & POLLIN) == 0 ||
		    ioctl(fd, BINDER_WRITE_READ, &bwr) < 0)
			return -1;
		while (position + sizeof(uint32_t) <= bwr.read_consumed) {
			struct binder_transaction_data transaction;
			struct flat_binder_object object;
			uint64_t offset;
			uint32_t command;

			memcpy(&command, reads + position, sizeof(command));
			position += sizeof(command);
			if (command == (uint32_t)BR_TRANSACTION_COMPLETE)
				continue;
			if (command != (uint32_t)BR_REPLY ||
			    position + sizeof(transaction) > bwr.read_consumed)
				return -1;
			memcpy(&transaction, reads + position, sizeof(transaction));
			if (transaction.code != REQUEST_CODE ||
			    transaction.data_size != 52 ||
			    transaction.offsets_size != sizeof(offset) ||
			    transaction.data_buffer == 0 ||
			    transaction.offsets_buffer == 0)
				return -1;
			memcpy(&offset,
			       (const void *)(uintptr_t)transaction.offsets_buffer,
			       sizeof(offset));
			if (offset != 20)
				return -1;
			memcpy(&object,
			       (const void *)(uintptr_t)(transaction.data_buffer + offset),
			       sizeof(object));
			if (object.type != BINDER_TYPE_HANDLE ||
			    object.object.handle == 0)
				return -1;
			*handle = object.object.handle;
			*buffer = transaction.data_buffer;
			return 0;
		}
	}
}

static int dead_handle_client(void)
{
	uint32_t handle;
	uint64_t buffer;
	int fd = open_binder();

	if (fd < 0 || send_context_request(fd) < 0 ||
	    read_dead_handle_reply(fd, &handle, &buffer) < 0 ||
	    send_transaction_error(fd, handle, (uint32_t)BR_DEAD_REPLY) < 0 ||
	    free_buffer(fd, buffer) < 0) {
		perror("dead Binder handle transfer client");
		if (fd >= 0)
			close(fd);
		return 1;
	}
	close(fd);
	return 0;
}

static int test_dead_handle_transfer(int manager_fd, uint32_t handle)
{
	struct binder_transaction_data request;
	pid_t client = fork();
	int status;

	if (client < 0)
		return -1;
	if (client == 0) {
		close(manager_fd);
		_exit(dead_handle_client());
	}
	if (read_registration(manager_fd, &request) < 0 ||
	    request.code != REQUEST_CODE ||
	    (request.data_buffer != 0 &&
	     free_buffer(manager_fd, request.data_buffer) < 0))
		goto fail;
	if (send_dead_handle_reply(manager_fd, handle) < 0) {
		perror("BINDER_WRITE_READ dead Binder handle reply");
		goto fail;
	}
	if (waitpid(client, &status, 0) != client || !WIFEXITED(status) ||
	    WEXITSTATUS(status) != 0)
		return -1;
	puts("BINDER_DEAD_HANDLE_TRANSFER=PASS");
	return 0;

fail:
	(void)kill(client, SIGKILL);
	(void)waitpid(client, NULL, 0);
	return -1;
}

static int request_death_notification(int fd, uint32_t handle,
		uint64_t cookie)
{
	uint32_t command = (uint32_t)BC_REQUEST_DEATH_NOTIFICATION;
	struct binder_handle_cookie notification = {
		.handle = handle,
		.cookie = cookie,
	};
	uint8_t writes[sizeof(command) + sizeof(notification)];
	struct binder_write_read bwr = {};

	memcpy(writes, &command, sizeof(command));
	memcpy(writes + sizeof(command), &notification, sizeof(notification));
	bwr.write_size = sizeof(writes);
	bwr.write_buffer = (uint64_t)(uintptr_t)writes;
	return ioctl(fd, BINDER_WRITE_READ, &bwr) < 0 ||
		bwr.write_consumed != sizeof(writes) ? -1 : 0;
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

static int read_death_notification(int fd, uint64_t expected_cookie)
{
	uint8_t reads[sizeof(uint32_t) + sizeof(uint64_t)] = {};
	struct pollfd poll_fd = { .fd = fd, .events = POLLIN };
	struct binder_write_read bwr = {
		.read_size = sizeof(reads),
		.read_buffer = (uint64_t)(uintptr_t)reads,
	};
	uint32_t command;
	uint64_t cookie;

	if (poll(&poll_fd, 1, 5000) != 1 ||
	    (poll_fd.revents & POLLIN) == 0 ||
	    ioctl(fd, BINDER_WRITE_READ, &bwr) < 0 ||
	    bwr.read_consumed != sizeof(reads))
		return -1;
	memcpy(&command, reads, sizeof(command));
	memcpy(&cookie, reads + sizeof(command), sizeof(cookie));
	return command == (uint32_t)BR_DEAD_BINDER &&
		cookie == expected_cookie ? 0 : -1;
}

static int acknowledge_death_notification(int fd, uint64_t cookie)
{
	uint32_t command = (uint32_t)BC_DEAD_BINDER_DONE;
	uint8_t writes[sizeof(command) + sizeof(cookie)];
	struct binder_write_read bwr = {};

	memcpy(writes, &command, sizeof(command));
	memcpy(writes + sizeof(command), &cookie, sizeof(cookie));
	bwr.write_size = sizeof(writes);
	bwr.write_buffer = (uint64_t)(uintptr_t)writes;
	return ioctl(fd, BINDER_WRITE_READ, &bwr) < 0 ||
		bwr.write_consumed != sizeof(writes) ? -1 : 0;
}

int main(void)
{
	struct sigaction action = { .sa_handler = ignore_alarm };
	const uint64_t death_cookie = 0xdeadbeef12345678ULL;
	uint32_t context_manager = 0;
	uint32_t first_handle, second_handle, third_handle;
	uint32_t unwatched_first, unwatched_second, unwatched_third;
	uint64_t first_buffer, second_buffer, third_buffer;
	uint64_t unwatched_first_buffer, unwatched_second_buffer;
	uint64_t unwatched_third_buffer;
	pid_t owner;
	int control_fd;
	int manager_fd = open_binder();

	if (manager_fd < 0) {
		perror("open or mmap /dev/binder");
		return 1;
	}
	if (ioctl(manager_fd, BINDER_SET_CONTEXT_MGR, &context_manager) < 0) {
		perror("BINDER_SET_CONTEXT_MGR");
		close(manager_fd);
		return 2;
	}
	if (sigaction(SIGALRM, &action, NULL) < 0)
		return 3;
	alarm(30);

	if (start_owner(manager_fd, &owner, &control_fd, &first_handle,
			&first_buffer) < 0) {
		fprintf(stderr, "FIRST_OWNER_REGISTRATION=FAIL\n");
		close(manager_fd);
		return 4;
	}
	if (send_handle_command(manager_fd, (uint32_t)BC_INCREFS,
			first_handle) < 0 ||
	    send_handle_command(manager_fd, (uint32_t)BC_ACQUIRE,
			first_handle) < 0 ||
	    request_death_notification(manager_fd, first_handle,
			death_cookie) < 0 ||
	    free_buffer(manager_fd, first_buffer) < 0) {
		fprintf(stderr, "FIRST_OWNER_REFERENCE_SETUP=FAIL\n");
		(void)stop_owner(owner, control_fd);
		close(manager_fd);
		return 5;
	}
	if (stop_owner(owner, control_fd) < 0 ||
	    read_death_notification(manager_fd, death_cookie) < 0 ||
	    acknowledge_death_notification(manager_fd, death_cookie) < 0) {
		fprintf(stderr, "FIRST_OWNER_DEATH_ACK=FAIL\n");
		close(manager_fd);
		return 6;
	}
	if (test_dead_handle_transfer(manager_fd, first_handle) < 0) {
		fprintf(stderr, "BINDER_DEAD_HANDLE_TRANSFER=FAIL\n");
		close(manager_fd);
		return 21;
	}

	if (start_owner(manager_fd, &owner, &control_fd, &second_handle,
			&second_buffer) < 0) {
		fprintf(stderr, "SECOND_OWNER_REGISTRATION=FAIL\n");
		close(manager_fd);
		return 7;
	}
	if (second_handle == first_handle) {
		fprintf(stderr,
			"BINDER_DEAD_HANDLE_REUSED=FAIL old=%u new=%u\n",
			first_handle, second_handle);
		(void)free_buffer(manager_fd, second_buffer);
		(void)stop_owner(owner, control_fd);
		close(manager_fd);
		return 8;
	}
	puts("BINDER_DEAD_HANDLE_NOT_REUSED=PASS");
	if (free_buffer(manager_fd, second_buffer) < 0 ||
	    stop_owner(owner, control_fd) < 0 ||
	    send_handle_command(manager_fd, (uint32_t)BC_RELEASE,
			first_handle) < 0 ||
	    send_handle_command(manager_fd, (uint32_t)BC_DECREFS,
			first_handle) < 0) {
		fprintf(stderr, "DEAD_HANDLE_RELEASE=FAIL\n");
		close(manager_fd);
		return 9;
	}

	if (start_owner(manager_fd, &owner, &control_fd, &third_handle,
			&third_buffer) < 0) {
		fprintf(stderr, "THIRD_OWNER_REGISTRATION=FAIL\n");
		close(manager_fd);
		return 10;
	}
	if (third_handle != first_handle) {
		fprintf(stderr,
			"BINDER_DEAD_HANDLE_NOT_RECLAIMED=FAIL old=%u new=%u\n",
			first_handle, third_handle);
		(void)free_buffer(manager_fd, third_buffer);
		(void)stop_owner(owner, control_fd);
		close(manager_fd);
		return 11;
	}
	puts("BINDER_DEAD_HANDLE_RECLAIMED=PASS");
	if (free_buffer(manager_fd, third_buffer) < 0 ||
	    stop_owner(owner, control_fd) < 0) {
		fprintf(stderr, "THIRD_OWNER_CLEANUP=FAIL\n");
		close(manager_fd);
		return 12;
	}

	if (start_owner(manager_fd, &owner, &control_fd, &unwatched_first,
			&unwatched_first_buffer) < 0) {
		fprintf(stderr, "UNWATCHED_OWNER_REGISTRATION=FAIL\n");
		close(manager_fd);
		return 13;
	}
	if (send_handle_command(manager_fd, (uint32_t)BC_INCREFS,
			unwatched_first) < 0 ||
	    send_handle_command(manager_fd, (uint32_t)BC_ACQUIRE,
			unwatched_first) < 0 ||
	    free_buffer(manager_fd, unwatched_first_buffer) < 0) {
		fprintf(stderr, "UNWATCHED_OWNER_SETUP=FAIL\n");
		(void)stop_owner(owner, control_fd);
		close(manager_fd);
		return 14;
	}
	if (stop_owner(owner, control_fd) < 0) {
		fprintf(stderr, "UNWATCHED_OWNER_EXIT=FAIL\n");
		close(manager_fd);
		return 15;
	}
	if (send_transaction_error(manager_fd, unwatched_first,
			(uint32_t)BR_DEAD_REPLY) < 0) {
		fprintf(stderr, "BINDER_DEAD_HANDLE_TRANSACTION=FAIL\n");
		close(manager_fd);
		return 19;
	}
	puts("BINDER_DEAD_HANDLE_TRANSACTION=PASS");
	if (send_transaction_error(manager_fd, 255,
			(uint32_t)BR_FAILED_REPLY) < 0) {
		fprintf(stderr, "BINDER_INVALID_HANDLE_TRANSACTION=FAIL\n");
		close(manager_fd);
		return 20;
	}
	puts("BINDER_INVALID_HANDLE_TRANSACTION=PASS");
	if (start_owner(manager_fd, &owner, &control_fd, &unwatched_second,
			&unwatched_second_buffer) < 0) {
		fprintf(stderr, "UNWATCHED_SECOND_OWNER=FAIL\n");
		close(manager_fd);
		return 14;
	}
	if (unwatched_second == unwatched_first) {
		fprintf(stderr,
			"BINDER_UNWATCHED_DEAD_HANDLE_REUSED=FAIL old=%u new=%u\n",
			unwatched_first, unwatched_second);
		(void)free_buffer(manager_fd, unwatched_second_buffer);
		(void)stop_owner(owner, control_fd);
		close(manager_fd);
		return 15;
	}
	puts("BINDER_UNWATCHED_DEAD_HANDLE_NOT_REUSED=PASS");
	if (free_buffer(manager_fd, unwatched_second_buffer) < 0 ||
	    stop_owner(owner, control_fd) < 0 ||
	    send_handle_command(manager_fd, (uint32_t)BC_RELEASE,
			unwatched_first) < 0 ||
	    send_handle_command(manager_fd, (uint32_t)BC_DECREFS,
			unwatched_first) < 0 ||
	    start_owner(manager_fd, &owner, &control_fd, &unwatched_third,
			&unwatched_third_buffer) < 0) {
		fprintf(stderr, "UNWATCHED_DEAD_HANDLE_RELEASE=FAIL\n");
		close(manager_fd);
		return 16;
	}
	if (unwatched_third != unwatched_first) {
		fprintf(stderr,
			"BINDER_UNWATCHED_DEAD_HANDLE_NOT_RECLAIMED=FAIL old=%u new=%u\n",
			unwatched_first, unwatched_third);
		(void)free_buffer(manager_fd, unwatched_third_buffer);
		(void)stop_owner(owner, control_fd);
		close(manager_fd);
		return 17;
	}
	if (free_buffer(manager_fd, unwatched_third_buffer) < 0 ||
	    stop_owner(owner, control_fd) < 0) {
		fprintf(stderr, "UNWATCHED_THIRD_OWNER_CLEANUP=FAIL\n");
		close(manager_fd);
		return 18;
	}
	close(manager_fd);
	puts("BINDER_DEAD_HANDLE_LIFETIME=PASS");
	return 0;
}
