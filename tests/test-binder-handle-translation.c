/*
 * SPDX-FileCopyrightText: NONE
 * SPDX-License-Identifier: GPL-2.0-or-later
 * Note: AI-generated contribution; no legal determination implied.
 */
/* Verify transferred Binder handles are mapped for the receiving process. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#ifndef BINDER_DEVICE_PATH
#define BINDER_DEVICE_PATH "/dev/binder"
#endif
#define MAPPING_SIZE 65536
#define REGISTER_CODE 0x48414e44
#define GET_HANDLE_CODE 0x48414e45
#define PING_CODE 0x48414e46
#define PONG_CODE 0x48414e47
#define ROUNDTRIP_CODE 0x48414e48
#define OBJECT_COUNT 24
#define REGISTRATION_DATA_SIZE 128
#define OBJECT_OFFSET 104
#define TF_ONE_WAY 0x01
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
#define BC_INCREFS _IOW('c', 4, uint32_t)
#define BC_ACQUIRE _IOW('c', 5, uint32_t)
#define BC_RELEASE _IOW('c', 6, uint32_t)
#define BC_DECREFS _IOW('c', 7, uint32_t)
#define BC_INCREFS_DONE _IOW('c', 8, struct binder_ptr_cookie)
#define BC_ACQUIRE_DONE _IOW('c', 9, struct binder_ptr_cookie)
#define BR_INCREFS _IOR('r', 7, struct binder_ptr_cookie)
#define BR_ACQUIRE _IOR('r', 8, struct binder_ptr_cookie)
#define BR_RELEASE _IOR('r', 9, struct binder_ptr_cookie)
#define BR_DECREFS _IOR('r', 10, struct binder_ptr_cookie)
#define BR_TRANSACTION _IOR('r', 2, struct binder_transaction_data)
#define BR_REPLY _IOR('r', 3, struct binder_transaction_data)
#define BR_TRANSACTION_COMPLETE _IO('r', 6)

static int inherited_manager_fd = -1;

static void ignore_alarm(int signal_number)
{
	(void)signal_number;
}

static int open_binder(void)
{
	int fd = open(BINDER_DEVICE_PATH, O_RDWR | O_CLOEXEC);
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

static int send_transaction(int fd, uint32_t command,
		struct binder_transaction_data *transaction)
{
	uint8_t writes[sizeof(uint32_t) + sizeof(*transaction)];
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

static int read_transaction(int fd, uint32_t expected_command,
		struct binder_transaction_data *transaction)
{
	for (;;) {
		uint8_t reads[sizeof(uint32_t) + sizeof(*transaction) + 64] = {};
		struct pollfd poll_fd = { .fd = fd, .events = POLLIN };
		struct binder_write_read bwr = {};
		size_t position = 0;
		int poll_result = poll(&poll_fd, 1, 5000);

		if (poll_result <= 0) {
			fprintf(stderr,
				"READ_TRANSACTION_POLL=FAIL expected=%#x result=%d revents=%#x errno=%d\n",
				expected_command, poll_result, poll_fd.revents, errno);
			return -1;
		}
		bwr.read_size = sizeof(reads);
		bwr.read_buffer = (uint64_t)(uintptr_t)reads;
		if (ioctl(fd, BINDER_WRITE_READ, &bwr) < 0) {
			fprintf(stderr,
				"READ_TRANSACTION_IOCTL=FAIL expected=%#x errno=%d\n",
				expected_command, errno);
			return -1;
		}
		while (position + sizeof(uint32_t) <= bwr.read_consumed) {
			uint32_t command;

			memcpy(&command, reads + position, sizeof(command));
			position += sizeof(command);
			if (command == BR_TRANSACTION_COMPLETE)
				continue;
			if (command != expected_command ||
			    position + sizeof(*transaction) > bwr.read_consumed) {
				fprintf(stderr,
					"READ_TRANSACTION_COMMAND=FAIL expected=%#x command=%#x consumed=%llu position=%llu\n",
					expected_command, command,
					(unsigned long long)bwr.read_consumed,
					(unsigned long long)position);
				return -1;
			}
			memcpy(transaction, reads + position, sizeof(*transaction));
			return 0;
		}
		if (bwr.read_consumed == 0)
			return -1;
	}
}

static int send_reference_command(int fd, uint32_t command, uint32_t handle)
{
	uint32_t writes[] = { command, handle };
	struct binder_write_read bwr = {
		.write_size = sizeof(writes),
		.write_buffer = (uint64_t)(uintptr_t)writes,
	};

	return ioctl(fd, BINDER_WRITE_READ, &bwr) < 0 ||
		bwr.write_consumed != sizeof(writes) ? -1 : 0;
}

static int send_reference_done(int fd, uint32_t command,
		uint64_t pointer, uint64_t cookie)
{
	struct binder_ptr_cookie pair = { pointer, cookie };
	uint8_t writes[sizeof(uint32_t) + sizeof(pair)];
	struct binder_write_read bwr = {};

	memcpy(writes, &command, sizeof(command));
	memcpy(writes + sizeof(command), &pair, sizeof(pair));
	bwr.write_size = sizeof(writes);
	bwr.write_buffer = (uint64_t)(uintptr_t)writes;
	return ioctl(fd, BINDER_WRITE_READ, &bwr) < 0 ||
		bwr.write_consumed != sizeof(writes) ? -1 : 0;
}

static bool has_local_object(const struct flat_binder_object *objects,
		uint64_t binder, uint64_t cookie)
{
	unsigned int i;

	for (i = 0; i < OBJECT_COUNT; i++) {
		if (objects[i].object.binder == binder &&
		    objects[i].cookie == cookie)
			return true;
	}
	return false;
}

static bool has_local_binder(const struct flat_binder_object *objects,
		uint64_t binder)
{
	unsigned int i;

	for (i = 0; i < OBJECT_COUNT; i++) {
		if (objects[i].object.binder == binder)
			return true;
	}
	return false;
}

static int read_service_work(int fd,
		struct binder_transaction_data *transaction,
		unsigned int *reference_mask,
		const struct flat_binder_object *objects,
		uint32_t expected_command)
{
	for (;;) {
		uint8_t reads[sizeof(uint32_t) + sizeof(*transaction) + 64] = {};
		struct pollfd poll_fd = { .fd = fd, .events = POLLIN };
		struct binder_write_read bwr = {
			.read_size = sizeof(reads),
			.read_buffer = (uint64_t)(uintptr_t)reads,
		};
		size_t position = 0;
		int poll_result = poll(&poll_fd, 1, 250);

		if (poll_result <= 0)
			return poll_result;
		if (ioctl(fd, BINDER_WRITE_READ, &bwr) < 0)
			return -1;
		while (position + sizeof(uint32_t) <= bwr.read_consumed) {
			struct binder_ptr_cookie pair;
			uint32_t command;

			memcpy(&command, reads + position, sizeof(command));
			position += sizeof(command);
			if (command == BR_TRANSACTION_COMPLETE)
				continue;
			if (command == BR_INCREFS || command == BR_ACQUIRE ||
			    command == BR_RELEASE || command == BR_DECREFS) {
				uint32_t done_command = 0;
				unsigned int bit;

				if (position + sizeof(pair) > bwr.read_consumed)
					return -1;
				memcpy(&pair, reads + position, sizeof(pair));
				position += sizeof(pair);
				if (!has_local_object(objects, pair.ptr, pair.cookie))
					return -1;
				if (command == BR_INCREFS) {
					bit = 1U;
					done_command = (uint32_t)BC_INCREFS_DONE;
				} else if (command == BR_ACQUIRE) {
					bit = 2U;
					done_command = (uint32_t)BC_ACQUIRE_DONE;
				} else if (command == BR_RELEASE) {
					bit = 4U;
				} else {
					bit = 8U;
				}
				*reference_mask |= bit;
				if (done_command != 0 && send_reference_done(fd,
						done_command, pair.ptr, pair.cookie) < 0)
					return -1;
				continue;
			}
			if (command != expected_command ||
			    position + sizeof(*transaction) > bwr.read_consumed)
				return -1;
			memcpy(transaction, reads + position, sizeof(*transaction));
			return 1;
		}
	}
}

static int free_buffer(int fd, uint64_t buffer);

struct registration_context {
	int fd;
	const struct flat_binder_object *objects;
	unsigned int *reference_mask;
};

static int register_callback_objects(struct registration_context *context)
{
	uint8_t payload[REGISTRATION_DATA_SIZE] = {};
	uint64_t offset = OBJECT_OFFSET;

	for (unsigned int i = 0; i < OBJECT_COUNT; i++) {
		struct binder_transaction_data registration;
		struct binder_transaction_data reply;
		int work;

		memset(payload, 0, sizeof(payload));
		memcpy(payload + OBJECT_OFFSET, &context->objects[i],
			sizeof(context->objects[i]));
		registration = (struct binder_transaction_data) {
			.code = REGISTER_CODE,
			.flags = 0x10,
			.data_size = sizeof(payload),
			.offsets_size = sizeof(offset),
			.data_buffer = (uint64_t)(uintptr_t)payload,
			.offsets_buffer = (uint64_t)(uintptr_t)&offset,
		};
		if (send_transaction(context->fd, BC_TRANSACTION,
				    &registration) < 0) {
			fprintf(stderr,
				"SERVICE_REGISTER_SEND=FAIL index=%u errno=%d\n",
				i, errno);
			return 11;
		}
		do {
			work = read_service_work(context->fd, &reply,
					context->reference_mask,
					context->objects, BR_REPLY);
		} while (work == 0);
		if (work < 0) {
			fprintf(stderr,
				"SERVICE_REGISTER_REPLY=FAIL index=%u errno=%d\n",
				i, errno);
			return 11;
		}
		free_buffer(context->fd, reply.data_buffer);
	}
	return 0;
}

static void *registration_thread(void *argument)
{
	struct registration_context *context = argument;

	return (void *)(intptr_t)register_callback_objects(context);
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

static int send_ping_reply(int fd)
{
	uint32_t pong = PONG_CODE;
	struct binder_transaction_data reply = {
		.data_size = sizeof(pong),
		.data_buffer = (uint64_t)(uintptr_t)&pong,
	};

	return send_transaction(fd, BC_REPLY, &reply);
}

static int service_process(void)
{
	struct binder_transaction_data transaction;
	struct timespec start;
	struct flat_binder_object objects[OBJECT_COUNT];
	struct registration_context registration;
	pthread_t registrar;
	void *registration_result;
	unsigned int reference_mask = 0;
	unsigned int ping_count = 0;
	bool roundtrip_received = false;
	int fd;

	close(inherited_manager_fd);
	fd = open_binder();
	if (fd < 0)
		return 10;
	for (unsigned int i = 0; i < OBJECT_COUNT; i++) {
		objects[i] = (struct flat_binder_object) {
			.type = BINDER_TYPE_BINDER,
			.flags = 0x7f,
			.object.binder = 0x12345678U + i,
			.cookie = 0x87654321U + i,
		};
	}
	registration = (struct registration_context) {
		.fd = fd,
		.objects = objects,
		.reference_mask = &reference_mask,
	};
	int thread_error = pthread_create(&registrar, NULL,
					  registration_thread, &registration);
	if (thread_error != 0) {
		fprintf(stderr, "SERVICE_REGISTER_THREAD=FAIL error=%d\n",
			thread_error);
		return 11;
	}
	thread_error = pthread_join(registrar, &registration_result);
	if (thread_error != 0 || (intptr_t)registration_result != 0) {
		fprintf(stderr, "SERVICE_REGISTER_THREAD_JOIN=FAIL error=%d\n",
			thread_error);
		return 11;
	}
	if (clock_gettime(CLOCK_MONOTONIC, &start) < 0)
		return 12;
	alarm(30);
	while (!roundtrip_received || ping_count < OBJECT_COUNT ||
	       reference_mask != 0xfU) {
		int work = read_service_work(fd, &transaction, &reference_mask,
				objects, BR_TRANSACTION);
		struct timespec now;

		if (work < 0) {
			fprintf(stderr, "SERVICE_READ_FAIL errno=%d refs=%x\n",
				errno, reference_mask);
			return 12;
		}
		if (work == 0) {
			if (clock_gettime(CLOCK_MONOTONIC, &now) < 0 ||
			    now.tv_sec - start.tv_sec >= 30) {
				fprintf(stderr, "SERVICE_TIMEOUT refs=%x ping=%u\n",
					reference_mask, ping_count);
				return 12;
			}
			continue;
		}
		if (transaction.code == ROUNDTRIP_CODE) {
			struct flat_binder_object returned;

			if (transaction.data_size < sizeof(returned)) {
				fprintf(stderr, "SERVICE_ROUNDTRIP_SIZE=%llu\n",
					(unsigned long long)transaction.data_size);
				return 12;
			}
			memcpy(&returned,
				(void *)(uintptr_t)transaction.data_buffer,
				sizeof(returned));
			if (returned.type != BINDER_TYPE_BINDER ||
			    returned.object.binder != objects[0].object.binder ||
			    returned.cookie != objects[0].cookie) {
				fprintf(stderr,
					"SERVICE_ROUNDTRIP_OBJECT=FAIL type=%#x binder=%#llx cookie=%#llx\n",
					returned.type,
					(unsigned long long)returned.object.binder,
					(unsigned long long)returned.cookie);
				return 12;
			}
			fprintf(stderr, "SERVICE_ROUNDTRIP_OBJECT=PASS\n");
		}
		else if (transaction.code != PING_CODE) {
			fprintf(stderr, "SERVICE_UNEXPECTED_CODE=%#x\n",
				transaction.code);
			return 12;
		}
		if (transaction.code == PING_CODE &&
		    !has_local_binder(objects, transaction.target)) {
			fprintf(stderr, "SERVICE_UNEXPECTED_TARGET=%#llx\n",
				(unsigned long long)transaction.target);
			return 12;
		}
		free_buffer(fd, transaction.data_buffer);
		if (send_ping_reply(fd) < 0)
			return 13;
		if (transaction.code == ROUNDTRIP_CODE)
			roundtrip_received = true;
		else
			ping_count++;
	}
	close(fd);
	return 0;
}

static int client_process(int start_fd)
{
	struct binder_transaction_data transaction = {};
	struct binder_transaction_data reply;
	struct flat_binder_object object;
	uint32_t pong;
	char token;
	int fd;

	close(inherited_manager_fd);
	if (read(start_fd, &token, sizeof(token)) != sizeof(token))
		return 20;
	fd = open_binder();
	if (fd < 0)
		return 21;
	transaction.code = GET_HANDLE_CODE;
	if (send_transaction(fd, BC_TRANSACTION, &transaction) < 0)
		return 22;
	alarm(8);
	if (read_transaction(fd, BR_REPLY, &reply) < 0) {
		fprintf(stderr, "CLIENT_GET_REPLY_READ_FAIL errno=%d\n", errno);
		return 23;
	}
	if (reply.data_size < sizeof(object)) {
		fprintf(stderr, "CLIENT_GET_REPLY_SIZE=%llu\n",
			(unsigned long long)reply.data_size);
		return 23;
	}
	memcpy(&object, (void *)(uintptr_t)reply.data_buffer, sizeof(object));
	fprintf(stderr, "CLIENT_RECEIVED_HANDLE=%u\n", object.object.handle);
	if (object.type != BINDER_TYPE_HANDLE || object.object.handle == 0) {
		free_buffer(fd, reply.data_buffer);
		return 24;
	}
	free_buffer(fd, reply.data_buffer);
	if (send_reference_command(fd, (uint32_t)BC_INCREFS,
			object.object.handle) < 0 ||
	    send_reference_command(fd, (uint32_t)BC_ACQUIRE,
			object.object.handle) < 0)
		return 28;
	{
		struct flat_binder_object returned = {
			.type = BINDER_TYPE_HANDLE,
			.flags = 0x7f,
			.object.handle = object.object.handle,
		};
		uint64_t offset = 0;

		transaction = (struct binder_transaction_data) {
			.target = object.object.handle,
			.code = ROUNDTRIP_CODE,
			.data_size = sizeof(returned),
			.offsets_size = sizeof(offset),
			.data_buffer = (uint64_t)(uintptr_t)&returned,
			.offsets_buffer = (uint64_t)(uintptr_t)&offset,
		};
		if (send_transaction(fd, BC_TRANSACTION, &transaction) < 0 ||
		    read_transaction(fd, BR_REPLY, &reply) < 0 ||
		    reply.data_size != sizeof(pong)) {
			fprintf(stderr, "CLIENT_ROUNDTRIP_REPLY_FAIL errno=%d\n",
				errno);
			return 30;
		}
		memcpy(&pong, (void *)(uintptr_t)reply.data_buffer, sizeof(pong));
		free_buffer(fd, reply.data_buffer);
		if (pong != PONG_CODE)
			return 31;
	}
	transaction = (struct binder_transaction_data) {
		.target = object.object.handle,
		.code = PING_CODE,
	};
	if (send_transaction(fd, BC_TRANSACTION, &transaction) < 0)
		return 25;
	if (read_transaction(fd, BR_REPLY, &reply) < 0) {
		fprintf(stderr, "CLIENT_PING_REPLY_READ_FAIL errno=%d\n", errno);
		return 26;
	}
	if (reply.data_size != sizeof(pong)) {
		fprintf(stderr, "CLIENT_PING_REPLY_SIZE=%llu\n",
			(unsigned long long)reply.data_size);
		return 26;
	}
	memcpy(&pong, (void *)(uintptr_t)reply.data_buffer, sizeof(pong));
	free_buffer(fd, reply.data_buffer);
	if (send_reference_command(fd, (uint32_t)BC_RELEASE,
			object.object.handle) < 0 ||
	    send_reference_command(fd, (uint32_t)BC_DECREFS,
			object.object.handle) < 0)
		return 29;
	close(fd);
	return pong == PONG_CODE ? 0 : 27;
}

static int reply_with_handle(int fd, const struct flat_binder_object *object)
{
	uint64_t offset = 0;
	struct binder_transaction_data reply = {
		.data_size = sizeof(*object),
		.offsets_size = sizeof(offset),
		.data_buffer = (uint64_t)(uintptr_t)object,
		.offsets_buffer = (uint64_t)(uintptr_t)&offset,
	};

	return send_transaction(fd, BC_REPLY, &reply);
}

int main(void)
{
	struct binder_transaction_data transaction;
	struct flat_binder_object object;
	uint32_t handles[OBJECT_COUNT];
	struct sigaction action = { .sa_handler = ignore_alarm };
	uint32_t context_manager = 0;
	int start[2];
	pid_t service;
	pid_t client;
	int service_status;
	int client_status;
	uint32_t pong;
	char token = 's';
	int fd = open_binder();

	if (fd < 0) {
		perror("open or mmap /dev/binder");
		return 1;
	}
	if (ioctl(fd, BINDER_SET_CONTEXT_MGR, &context_manager) < 0) {
		perror("BINDER_SET_CONTEXT_MGR");
		return 2;
	}
	inherited_manager_fd = fd;
	if (sigaction(SIGALRM, &action, NULL) < 0)
		return 5;
	service = fork();
	if (service < 0)
		return 4;
	if (service == 0)
		_exit(service_process());
	alarm(30);
	for (unsigned int i = 0; i < OBJECT_COUNT; i++) {
		struct flat_binder_object received;

		if (read_transaction(fd, BR_TRANSACTION, &transaction) < 0) {
			fprintf(stderr,
				"MANAGER_REGISTRATION_READ=FAIL index=%u errno=%d\n",
				i, errno);
			return 6;
		}
		if (transaction.code != REGISTER_CODE ||
		    transaction.data_size != REGISTRATION_DATA_SIZE ||
		    transaction.offsets_size != sizeof(uint64_t)) {
			fprintf(stderr,
				"MANAGER_REGISTRATION_SHAPE=FAIL index=%u code=%#x data=%llu offsets=%llu\n",
				i, transaction.code,
				(unsigned long long)transaction.data_size,
				(unsigned long long)transaction.offsets_size);
			return 6;
		}
		memcpy(&received, (void *)(uintptr_t)(transaction.data_buffer +
			OBJECT_OFFSET), sizeof(received));
		if (received.type != BINDER_TYPE_HANDLE ||
		    received.object.handle == 0) {
			fprintf(stderr,
				"MANAGER_CALLBACK_HANDLE=FAIL index=%u type=%#x handle=%u\n",
				i, received.type, received.object.handle);
			return 7;
		}
		handles[i] = received.object.handle;
		if (i == 0)
			object = received;
		free_buffer(fd, transaction.data_buffer);
		{
			uint32_t status = 0;
			struct binder_transaction_data reply = {
				.data_size = sizeof(status),
				.data_buffer = (uint64_t)(uintptr_t)&status,
			};

			if (send_transaction(fd, BC_REPLY, &reply) < 0) {
				fprintf(stderr,
					"MANAGER_REGISTRATION_REPLY=FAIL index=%u errno=%d\n",
					i, errno);
				return 6;
			}
		}
	}
	for (unsigned int i = 0; i < OBJECT_COUNT; i++) {
		transaction = (struct binder_transaction_data) {
			.target = handles[i],
			.code = PING_CODE,
		};
		if (send_transaction(fd, BC_TRANSACTION, &transaction) < 0 ||
		    read_transaction(fd, BR_REPLY, &transaction) < 0 ||
		    transaction.data_size != sizeof(pong)) {
			fprintf(stderr,
				"MANAGER_CALLBACK_ROUNDTRIP=FAIL index=%u handle=%u errno=%d\n",
				i, handles[i], errno);
			return 13;
		}
		memcpy(&pong, (void *)(uintptr_t)transaction.data_buffer,
			sizeof(pong));
		free_buffer(fd, transaction.data_buffer);
		if (pong != PONG_CODE) {
			fprintf(stderr,
				"MANAGER_CALLBACK_VALUE=FAIL index=%u value=%#x\n",
				i, pong);
			return 13;
		}
	}
	fprintf(stderr, "MANAGER_CALLBACK_ROUNDTRIP=PASS count=%u\n",
		OBJECT_COUNT);
	if (pipe(start) < 0)
		return 3;
	client = fork();
	if (client < 0)
		return 8;
	if (client == 0)
		_exit(client_process(start[0]));
	close(start[0]);
	if (write(start[1], &token, sizeof(token)) != sizeof(token))
		return 9;
	if (read_transaction(fd, BR_TRANSACTION, &transaction) < 0 ||
	    transaction.code != GET_HANDLE_CODE)
		return 10;
	free_buffer(fd, transaction.data_buffer);
	if (reply_with_handle(fd, &object) < 0)
		return 11;
	alarm(0);
	waitpid(client, &client_status, 0);
	waitpid(service, &service_status, 0);
	close(start[1]);
	close(fd);
	if (!WIFEXITED(client_status) || WEXITSTATUS(client_status) != 0 ||
	    !WIFEXITED(service_status) || WEXITSTATUS(service_status) != 0) {
		fprintf(stderr, "client_status=%#x service_status=%#x\n",
			client_status, service_status);
		fprintf(stderr, "BINDER_HANDLE_TRANSLATION=FAIL\n");
		return 12;
	}
	puts("BINDER_HANDLE_TRANSLATION=PASS");
	return 0;
}
