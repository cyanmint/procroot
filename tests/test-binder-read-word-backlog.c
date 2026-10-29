/*
 * SPDX-FileCopyrightText: NONE
 * SPDX-License-Identifier: GPL-2.0-or-later
 * Note: AI-generated contribution; no legal determination implied.
 */
/* Verify pending Binder completion words do not deadlock new transactions. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
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
#define BC_FREE_BUFFER _IOW('c', 3, uint64_t)
#define BR_TRANSACTION _IOR('r', 2, struct binder_transaction_data)
#define BR_TRANSACTION_COMPLETE _IO('r', 6)
#define BINDER_TF_ONE_WAY 0x01
#define ITERATION_COUNT 300
#define READ_SIZE 256

static int free_binder_buffer(int fd, uint64_t address)
{
	uint32_t command = (uint32_t)BC_FREE_BUFFER;
	uint8_t writes[sizeof(command) + sizeof(address)];
	struct binder_write_read bwr;

	memcpy(writes, &command, sizeof(command));
	memcpy(writes + sizeof(command), &address, sizeof(address));
	bwr = (struct binder_write_read) {
		.write_size = sizeof(writes),
		.write_buffer = (uint64_t)(uintptr_t)writes,
	};
	if (ioctl(fd, BINDER_WRITE_READ, &bwr) < 0)
		return -1;
	return bwr.write_consumed == sizeof(writes) ? 0 : -1;
}

static int read_response(int fd, uint32_t code,
		unsigned int *completion_count)
{
	uint32_t command = (uint32_t)BC_TRANSACTION;
	struct binder_transaction_data transaction = {
		.target = 0,
		.code = code,
		.flags = BINDER_TF_ONE_WAY,
	};
	uint8_t writes[sizeof(command) + sizeof(transaction)];
	unsigned int attempt;

	memcpy(writes, &command, sizeof(command));
	memcpy(writes + sizeof(command), &transaction, sizeof(transaction));
	for (attempt = 0; attempt < 16; attempt++) {
		struct binder_write_read bwr;
		uint8_t reads[READ_SIZE] = {};
		size_t offset = 0;
		uint64_t buffer = 0;
		bool received_transaction = false;

		bwr = (struct binder_write_read) {
			.write_size = sizeof(writes),
			.write_buffer = (uint64_t)(uintptr_t)writes,
			.read_size = sizeof(reads),
			.read_buffer = (uint64_t)(uintptr_t)reads,
		};
		if (ioctl(fd, BINDER_WRITE_READ, &bwr) < 0)
			return -errno;
		if (bwr.read_consumed > sizeof(reads) ||
		    (bwr.write_consumed != 0 &&
		     bwr.write_consumed != sizeof(writes)))
			return -1;
		while (offset < bwr.read_consumed) {
			uint32_t response_command;

			if (bwr.read_consumed - offset < sizeof(response_command))
				return -2;
			memcpy(&response_command, reads + offset,
			       sizeof(response_command));
			offset += sizeof(response_command);
			if (response_command == BR_TRANSACTION_COMPLETE) {
				(*completion_count)++;
				continue;
			}
			if (response_command == BR_TRANSACTION &&
			    !received_transaction &&
			    bwr.read_consumed - offset >= sizeof(transaction)) {
				memcpy(&transaction, reads + offset,
				       sizeof(transaction));
				if (transaction.code != code)
					return -3;
				buffer = transaction.data_buffer;
				received_transaction = true;
				offset = bwr.read_consumed;
				continue;
			}
			fprintf(stderr,
				"unexpected Binder read word=%#x offset=%zu consumed=%llu got_transaction=%d\n",
				response_command, offset,
				(unsigned long long)bwr.read_consumed,
				received_transaction);
			return -4;
		}
		if (bwr.write_consumed == sizeof(writes)) {
			if (!received_transaction)
				return -5;
			return buffer == 0 ? 0 : free_binder_buffer(fd, buffer);
		}
		if (bwr.read_consumed == 0)
			return -6;
	}
	return -7;
}

static int drain_completions(int fd, unsigned int *completion_count)
{
	unsigned int attempt;

	if (*completion_count >= ITERATION_COUNT)
		return *completion_count == ITERATION_COUNT ? 0 : -5;
	for (attempt = 0; attempt < 16; attempt++) {
		struct binder_write_read bwr;
		uint8_t reads[READ_SIZE] = {};
		size_t offset = 0;

		bwr = (struct binder_write_read) {
			.read_size = sizeof(reads),
			.read_buffer = (uint64_t)(uintptr_t)reads,
		};
		if (ioctl(fd, BINDER_WRITE_READ, &bwr) < 0)
			return -1;
		while (offset < bwr.read_consumed) {
			uint32_t command;

			if (bwr.read_consumed - offset < sizeof(command))
				return -2;
			memcpy(&command, reads + offset, sizeof(command));
			if (command != BR_TRANSACTION_COMPLETE)
				return -3;
			(*completion_count)++;
			offset += sizeof(command);
		}
		if (*completion_count == ITERATION_COUNT)
			return 0;
		if (bwr.read_consumed == 0)
			return -5;
	}
	return -4;
}

int main(void)
{
	int fd = open("/dev/binder", O_RDWR | O_CLOEXEC);
	uint32_t context_manager = 0;
	unsigned int completion_count = 0;
	unsigned int i;

	if (fd < 0) {
		perror("open /dev/binder");
		return 1;
	}
	if (ioctl(fd, BINDER_SET_CONTEXT_MGR, &context_manager) < 0) {
		perror("BINDER_SET_CONTEXT_MGR");
		close(fd);
		return 2;
	}

	for (i = 0; i < ITERATION_COUNT; i++) {
		int status = read_response(fd, 0x7000u + i,
			&completion_count);

		if (status < 0) {
			fprintf(stderr,
				"BINDER_READ_WORD_BACKLOG=FAIL iteration=%u status=%d errno=%d\n",
				i, status, errno);
			close(fd);
			return 5;
		}
	}
	if (drain_completions(fd, &completion_count) < 0 ||
	    completion_count != ITERATION_COUNT) {
		fprintf(stderr,
			"BINDER_READ_WORD_BACKLOG=FAIL completions=%u expected=%u\n",
			completion_count, ITERATION_COUNT);
		close(fd);
		return 6;
	}

	close(fd);
	puts("BINDER_READ_WORD_BACKLOG=PASS");
	return 0;
}
