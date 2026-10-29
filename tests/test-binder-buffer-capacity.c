/*
 * SPDX-FileCopyrightText: NONE
 * SPDX-License-Identifier: GPL-2.0-or-later
 * Note: AI-generated contribution; no legal determination implied.
 */
/* Verify Binder can track more than 128 simultaneously live buffers. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
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
#define TF_ONE_WAY 0x01u

#define TRANSACTION_COUNT 129
#define TRANSACTION_CODE_BASE 0x6b00u
#define READ_SIZE 4096
#define MAPPING_SIZE 65536
#define TRANSACTION_WIRE_SIZE (sizeof(uint32_t) + sizeof(struct binder_transaction_data))
#define FREE_WIRE_SIZE (sizeof(uint32_t) + sizeof(uint64_t))

static int send_transaction(int fd, unsigned int index)
{
	uint32_t command = (uint32_t)BC_TRANSACTION;
	struct binder_transaction_data transaction = {
		.target = 0,
		.code = TRANSACTION_CODE_BASE + index,
		.flags = TF_ONE_WAY,
	};
	uint8_t writes[TRANSACTION_WIRE_SIZE];
	struct binder_write_read bwr = {
		.write_size = sizeof(writes),
		.write_buffer = (uint64_t)(uintptr_t)writes,
	};

	memcpy(writes, &command, sizeof(command));
	memcpy(writes + sizeof(command), &transaction, sizeof(transaction));
	if (ioctl(fd, BINDER_WRITE_READ, &bwr) < 0) {
		fprintf(stderr, "submit ioctl failed: errno=%d\n", errno);
		return -1;
	}
	return bwr.write_consumed == sizeof(writes) ? 0 : -1;
}

static int receive_transaction(int fd, unsigned int index, uint64_t *buffer)
{
	unsigned int attempt;

	for (attempt = 0; attempt < 8; attempt++) {
		uint8_t reads[READ_SIZE] = {};
		struct binder_write_read bwr = {
			.read_size = sizeof(reads),
			.read_buffer = (uint64_t)(uintptr_t)reads,
		};
		size_t offset = 0;

		if (ioctl(fd, BINDER_WRITE_READ, &bwr) < 0) {
			fprintf(stderr,
				"receive ioctl failed after %u transactions: errno=%d\n",
				index, errno);
			return -1;
		}
		if (bwr.read_consumed > sizeof(reads)) {
			fprintf(stderr, "read overflow: consumed=%llu\n",
				(unsigned long long)bwr.read_consumed);
			return -1;
		}
		while (offset < bwr.read_consumed) {
			uint32_t command;
			struct binder_transaction_data transaction;

			if (bwr.read_consumed - offset < sizeof(command))
				return -1;
			memcpy(&command, reads + offset, sizeof(command));
			offset += sizeof(command);
			if (command == BR_TRANSACTION_COMPLETE)
				continue;
			if (command != BR_TRANSACTION ||
			    bwr.read_consumed - offset < sizeof(transaction))
				return -1;
			memcpy(&transaction, reads + offset, sizeof(transaction));
			offset += sizeof(transaction);
			if (transaction.code != TRANSACTION_CODE_BASE + index ||
			    transaction.data_size != 0 ||
			    transaction.data_buffer == 0) {
				fprintf(stderr,
					"invalid transaction code=%#x size=%llu buffer=%#llx\n",
					transaction.code,
					(unsigned long long)transaction.data_size,
					(unsigned long long)transaction.data_buffer);
				return -1;
			}
			*buffer = transaction.data_buffer;
			return 0;
		}
	}
	fprintf(stderr, "transaction %u was not delivered\n", index);
	return -1;
}

static int free_transactions(int fd, const uint64_t *buffers)
{
	uint8_t writes[TRANSACTION_COUNT * FREE_WIRE_SIZE];
	struct binder_write_read bwr = {};
	uint32_t command = (uint32_t)BC_FREE_BUFFER;
	unsigned int i;

	for (i = 0; i < TRANSACTION_COUNT; i++) {
		size_t offset = i * FREE_WIRE_SIZE;

		if (buffers[i] == 0) {
			fprintf(stderr, "missing buffer index=%u\n", i);
			return -1;
		}
		memcpy(writes + offset, &command, sizeof(command));
		memcpy(writes + offset + sizeof(command), &buffers[i],
		       sizeof(buffers[i]));
	}
	bwr.write_size = sizeof(writes);
	bwr.write_buffer = (uint64_t)(uintptr_t)writes;
	if (ioctl(fd, BINDER_WRITE_READ, &bwr) < 0) {
		fprintf(stderr, "free ioctl failed: errno=%d\n", errno);
		return -1;
	}
	return bwr.write_consumed == sizeof(writes) ? 0 : -1;
}

int main(void)
{
	int fd = open("/dev/binder", O_RDWR | O_CLOEXEC);
	uint32_t context_manager = 0;
	uint64_t buffers[TRANSACTION_COUNT] = {};
	void *mapping;

	unsigned int i;

	if (fd < 0) {
		perror("open /dev/binder");
		return 1;
	}
	mapping = mmap(NULL, MAPPING_SIZE, PROT_READ, MAP_PRIVATE, fd, 0);
	if (mapping == MAP_FAILED) {
		perror("mmap /dev/binder");
		close(fd);
		return 2;
	}
	if (ioctl(fd, BINDER_SET_CONTEXT_MGR, &context_manager) < 0) {
		perror("BINDER_SET_CONTEXT_MGR");
		munmap(mapping, MAPPING_SIZE);
		close(fd);
		return 3;
	}
	for (i = 0; i < TRANSACTION_COUNT; i++) {
		if (send_transaction(fd, i) < 0 ||
		    receive_transaction(fd, i, &buffers[i]) < 0) {
			fprintf(stderr,
				"BINDER_BUFFER_CAPACITY=FAIL iteration=%u errno=%d\n",
				i, errno);
			munmap(mapping, MAPPING_SIZE);
			close(fd);
			return 4;
		}
	}
	if (free_transactions(fd, buffers) < 0) {
		fprintf(stderr, "BINDER_BUFFER_CAPACITY=FAIL freeing\n");
		munmap(mapping, MAPPING_SIZE);
		close(fd);
		return 5;
	}
	munmap(mapping, MAPPING_SIZE);
	close(fd);
	puts("BINDER_BUFFER_CAPACITY=PASS count=129");
	return 0;
}
