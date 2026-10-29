/*
 * SPDX-FileCopyrightText: NONE
 * SPDX-License-Identifier: GPL-2.0-or-later
 * Note: AI-generated contribution; no legal determination implied.
 */
/* Verify Binder reference-count commands through the userspace broker. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <unistd.h>

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
#define BC_INCREFS _IOW('c', 4, uint32_t)
#define BC_ACQUIRE _IOW('c', 5, uint32_t)
#define BC_RELEASE _IOW('c', 6, uint32_t)
#define BC_DECREFS _IOW('c', 7, uint32_t)

int main(void)
{
	struct binder_write_read bwr = {};
	uint32_t context_manager = 0;
	uint32_t writes[] = {
		(uint32_t) BC_INCREFS, 0,
		(uint32_t) BC_ACQUIRE, 0,
		(uint32_t) BC_RELEASE, 0,
		(uint32_t) BC_DECREFS, 0,
	};
	uint32_t invalid_writes[] = {
		(uint32_t) BC_INCREFS, 25,
		(uint32_t) BC_ACQUIRE, 25,
		(uint32_t) BC_RELEASE, 25,
		(uint32_t) BC_DECREFS, 25,
	};
	int fd;

	fd = open("/dev/binder", O_RDWR | O_CLOEXEC);
	if (fd < 0) {
		perror("open /dev/binder");
		return 1;
	}
	if (ioctl(fd, BINDER_SET_CONTEXT_MGR, &context_manager) < 0) {
		perror("BINDER_SET_CONTEXT_MGR");
		close(fd);
		return 2;
	}

	bwr.write_size = sizeof(writes);
	bwr.write_buffer = (uint64_t) (uintptr_t) writes;
	if (ioctl(fd, BINDER_WRITE_READ, &bwr) < 0) {
		perror("BINDER_WRITE_READ reference commands");
		close(fd);
		return 3;
	}
	if (bwr.write_consumed != sizeof(writes)) {
		fprintf(stderr, "unexpected write_consumed=%llu expected=%lu\n",
			(unsigned long long) bwr.write_consumed,
			(unsigned long) sizeof(writes));
		return 4;
	}
	printf("BINDER_REFCOUNT_COMMANDS=PASS consumed=%llu\n",
	       (unsigned long long) bwr.write_consumed);

	bwr = (struct binder_write_read) {
		.write_size = sizeof(invalid_writes),
		.write_buffer = (uint64_t) (uintptr_t) invalid_writes,
	};
	if (ioctl(fd, BINDER_WRITE_READ, &bwr) < 0) {
		perror("BINDER_WRITE_READ invalid reference commands");
		close(fd);
		return 5;
	}
	if (bwr.write_consumed != sizeof(invalid_writes)) {
		fprintf(stderr, "invalid ref write_consumed=%llu expected=%lu\n",
			(unsigned long long) bwr.write_consumed,
			(unsigned long) sizeof(invalid_writes));
		close(fd);
		return 6;
	}
	printf("BINDER_INVALID_REF_COMMANDS=PASS consumed=%llu\n",
	       (unsigned long long) bwr.write_consumed);
	close(fd);
	return 0;
}
