/*
 * SPDX-FileCopyrightText: NONE
 * SPDX-License-Identifier: GPL-2.0-or-later
 * Note: AI-generated contribution; no legal determination implied.
 */
/* Verify unknown BC_FREE_BUFFER pointers are consumed without aborting. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
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

#define BINDER_WRITE_READ _IOWR('b', 1, struct binder_write_read)
#define BC_FREE_BUFFER _IOW('c', 3, uint64_t)

int main(void)
{
	int fd = open("/dev/binder", O_RDWR | O_CLOEXEC);
	uint32_t command = (uint32_t)BC_FREE_BUFFER;
	uint64_t unknown_buffer = UINT64_C(0x12345678);
	uint8_t writes[sizeof(command) + sizeof(unknown_buffer)];
	struct binder_write_read bwr;

	if (fd < 0) {
		perror("open /dev/binder");
		return 1;
	}
	memcpy(writes, &command, sizeof(command));
	memcpy(writes + sizeof(command), &unknown_buffer,
	       sizeof(unknown_buffer));
	bwr = (struct binder_write_read) {
		.write_size = sizeof(writes),
		.write_buffer = (uint64_t)(uintptr_t)writes,
	};
	if (ioctl(fd, BINDER_WRITE_READ, &bwr) < 0) {
		perror("BINDER_WRITE_READ with unknown BC_FREE_BUFFER");
		close(fd);
		return 2;
	}
	if (bwr.write_consumed != sizeof(writes)) {
		fprintf(stderr, "unknown free consumed %llu of %zu bytes\n",
			(unsigned long long)bwr.write_consumed, sizeof(writes));
		close(fd);
		return 3;
	}
	close(fd);
	puts("BINDER_FREE_UNKNOWN_BUFFER=PASS");
	return 0;
}
