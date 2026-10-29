/*
 * SPDX-FileCopyrightText: NONE
 * SPDX-License-Identifier: GPL-2.0-or-later
 * Note: AI-generated contribution; no legal determination implied.
 */
/* Verify bounds for scratch storage in a Binder read buffer. */
#include <errno.h>
#include <stdint.h>
#include <stdio.h>

extern int binder_fda_scratch_address(uintptr_t buffer, size_t read_size,
		size_t read_consumed, size_t scratch_size,
		size_t alignment, uintptr_t *address) __attribute__((weak));

int main(void)
{
	uintptr_t address = 0;

	if (binder_fda_scratch_address == NULL) {
		puts("FDA_SCRATCH=FAIL helper missing");
		return 1;
	}
	if (binder_fda_scratch_address(0x1000, 1024, 256, 256, 16,
			&address) != 0 || address != 0x1100) {
		puts("FDA_SCRATCH=FAIL valid tail was rejected");
		return 1;
	}
	if (binder_fda_scratch_address(0x1003, 128, 1, 8, 16,
			&address) != 0 || address != 0x1010) {
		puts("FDA_SCRATCH=FAIL unaligned tail was not aligned");
		return 1;
	}
	if (binder_fda_scratch_address(0x1000, 1024, 768, 257, 16,
			&address) != -ENOSPC) {
		puts("FDA_SCRATCH=FAIL out-of-bounds tail was accepted");
		return 1;
	}
	if (binder_fda_scratch_address(0x1000, 1024, 1025, 1, 16,
			&address) != -ENOSPC) {
		puts("FDA_SCRATCH=FAIL oversized read was accepted");
		return 1;
	}
	if (binder_fda_scratch_address(0x1000, 1024, 0, 8, 3,
			&address) != -EINVAL) {
		puts("FDA_SCRATCH=FAIL invalid alignment was accepted");
		return 1;
	}
	if (binder_fda_scratch_address(UINTPTR_MAX - 8, 32, 16, 1, 16,
			&address) != -EOVERFLOW) {
		puts("FDA_SCRATCH=FAIL pointer overflow was accepted");
		return 1;
	}
	puts("FDA_SCRATCH=PASS");
	return 0;
}
