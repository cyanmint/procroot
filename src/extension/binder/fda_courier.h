/*
 * SPDX-FileCopyrightText: NONE
 * SPDX-License-Identifier: GPL-2.0-or-later
 * Note: AI-generated contribution; no legal determination implied.
 */
#ifndef BINDER_FDA_COURIER_H
#define BINDER_FDA_COURIER_H

#include <sys/types.h>
#include <stddef.h>
#include <stdint.h>

int binder_fda_verify_peer_pid(int fd, pid_t expected_pid);
int binder_fda_scratch_address(uintptr_t buffer, size_t read_size,
		size_t read_consumed, size_t scratch_size, size_t alignment,
		uintptr_t *address);

#endif /* BINDER_FDA_COURIER_H */
