/*
 * SPDX-FileCopyrightText: NONE
 * SPDX-License-Identifier: GPL-2.0-or-later
 * Note: AI-generated contribution; no legal determination implied.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <errno.h>
#include <sys/socket.h>

#include "extension/binder/fda_courier.h"

int binder_fda_verify_peer_pid(int fd, pid_t expected_pid)
{
	struct ucred credentials = {};
	socklen_t size = sizeof(credentials);

	if (expected_pid <= 0)
		return -EINVAL;
	if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &credentials, &size) < 0)
		return -errno;
	if (size != sizeof(credentials) || credentials.pid != expected_pid)
		return -EACCES;
	return 0;
}

int binder_fda_scratch_address(uintptr_t buffer, size_t read_size,
		size_t read_consumed, size_t scratch_size, size_t alignment,
		uintptr_t *address)
{
	uintptr_t candidate;
	size_t padding;
	size_t offset;

	if (buffer == 0 || address == NULL || alignment == 0 ||
	    (alignment & (alignment - 1)) != 0)
		return -EINVAL;
	if (read_consumed > read_size)
		return -ENOSPC;
	if (read_consumed > UINTPTR_MAX - buffer)
		return -EOVERFLOW;
	candidate = buffer + read_consumed;
	padding = (alignment - candidate % alignment) % alignment;
	if (padding > read_size - read_consumed)
		return -ENOSPC;
	offset = read_consumed + padding;
	if (scratch_size > read_size - offset)
		return -ENOSPC;
	if (offset > UINTPTR_MAX - buffer)
		return -EOVERFLOW;
	candidate = buffer + offset;
	if (scratch_size > UINTPTR_MAX - candidate)
		return -EOVERFLOW;
	*address = candidate;
	return 0;
}
