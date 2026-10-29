/*
 * SPDX-FileCopyrightText: NONE
 * SPDX-License-Identifier: GPL-2.0-or-later
 * Note: AI-generated contribution; no legal determination implied.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <linux/netlink.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

int main(void)
{
	int fd = socket(AF_NETLINK, SOCK_DGRAM | SOCK_CLOEXEC,
			NETLINK_KOBJECT_UEVENT);
	if (fd < 0) {
		perror("socket NETLINK_KOBJECT_UEVENT");
		return 1;
	}

	struct sockaddr_nl address = {
		.nl_family = AF_NETLINK,
		.nl_pid = 0,
		.nl_groups = UINT32_MAX,
	};
	if (bind(fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
		perror("bind NETLINK_KOBJECT_UEVENT");
		close(fd);
		return 2;
	}

	socklen_t address_size = sizeof(address);
	memset(&address, 0, sizeof(address));
	if (getsockname(fd, (struct sockaddr *)&address, &address_size) < 0) {
		perror("getsockname NETLINK_KOBJECT_UEVENT");
		close(fd);
		return 3;
	}
	close(fd);

	printf("family=%u groups=%u\n", address.nl_family, address.nl_groups);
	if (address.nl_family != AF_NETLINK || address.nl_groups != 0) {
		fprintf(stderr, "uevent socket was not isolated from host multicast\n");
		return 4;
	}
	return 0;
}
