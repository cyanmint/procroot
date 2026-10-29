/*
 * SPDX-FileCopyrightText: NONE
 * SPDX-License-Identifier: GPL-2.0-or-later
 * Note: AI-generated contribution; no legal determination implied.
 */
/* Binder mode must not block shutdown(2) on ordinary sockets. */
#include <stdio.h>
#include <sys/socket.h>
#include <unistd.h>

int main(void)
{
	int sockets[2];
	char byte;
	ssize_t count;

	if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sockets) < 0) {
		perror("socketpair");
		return 1;
	}
	if (shutdown(sockets[0], SHUT_WR) < 0) {
		perror("shutdown");
		close(sockets[0]);
		close(sockets[1]);
		return 1;
	}
	count = read(sockets[1], &byte, sizeof(byte));
	close(sockets[0]);
	close(sockets[1]);
	if (count != 0) {
		fprintf(stderr, "expected EOF after SHUT_WR, got %zd bytes\n", count);
		return 1;
	}
	puts("BINDER_SOCKET_SHUTDOWN=PASS");
	return 0;
}
