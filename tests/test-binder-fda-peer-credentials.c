/*
 * SPDX-FileCopyrightText: NONE
 * SPDX-License-Identifier: GPL-2.0-or-later
 * Note: AI-generated contribution; no legal determination implied.
 */
/* Verify that Binder FD courier peers are authenticated by process ID. */
#define _GNU_SOURCE
#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

extern int binder_fda_verify_peer_pid(int fd, pid_t expected_pid)
	__attribute__((weak));

static int make_listener(struct sockaddr_un *address, socklen_t *length)
{
	char name[sizeof(address->sun_path) - 1];
	int fd;
	int size;

	memset(address, 0, sizeof(*address));
	address->sun_family = AF_UNIX;
	size = snprintf(name, sizeof(name), "proot-fda-test-%ld",
		(long)getpid());
	if (size < 0 || (size_t)size >= sizeof(name))
		return -1;
	address->sun_path[0] = '\0';
	memcpy(address->sun_path + 1, name, (size_t)size);
	*length = (socklen_t)(offsetof(struct sockaddr_un, sun_path) + 1 + size);

	fd = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
	if (fd < 0)
		return -1;
	if (bind(fd, (struct sockaddr *)address, *length) < 0 ||
	    listen(fd, 1) < 0) {
		close(fd);
		return -1;
	}
	return fd;
}

int main(void)
{
	struct sockaddr_un address;
	socklen_t address_length;
	pid_t child;
	int listener;
	int accepted;
	int child_status;

	if (binder_fda_verify_peer_pid == NULL) {
		puts("FDA_PEER_CREDENTIALS=FAIL verifier missing");
		return 1;
	}
	listener = make_listener(&address, &address_length);
	if (listener < 0) {
		perror("make_listener");
		return 1;
	}
	child = fork();
	if (child < 0) {
		perror("fork");
		close(listener);
		return 1;
	}
	if (child == 0) {
		int client = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
		int status = client < 0 ? -1 :
			connect(client, (struct sockaddr *)&address, address_length);
		if (client >= 0)
			close(client);
		_exit(status == 0 ? 0 : 2);
	}
	accepted = accept4(listener, NULL, NULL, SOCK_CLOEXEC);
	close(listener);
	if (accepted < 0) {
		perror("accept4");
		(void)waitpid(child, NULL, 0);
		return 1;
	}
	if (binder_fda_verify_peer_pid(accepted, getpid()) != -EACCES) {
		puts("FDA_PEER_CREDENTIALS=FAIL wrong PID was accepted");
		close(accepted);
		(void)waitpid(child, NULL, 0);
		return 1;
	}
	if (binder_fda_verify_peer_pid(accepted, child) != 0) {
		puts("FDA_PEER_CREDENTIALS=FAIL valid peer was rejected");
		close(accepted);
		(void)waitpid(child, NULL, 0);
		return 1;
	}
	if (binder_fda_verify_peer_pid(-1, child) != -EBADF) {
		puts("FDA_PEER_CREDENTIALS=FAIL invalid socket error mismatch");
		close(accepted);
		(void)waitpid(child, NULL, 0);
		return 1;
	}
	close(accepted);
	if (waitpid(child, &child_status, 0) != child ||
	    !WIFEXITED(child_status) || WEXITSTATUS(child_status) != 0) {
		puts("FDA_PEER_CREDENTIALS=FAIL client connect failed");
		return 1;
	}
	puts("FDA_PEER_CREDENTIALS=PASS");
	return 0;
}
