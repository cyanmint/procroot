/*
 * SPDX-FileCopyrightText: NONE
 * SPDX-License-Identifier: GPL-2.0-or-later
 * Note: AI-generated contribution; no legal determination implied.
 */
/* Verify CLONE_THREAD shares Binder fd-domain bookkeeping. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <unistd.h>

#define BINDER_SET_CONTEXT_MGR _IOW('b', 7, uint32_t)

struct worker_state {
	atomic_int fd;
	int ready_fd;
	int go_fd;
	int result;
	int error;
};

static void *register_hwbinder_context_manager(void *argument)
{
	struct worker_state *state = argument;
	uint32_t manager = 0;
	char token = 'r';

	if (write(state->ready_fd, &token, 1) != 1 ||
	    read(state->go_fd, &token, 1) != 1) {
		state->result = -2;
		return NULL;
	}
	errno = 0;
	state->result = ioctl(atomic_load(&state->fd),
		BINDER_SET_CONTEXT_MGR, &manager);
	state->error = errno;
	return NULL;
}

int main(void)
{
	int manager_ready[2] = { -1, -1 };
	int manager_release[2] = { -1, -1 };
	int worker_ready[2] = { -1, -1 };
	int worker_go[2] = { -1, -1 };
	uint32_t binder_manager = 0;
	pid_t manager_process;
	pthread_t worker;
	struct worker_state state = {};
	char token = 'x';
	int child_status;

	if (pipe(manager_ready) < 0 || pipe(manager_release) < 0 ||
	    pipe(worker_ready) < 0 || pipe(worker_go) < 0) {
		perror("pipe");
		return 1;
	}
	manager_process = fork();
	if (manager_process < 0) {
		perror("fork");
		return 2;
	}
	if (manager_process == 0) {
		int fd;
		close(manager_ready[0]);
		close(manager_release[1]);
		fd = open("/dev/binder", O_RDWR | O_CLOEXEC);
		if (fd < 0 || ioctl(fd, BINDER_SET_CONTEXT_MGR,
				&binder_manager) < 0)
			_exit(3);
		if (write(manager_ready[1], &token, 1) != 1 ||
		    read(manager_release[0], &token, 1) != 1)
			_exit(4);
		close(fd);
		_exit(0);
	}
	close(manager_ready[1]);
	close(manager_release[0]);
	if (read(manager_ready[0], &token, 1) != 1) {
		fprintf(stderr, "failed to start Binder-domain manager\n");
		return 5;
	}

	state.ready_fd = worker_ready[1];
	state.go_fd = worker_go[0];
	if (pthread_create(&worker, NULL, register_hwbinder_context_manager,
			   &state) != 0) {
		fprintf(stderr, "failed to create Binder worker thread\n");
		return 6;
	}
	if (read(worker_ready[0], &token, 1) != 1) {
		fprintf(stderr, "worker did not reach the synchronization point\n");
		return 7;
	}
	int hwbinder_fd = open("/dev/hwbinder", O_RDWR | O_CLOEXEC);
	if (hwbinder_fd < 0) {
		perror("open /dev/hwbinder");
		return 8;
	}
	atomic_store(&state.fd, hwbinder_fd);
	if (write(worker_go[1], &token, 1) != 1) {
		perror("release worker");
		return 9;
	}
	close(worker_go[1]);
	pthread_join(worker, NULL);

	if (write(manager_release[1], &token, 1) != 1 ||
	    waitpid(manager_process, &child_status, 0) < 0) {
		perror("stop Binder-domain manager");
		return 10;
	}
	close(hwbinder_fd);
	close(manager_ready[0]);
	close(manager_release[1]);
	close(worker_ready[0]);
	close(worker_ready[1]);
	close(worker_go[0]);
	if (!WIFEXITED(child_status) || WEXITSTATUS(child_status) != 0) {
		fprintf(stderr, "Binder-domain manager exited with status %#x\n",
			child_status);
		return 11;
	}
	if (state.result < 0) {
		fprintf(stderr,
			"BINDER_SHARED_THREAD_FD_DOMAIN=FAIL result=%d errno=%d\n",
			state.result, state.error);
		return 12;
	}
	puts("BINDER_SHARED_THREAD_FD_DOMAIN=PASS");
	return 0;
}
