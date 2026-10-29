/*
 * SPDX-FileCopyrightText: NONE
 * SPDX-License-Identifier: GPL-2.0-or-later
 * Note: AI-generated contribution; no legal determination implied.
 */
#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <signal.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef WORKER_COUNT
#define WORKER_COUNT 4
#endif
#ifndef ITERATIONS_PER_WORKER
#define ITERATIONS_PER_WORKER 1024
#endif

static void timeout_handler(int signal_number)
{
	static const char message[] = "FORK_CHILD_EXIT_RACE=FAIL timeout\n";

	(void) signal_number;
	(void) write(STDERR_FILENO, message, sizeof(message) - 1);
	_exit(4);
}

static void *run_worker(void *argument)
{
	int worker = (int) (intptr_t) argument;

	for (int iteration = 0; iteration < ITERATIONS_PER_WORKER; iteration++) {
		pid_t child = fork();
		int status = 0;
		pid_t waited;

		if (child < 0) {
			dprintf(STDERR_FILENO,
				"FORK_CHILD_EXIT_RACE=FAIL worker=%d iteration=%d fork_errno=%d\n",
				worker, iteration, errno);
			return (void *) 1;
		}
		if (child == 0)
			_exit(0);

		do {
			waited = waitpid(child, &status, 0);
		} while (waited < 0 && errno == EINTR);

		if (waited != child || !WIFEXITED(status) || WEXITSTATUS(status) != 0) {
			dprintf(STDERR_FILENO,
				"FORK_CHILD_EXIT_RACE=FAIL worker=%d iteration=%d child=%d waited=%d status=%#x errno=%d\n",
				worker, iteration, child, waited, status, errno);
			return (void *) 1;
		}
	}

	return NULL;
}

int main(void)
{
	struct sigaction action = {};
	pthread_t workers[WORKER_COUNT];
	int started = 0;

	action.sa_handler = timeout_handler;
	sigemptyset(&action.sa_mask);
	if (sigaction(SIGALRM, &action, NULL) < 0)
		return 1;
	alarm(120);

	for (; started < WORKER_COUNT; started++) {
		if (pthread_create(&workers[started], NULL, run_worker,
				   (void *) (intptr_t) started) != 0)
			break;
	}
	if (started != WORKER_COUNT) {
		fprintf(stderr, "FORK_CHILD_EXIT_RACE=FAIL pthread_create\n");
		return 1;
	}

	for (int worker = 0; worker < WORKER_COUNT; worker++) {
		void *result = NULL;
		if (pthread_join(workers[worker], &result) != 0 || result != NULL)
			return 2;
	}

	alarm(0);
	printf("FORK_CHILD_EXIT_RACE=PASS workers=%d iterations_per_worker=%d\n",
	       WORKER_COUNT, ITERATIONS_PER_WORKER);
	return 0;
}
