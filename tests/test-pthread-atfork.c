/*
 * SPDX-FileCopyrightText: NONE
 * SPDX-License-Identifier: GPL-2.0-or-later
 * Note: AI-generated contribution; no legal determination implied.
 */
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

static volatile sig_atomic_t child_handler_ran;

static void atfork_child(void)
{
	child_handler_ran = 1;
}

static void timeout_handler(int signal_number)
{
	static const char message[] = "PTHREAD_ATFORK_CHILD_RESET=TIMEOUT\n";
	(void)signal_number;
	(void)write(STDERR_FILENO, message, sizeof(message) - 1);
	_exit(124);
}

int main(void)
{
	struct sigaction action = {};
	int iteration;

	action.sa_handler = timeout_handler;
	sigemptyset(&action.sa_mask);
	if (sigaction(SIGALRM, &action, NULL) < 0 ||
	    pthread_atfork(NULL, NULL, atfork_child) != 0)
		return 1;

	for (iteration = 0; iteration < 2048; iteration++) {
		pid_t child = fork();
		int child_status = 0;
		pid_t waited;

		if (child < 0)
			return 1;
		if (child == 0) {
			alarm(3);
			if (!child_handler_ran)
				_exit(2);
			if (pthread_atfork(NULL, NULL, NULL) != 0)
				_exit(3);
			alarm(0);
			_exit(0);
		}

		do {
			waited = waitpid(child, &child_status, 0);
		} while (waited < 0 && errno == EINTR);
		if (waited != child || !WIFEXITED(child_status) ||
		    WEXITSTATUS(child_status) != 0) {
			fprintf(stderr,
				"PTHREAD_ATFORK_CHILD_RESET=FAIL iteration=%d child=%d waited=%d status=%#x errno=%d\n",
				iteration, child, waited, child_status, errno);
			return 1;
		}
	}

	puts("PTHREAD_ATFORK_CHILD_RESET=PASS iterations=2048");
	return 0;
}
