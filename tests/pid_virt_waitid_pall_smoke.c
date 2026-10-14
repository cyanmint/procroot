#define _GNU_SOURCE
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

int main(void)
{
	pid_t self = getpid();
	pid_t child = fork();
	if (child < 0) {
		perror("fork");
		return 2;
	}
	if (child == 0)
		_exit(0);

	siginfo_t info = { 0 };
	errno = 0;
	int rc = waitid(P_ALL, 0, &info, WEXITED | WNOWAIT);
	int waitid_errno = errno;
	printf("self=%ld child=%ld waitid_rc=%d errno=%d si_pid=%ld\n",
	       (long)self, (long)child, rc, waitid_errno, (long)info.si_pid);
	if (rc != 0 || self != 1 || child != 2 || info.si_pid != child)
		return 1;

	int status = 0;
	errno = 0;
	pid_t waited = waitpid(info.si_pid, &status, 0);
	int waitpid_errno = errno;
	printf("waitpid_rc=%ld errno=%d status=%d\n",
	       (long)waited, waitpid_errno, status);
	if (waited != child || !WIFEXITED(status) || WEXITSTATUS(status) != 0)
		return 1;
	return 0;
}
