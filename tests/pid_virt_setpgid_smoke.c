#define _GNU_SOURCE
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

int main(void)
{
    int p[2];
    if (pipe(p) < 0) {
        perror("pipe");
        return 2;
    }

    pid_t self = getpid();
    pid_t child = fork();
    if (child < 0) {
        perror("fork");
        return 2;
    }
    if (child == 0) {
        close(p[0]);
        pid_t visible = getpid();
        (void) write(p[1], &visible, sizeof(visible));
        close(p[1]);
        sleep(3);
        _exit(0);
    }

    close(p[1]);
    pid_t child_visible = -1;
    ssize_t got = read(p[0], &child_visible, sizeof(child_visible));
    close(p[0]);

    errno = 0;
    int rc = setpgid(child, child);
    int saved_errno = errno;
    pid_t pgid = getpgid(child);
    printf("self=%ld child_return=%ld child_getpid=%ld setpgid_rc=%d errno=%d pgid=%ld\n",
           (long) self, (long) child, (long) child_visible,
           rc, saved_errno, (long) pgid);
    fflush(stdout);

    if (got != sizeof(child_visible) || self != 1 || child != child_visible ||
        rc != 0 || pgid != child) {
        kill(child, SIGKILL);
        waitpid(child, NULL, 0);
        return 1;
    }
    kill(child, SIGTERM);
    waitpid(child, NULL, 0);
    return 0;
}
