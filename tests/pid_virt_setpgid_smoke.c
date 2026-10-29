/*
 * SPDX-FileCopyrightText: NONE
 * SPDX-License-Identifier: GPL-2.0-or-later
 * Note: AI-generated contribution; no legal determination implied.
 */
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
    int group_rc = setpgid(child, child);
    int group_errno = errno;
    pid_t pgid = getpgid(child);
    kill(child, SIGTERM);

    siginfo_t info = {};
    errno = 0;
    int wait_rc = waitid(P_PID, (id_t) child, &info, WEXITED);
    int wait_errno = errno;
    printf("self=%ld child_return=%ld child_getpid=%ld setpgid_rc=%d errno=%d pgid=%ld waitid_rc=%d errno=%d si_pid=%ld\n",
           (long) self, (long) child, (long) child_visible,
           group_rc, group_errno, (long) pgid, wait_rc, wait_errno,
           (long) info.si_pid);
    fflush(stdout);

    if (got != sizeof(child_visible) || self != 1 || child != child_visible ||
        group_rc != 0 || pgid != child || wait_rc != 0 || info.si_pid != child)
        return 1;
    return 0;
}
