/*
 * SPDX-FileCopyrightText: NONE
 * SPDX-License-Identifier: GPL-2.0-or-later
 * Note: AI-generated contribution; no legal determination implied.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <sched.h>
#include <stdio.h>
#include <unistd.h>

int main(void)
{
	pid_t pid = getpid();
	int policy;
	int policy_errno;
	struct sched_param param;
	int param_status;
	int param_errno;

	errno = 0;
	policy = sched_getscheduler(pid);
	policy_errno = errno;
	errno = 0;
	param_status = sched_getparam(pid, &param);
	param_errno = errno;

	printf("PID_VIRT_SCHED pid=%ld policy=%d policy_errno=%d "
	       "getparam=%d getparam_errno=%d\n",
	       (long) pid, policy, policy_errno, param_status, param_errno);
	if (policy < 0 || param_status < 0)
		return 1;

	puts("PID_VIRT_SCHED=PASS");
	return 0;
}
