/*
 * SPDX-FileCopyrightText: NONE
 * SPDX-License-Identifier: GPL-2.0-or-later
 * Note: AI-generated contribution; no legal determination implied.
 */
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(void)
{
	char path[64];
	char contents[4096];
	char expected[64];
	int directory_fd;
	int status_fd;
	int task_fd;
	DIR *task_directory;
	struct dirent *entry;
	int found_virtual_tid = 0;
	ssize_t length;
	int path_length;

	path_length = snprintf(path, sizeof(path), "/proc/%ld", (long) getpid());
	if (path_length < 0 || (size_t) path_length >= sizeof(path)) {
		fprintf(stderr, "proc path is too long\n");
		return 1;
	}

	directory_fd = open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if (directory_fd < 0) {
		fprintf(stderr, "open(%s) failed: %s\n", path, strerror(errno));
		return 1;
	}

	status_fd = openat(directory_fd, "status", O_RDONLY | O_CLOEXEC);
	if (status_fd < 0) {
		fprintf(stderr, "openat(status) failed: %s\n", strerror(errno));
		close(directory_fd);
		return 1;
	}
	task_fd = openat(directory_fd, "task", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if (task_fd < 0) {
		fprintf(stderr, "openat(task) failed: %s\n", strerror(errno));
		close(status_fd);
		close(directory_fd);
		return 1;
	}

	length = read(status_fd, contents, sizeof(contents) - 1);
	close(status_fd);
	if (length <= 0) {
		fprintf(stderr, "reading status failed\n");
		close(task_fd);
		close(directory_fd);
		return 1;
	}
	contents[length] = '\0';

	path_length = snprintf(expected, sizeof(expected), "Pid:\t%ld\n",
			       (long) getpid());
	if (path_length < 0 || (size_t) path_length >= sizeof(expected)
	    || strstr(contents, expected) == NULL) {
		fprintf(stderr, "status did not report the virtual pid\n");
		close(task_fd);
		close(directory_fd);
		return 1;
	}
	puts("PROC_PID_DIRFD_STATUS=PASS");

	task_directory = fdopendir(task_fd);
	if (task_directory == NULL) {
		fprintf(stderr, "fdopendir(task) failed: %s\n", strerror(errno));
		close(task_fd);
		close(directory_fd);
		return 1;
	}
	while ((entry = readdir(task_directory)) != NULL) {
		char *end;
		long tid;

		if (entry->d_name[0] == '.')
			continue;
		tid = strtol(entry->d_name, &end, 10);
		if (*end == '\0' && tid == (long) gettid())
			found_virtual_tid = 1;
	}
	closedir(task_directory);
	close(directory_fd);
	if (!found_virtual_tid) {
		fprintf(stderr, "task directory did not report the virtual tid\n");
		return 1;
	}

	puts("PROC_PID_DIRFD_TASK=PASS");
	return 0;
}
