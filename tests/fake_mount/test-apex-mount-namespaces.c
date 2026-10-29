/*
 * SPDX-FileCopyrightText: NONE
 * SPDX-License-Identifier: GPL-2.0-or-later
 * Note: AI-generated contribution; no legal determination implied.
 */
#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <linux/mount.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <unistd.h>

static int fail(const char *what)
{
	fprintf(stderr, "FAIL: %s: %s\n", what, strerror(errno));
	return -1;
}

static int make_dir(const char *path)
{
	if (mkdir(path, 0755) == 0 || errno == EEXIST)
		return 0;
	return fail(path);
}

static int mount_bind(const char *source, const char *target)
{
	if (mount(source, target, NULL, MS_BIND | MS_REC, NULL) == 0)
		return 0;
	return fail("mount bind");
}

static int namespace_id(char *buffer, size_t size)
{
	ssize_t length = readlink("/proc/self/ns/mnt", buffer, size - 1);
	if (length < 0)
		return fail("readlink /proc/self/ns/mnt");
	buffer[length] = '\0';
	return 0;
}

static int exists(const char *path)
{
	struct stat status;
	return stat(path, &status) == 0;
}

static int write_marker(const char *path, const char *value)
{
	int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (fd < 0)
		return fail(path);
	if (write(fd, value, strlen(value)) != (ssize_t)strlen(value)) {
		close(fd);
		return fail(path);
	}
	close(fd);
	return 0;
}

static int marker_matches(const char *path, const char *expected)
{
	char buffer[32];
	int fd = open(path, O_RDONLY | O_CLOEXEC);
	ssize_t length;

	if (fd < 0)
		return 0;
	length = read(fd, buffer, sizeof(buffer));
	close(fd);
	return length == (ssize_t)strlen(expected) &&
		memcmp(buffer, expected, (size_t)length) == 0;
}

int main(void)
{
	char bootstrap_id[64];
	char default_id[64];
	int bootstrap_ns = -1;
	int default_ns = -1;
	int result = 1;

	if (make_dir("/apex") < 0 || make_dir("/apex/com.android.runtime") < 0 ||
	    make_dir("/bootstrap-apex") < 0 ||
	    make_dir("/bootstrap-apex/com.android.runtime") < 0 ||
	    make_dir("/mnt") < 0 || make_dir("/mnt/default-apex") < 0 ||
	    make_dir("/mnt/default-apex/com.android.runtime") < 0 ||
	    write_marker("/bootstrap-apex/com.android.runtime/marker",
			 "bootstrap") < 0 ||
	    write_marker("/mnt/default-apex/com.android.runtime/marker",
			 "default") < 0)
		goto out;
	if (namespace_id(bootstrap_id, sizeof(bootstrap_id)) != 0)
		goto out;
	bootstrap_ns = open("/proc/self/ns/mnt", O_RDONLY | O_CLOEXEC);
	if (bootstrap_ns < 0) {
		fail("open bootstrap mount namespace");
		goto out;
	}
	if (unshare(CLONE_NEWNS) < 0) {
		fail("unshare mount namespace");
		goto out;
	}
	if (namespace_id(default_id, sizeof(default_id)) != 0)
		goto out;
	if (strcmp(bootstrap_id, default_id) == 0) {
		fprintf(stderr, "FAIL: unshare reused mount namespace identity %s\n",
			default_id);
		goto out;
	}
	default_ns = open("/proc/self/ns/mnt", O_RDONLY | O_CLOEXEC);
	if (default_ns < 0) {
		fail("open default mount namespace");
		goto out;
	}

	if (setns(bootstrap_ns, CLONE_NEWNS) < 0) {
		fail("setns bootstrap mount namespace");
		goto out;
	}
	if (mount_bind("/bootstrap-apex", "/apex") < 0 ||
	    !marker_matches("/apex/com.android.runtime/marker", "bootstrap")) {
		fprintf(stderr, "FAIL: bootstrap APEX mount is missing\n");
		goto out;
	}
	if (setns(default_ns, CLONE_NEWNS) < 0) {
		fail("setns default mount namespace");
		goto out;
	}
	if (exists("/apex/com.android.runtime/marker")) {
		fprintf(stderr, "FAIL: bootstrap APEX leaked into default view\n");
		goto out;
	}
	if (!marker_matches("/bootstrap-apex/com.android.runtime/marker",
			    "bootstrap")) {
		fprintf(stderr, "FAIL: bootstrap APEX source is missing in default view\n");
		goto out;
	}
	if (mount_bind("/mnt/default-apex", "/apex") < 0 ||
	    !marker_matches("/apex/com.android.runtime/marker", "default")) {
		fprintf(stderr, "FAIL: default APEX mount is missing\n");
		goto out;
	}
	if (setns(bootstrap_ns, CLONE_NEWNS) < 0) {
		fail("return to bootstrap mount namespace");
		goto out;
	}
	if (!marker_matches("/apex/com.android.runtime/marker", "bootstrap")) {
		fprintf(stderr, "FAIL: default APEX leaked into bootstrap view\n");
		goto out;
	}
	if (setns(default_ns, CLONE_NEWNS) < 0 ||
	    !marker_matches("/apex/com.android.runtime/marker", "default")) {
		fprintf(stderr, "FAIL: default APEX view did not survive namespace switch\n");
		goto out;
	}
	puts("PASS: bootstrap/default APEX mounts remain isolated across setns");
	result = 0;

out:
	if (bootstrap_ns >= 0)
		close(bootstrap_ns);
	if (default_ns >= 0)
		close(default_ns);
	return result;
}
