/*
 * SPDX-FileCopyrightText: NONE
 * SPDX-License-Identifier: GPL-2.0-or-later
 * Note: AI-generated contribution; no legal determination implied.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/vfs.h>
#include <sys/xattr.h>
#include <unistd.h>

#define TMPFS_MAGIC 0x01021994

int main(void)
{
	char path[] = "/dev/__properties__/proot-property-XXXXXX";
	static const char label[] = "u:object_r:procroot_test_prop:s0";
	struct statfs fs;
	int fd;
	int status;

	fd = mkstemp(path);
	if (fd < 0) {
		perror("mkstemp(/dev/__properties__)");
		return 1;
	}
	if (statfs("/dev/__properties__", &fs) < 0) {
		perror("statfs(/dev/__properties__)");
		close(fd);
		unlink(path);
		return 5;
	}
	if ((unsigned long) fs.f_type != TMPFS_MAGIC) {
		fprintf(stderr, "statfs(/dev/__properties__): expected tmpfs, got 0x%lx\n",
			(unsigned long) fs.f_type);
		close(fd);
		unlink(path);
		return 5;
	}
	if (fstatfs(fd, &fs) < 0) {
		perror("fstatfs(/dev/__properties__)");
		close(fd);
		unlink(path);
		return 6;
	}
	if ((unsigned long) fs.f_type != TMPFS_MAGIC) {
		fprintf(stderr, "fstatfs(/dev/__properties__): expected tmpfs, got 0x%lx\n",
			(unsigned long) fs.f_type);
		close(fd);
		unlink(path);
		return 6;
	}
	printf("PROPERTY_AREA=tmpfs,statfs+fstatfs\n");

	status = fsetxattr(fd, "security.selinux", label, sizeof(label), 0);
	if (status < 0) {
		perror("fsetxattr(security.selinux)");
		close(fd);
		unlink(path);
		return 2;
	}
	printf("PROPERTY_LABEL_XATTR=accepted\n");

	errno = 0;
	status = fsetxattr(fd, "security.selinux", label, sizeof(label), 0x40000000);
	if (status != -1 || errno != EINVAL) {
		fprintf(stderr, "invalid SELinux xattr flags unexpectedly returned %d (errno %d)\n",
			status, errno);
		close(fd);
		unlink(path);
		return 4;
	}
	printf("PROPERTY_INVALID_XATTR_FLAGS=EINVAL\n");

	if (close(fd) < 0 || unlink(path) < 0) {
		perror("cleanup property probe");
		return 3;
	}
	return 0;
}
