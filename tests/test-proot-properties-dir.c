/*
 * SPDX-FileCopyrightText: NONE
 * SPDX-License-Identifier: GPL-2.0-or-later
 * Note: AI-generated contribution; no legal determination implied.
 */
#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>

#define PROPERTY_TEST_PATH "/dev/__properties__/proot-property-owner-test"

int main(void)
{
	int fd;
	struct stat st;

	if (getuid() != 0 || getgid() != 0) {
		fprintf(stderr, "test requires fake root (uid/gid 0)\n");
		return 1;
	}

	fd = open(PROPERTY_TEST_PATH, O_WRONLY | O_CREAT | O_EXCL, 0444);
	if (fd < 0) {
		perror("create test property");
		return 2;
	}
	if (fchown(fd, 0, 0) < 0) {
		perror("chown test property to root");
		close(fd);
		return 3;
	}
	if (setgid(1000) < 0) {
		perror("setgid(system)");
		return 4;
	}
	if (setuid(1000) < 0) {
		perror("setuid(system)");
		return 5;
	}
	if (getuid() != 1000 || getgid() != 1000) {
		fprintf(stderr, "identity drop failed: %u:%u\n", getuid(), getgid());
		return 6;
	}

	if (fstat(fd, &st) < 0) {
		perror("fstat property area as system");
		return 7;
	}
	if (st.st_uid != 0 || st.st_gid != 0) {
		fprintf(stderr, "open property owner changed after uid drop: %u:%u\n",
			st.st_uid, st.st_gid);
		return 8;
	}
	close(fd);

	if (stat(PROPERTY_TEST_PATH, &st) < 0) {
		perror("stat property area as system");
		return 9;
	}
	if (st.st_uid != 0 || st.st_gid != 0) {
		fprintf(stderr, "property path owner changed after uid drop: %u:%u\n",
			st.st_uid, st.st_gid);
		return 10;
	}

	puts("ANDROID_PROPERTY_AREA_ROOT_OWNERSHIP=PASS");
	return 0;
}
