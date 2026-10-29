/*
 * SPDX-FileCopyrightText: NONE
 * SPDX-License-Identifier: GPL-2.0-or-later
 * Note: AI-generated contribution; no legal determination implied.
 */
#include <errno.h>
#include <fcntl.h>
#include <linux/loop.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <unistd.h>

int main(int argc, char **argv)
{
	int fd;
	int loop_fd;
	int backing_fd;
	int number;
	int add_result;
	int add_id;
	int add_count;
	char loop_path[64];
	char sysfs_path[64];
	struct stat loop_control_stat;

	if (argc != 2) {
		fprintf(stderr, "usage: %s APEX_PATH\n", argv[0]);
		return 2;
	}

	if (access("/dev/loop-control", F_OK) < 0) {
		perror("access /dev/loop-control");
		return 1;
	}
	if (stat("/dev/loop-control", &loop_control_stat) < 0) {
		perror("stat /dev/loop-control");
		return 1;
	}
	printf("LOOP_CONTROL_VISIBLE PASS\n");

	fd = open("/dev/loop-control", O_RDWR | O_CLOEXEC);
	if (fd < 0) {
		perror("open /dev/loop-control");
		return 1;
	}
	{
		int count = 0;
		int id;
		add_count = 0;

		for (id = 0; count < 10; id++) {
			errno = 0;
			add_result = ioctl(fd, LOOP_CTL_ADD, id);
			if (add_result > 0) {
				count++;
				add_count++;
				continue;
			}
			if (add_result < 0 && errno == EEXIST) {
				(void)snprintf(sysfs_path, sizeof(sysfs_path),
					       "/sys/block/loop%d/loop", id);
				if (access(sysfs_path, F_OK) < 0)
					count++;
				continue;
			}
			fprintf(stderr,
				"APEX_LOOP_PREALLOC_FAIL id=%d result=%d errno=%d\n",
				id, add_result, errno);
			close(fd);
			return 1;
		}
	}
	printf("APEX_LOOP_PREALLOC_PASS count=10 new=%d\n", add_count);
	for (add_id = 255; add_id > 0; add_id--) {
		errno = 0;
		add_result = ioctl(fd, LOOP_CTL_ADD, add_id);
		if (add_result == add_id)
			break;
		if (add_result < 0 && errno == EEXIST)
			continue;
		fprintf(stderr,
			"LOOP_CTL_ADD_DYNAMIC_FAIL id=%d result=%d errno=%d\n",
			add_id, add_result, errno);
		close(fd);
		return 1;
	}
	if (add_id <= 0) {
		fprintf(stderr, "LOOP_CTL_ADD_DYNAMIC_FAIL no free index\n");
		close(fd);
		return 1;
	}
	printf("LOOP_CTL_ADD_DYNAMIC=%d PASS\n", add_id);

	number = ioctl(fd, LOOP_CTL_GET_FREE);
	if (number < 0) {
		perror("LOOP_CTL_GET_FREE");
		close(fd);
		return 1;
	}

	printf("LOOP_CTL_GET_FREE=%d PASS\n", number);
	(void)snprintf(loop_path, sizeof(loop_path), "/dev/block/loop%d", number);
	loop_fd = open(loop_path, O_RDWR | O_CLOEXEC);
	if (loop_fd < 0) {
		perror("open loop device");
		close(fd);
		return 1;
	}
	backing_fd = open(argv[1], O_RDONLY | O_CLOEXEC);
	if (backing_fd < 0) {
		perror("open APEX backing file");
		close(loop_fd);
		close(fd);
		return 1;
	}
	if (ioctl(loop_fd, LOOP_SET_FD, backing_fd) < 0) {
		perror("LOOP_SET_FD");
		close(backing_fd);
		close(loop_fd);
		close(fd);
		return 1;
	}
	printf("LOOP_SET_FD=%s PASS\n", argv[1]);
	close(backing_fd);
	close(loop_fd);
	close(fd);
	return 0;
}
