/*
 * SPDX-FileCopyrightText: NONE
 * SPDX-License-Identifier: GPL-2.0-or-later
 * Note: AI-generated contribution; no legal determination implied.
 */
/* Verify BinderFS feature files remain ordinary readable files. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

struct procroot_binderfs_device {
	char name[256];
	uint32_t major;
	uint32_t minor;
};

#define BINDER_CTL_ADD _IOWR('b', 1, struct procroot_binderfs_device)

int main(void)
{
	struct procroot_binderfs_device device = {};
	char feature[16];
	int control_fd;
	int feature_fd;
	ssize_t count;

	control_fd = open("/dev/binderfs/binder-control", O_RDWR | O_CLOEXEC);
	if (control_fd < 0) {
		perror("open /dev/binderfs/binder-control");
		return 1;
	}
	strcpy(device.name, "binder");
	if (ioctl(control_fd, BINDER_CTL_ADD, &device) < 0) {
		perror("BINDER_CTL_ADD binder");
		close(control_fd);
		return 2;
	}
	close(control_fd);

	feature_fd = open("/dev/binderfs/features/oneway_spam_detection",
			   O_RDONLY | O_CLOEXEC | O_NONBLOCK);
	if (feature_fd < 0) {
		perror("open BinderFS feature file");
		return 3;
	}
	count = read(feature_fd, feature, sizeof(feature));
	if (count < 0) {
		perror("read BinderFS feature file");
		close(feature_fd);
		return 4;
	}
	if (count == 0) {
		fprintf(stderr, "BinderFS feature file was empty\n");
		close(feature_fd);
		return 5;
	}
	close(feature_fd);
	printf("BINDERFS_FEATURE_VALUE=%.*s", (int) count, feature);
	puts("BINDERFS_FEATURE_PATH=PASS");
	return 0;
}
