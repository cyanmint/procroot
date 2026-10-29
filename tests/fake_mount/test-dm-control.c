/*
 * SPDX-FileCopyrightText: NONE
 * SPDX-License-Identifier: GPL-2.0-or-later
 * Note: AI-generated contribution; no legal determination implied.
 */
#include <errno.h>
#include <fcntl.h>
#include <linux/dm-ioctl.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/sysmacros.h>
#include <unistd.h>

static void initialize_dm_ioctl(struct dm_ioctl *info, const char *name)
{
	memset(info, 0, sizeof(*info));
	info->version[0] = DM_VERSION_MAJOR;
	info->version[1] = DM_VERSION_MINOR;
	info->version[2] = DM_VERSION_PATCHLEVEL;
	info->data_size = sizeof(*info);
	info->data_start = sizeof(*info);
	(void)snprintf(info->name, sizeof(info->name), "%s", name);
}

int main(void)
{
	struct dm_ioctl info;
	char device_path[64];
	int control_fd;
	int device_fd;
	int device_number;

	control_fd = open("/dev/device-mapper", O_RDWR | O_CLOEXEC);
	if (control_fd < 0) {
		perror("open /dev/device-mapper");
		return 1;
	}

	initialize_dm_ioctl(&info, "fake-mount-test");
	if (ioctl(control_fd, DM_DEV_CREATE, &info) < 0) {
		perror("DM_DEV_CREATE");
		close(control_fd);
		return 1;
	}
	device_number = minor((dev_t)info.dev);
	if (device_number < 0 || device_number >= 256) {
		fprintf(stderr, "invalid synthetic DM minor: %d\n", device_number);
		close(control_fd);
		return 1;
	}
	(void)snprintf(device_path, sizeof(device_path), "/dev/block/dm-%d",
		       device_number);
	device_fd = open(device_path, O_RDONLY | O_CLOEXEC);
	if (device_fd < 0) {
		perror("open synthetic DM device");
		close(control_fd);
		return 1;
	}
	printf("DM_DEV_CREATE=%s PASS\n", device_path);
	close(device_fd);

	initialize_dm_ioctl(&info, "fake-mount-test");
	if (ioctl(control_fd, DM_DEV_REMOVE, &info) < 0) {
		perror("DM_DEV_REMOVE");
		close(control_fd);
		return 1;
	}
	printf("DM_DEV_REMOVE PASS\n");
	close(control_fd);
	return 0;
}
