/*
 * SPDX-FileCopyrightText: NONE
 * SPDX-License-Identifier: GPL-2.0-or-later
 * Note: AI-generated contribution; no legal determination implied.
 */
#include <errno.h>
#include <fcntl.h>
#include <linux/dm-ioctl.h>
#include <linux/fs.h>
#include <linux/loop.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <unistd.h>

#define DM_BUFFER_SIZE 4096

static void init_dm_ioctl(struct dm_ioctl *info, const char *name)
{
	memset(info, 0, sizeof(*info));
	info->version[0] = DM_VERSION_MAJOR;
	info->version[1] = DM_VERSION_MINOR;
	info->version[2] = DM_VERSION_PATCHLEVEL;
	info->data_size = sizeof(*info);
	if (name != NULL)
		(void)snprintf(info->name, sizeof(info->name), "%s", name);
}

int main(int argc, char **argv)
{
	char dm_buffer[DM_BUFFER_SIZE] = { 0 };
	char loop_path[64];
	char dm_path[64];
	char mount_path[128];
	char manifest_path[160];
	char parameters[512];
	char *end;
	uint64_t offset;
	int control_fd = -1;
	int loop_control_fd = -1;
	int loop_fd = -1;
	int backing_fd = -1;
	int dm_fd = -1;
	int loop_number;
	int dm_number;
	int result = 1;
	struct dm_ioctl *info = (struct dm_ioctl *)dm_buffer;
	struct dm_target_spec *spec;
	struct loop_info64 loop_info = { 0 };
	struct loop_info64 loop_status = { 0 };
	const char *filesystem = "ext4";

	if (argc != 3 && argc != 4) {
		fprintf(stderr, "usage: %s APEX_PATH PAYLOAD_OFFSET [FILESYSTEM]\n",
			argv[0]);
		return 2;
	}
	if (argc == 4)
		filesystem = argv[3];
	errno = 0;
	offset = strtoull(argv[2], &end, 0);
	if (errno != 0 || *end != '\0') {
		fprintf(stderr, "invalid payload offset: %s\n", argv[2]);
		return 2;
	}

	loop_control_fd = open("/dev/loop-control", O_RDWR | O_CLOEXEC);
	if (loop_control_fd < 0) {
		perror("open /dev/loop-control");
		goto end;
	}
	loop_number = ioctl(loop_control_fd, LOOP_CTL_GET_FREE);
	if (loop_number < 0) {
		perror("LOOP_CTL_GET_FREE");
		goto end;
	}
	printf("stage=loop-free number=%d\n", loop_number);
	fflush(stdout);
	(void)snprintf(loop_path, sizeof(loop_path), "/dev/block/loop%d",
		       loop_number);
	loop_fd = open(loop_path, O_RDWR | O_CLOEXEC);
	backing_fd = open(argv[1], O_RDONLY | O_CLOEXEC);
	if (loop_fd < 0 || backing_fd < 0) {
		perror("open loop or APEX payload");
		goto end;
	}
	if (ioctl(loop_fd, LOOP_SET_FD, backing_fd) < 0) {
		perror("LOOP_SET_FD");
		goto end;
	}
	printf("stage=loop-set-fd\n");
	fflush(stdout);
	(void)snprintf((char *)loop_info.lo_crypt_name,
		       sizeof(loop_info.lo_crypt_name), "apex:test");
	loop_info.lo_offset = offset;
	if (ioctl(loop_fd, LOOP_SET_STATUS64, &loop_info) < 0) {
		perror("LOOP_SET_STATUS64");
		goto end;
	}
	printf("stage=loop-set-offset offset=%llu\n",
	       (unsigned long long)offset);
	fflush(stdout);
	if (ioctl(loop_fd, LOOP_GET_STATUS64, &loop_status) < 0) {
		perror("LOOP_GET_STATUS64");
		goto end;
	}
	if (strcmp((char *)loop_status.lo_crypt_name, "apex:test") != 0) {
		fprintf(stderr, "LOOP_GET_STATUS64 lost lo_crypt_name\n");
		goto end;
	}
	if (ioctl(loop_fd, BLKFLSBUF, 0) < 0) {
		perror("BLKFLSBUF");
		goto end;
	}
	printf("stage=loop-status-preserved-and-flushed\n");
	fflush(stdout);
	close(backing_fd);
	backing_fd = -1;
	close(loop_control_fd);
	loop_control_fd = -1;

	control_fd = open("/dev/device-mapper", O_RDWR | O_CLOEXEC);
	if (control_fd < 0) {
		perror("open /dev/device-mapper");
		goto end;
	}
	init_dm_ioctl(info, "proot-fake-apex-test");
	if (ioctl(control_fd, DM_DEV_CREATE, info) < 0) {
		perror("DM_DEV_CREATE");
		goto end;
	}
	printf("stage=dm-create\n");
	fflush(stdout);
	dm_number = (int)minor((dev_t)info->dev);
	(void)snprintf(dm_path, sizeof(dm_path), "/dev/block/dm-%d", dm_number);

	memset(dm_buffer, 0, sizeof(dm_buffer));
	init_dm_ioctl(info, "proot-fake-apex-test");
	info->data_size = sizeof(dm_buffer);
	info->data_start = (uint32_t)((sizeof(*info) + 7) & ~7U);
	info->target_count = 1;
	spec = (struct dm_target_spec *)(dm_buffer + info->data_start);
	spec->sector_start = 0;
	spec->length = 1024;
	spec->next = 0;
	(void)snprintf(spec->target_type, sizeof(spec->target_type), "verity");
	(void)snprintf(parameters, sizeof(parameters),
		       "1 /dev/block/loop%d /dev/block/loop%d "
		       "4096 4096 64 64 sha256 "
		       "0000000000000000000000000000000000000000000000000000000000000000 -",
		       loop_number, loop_number);
	(void)snprintf((char *)(spec + 1),
		       sizeof(dm_buffer) - info->data_start - sizeof(*spec),
		       "%s", parameters);
	if (ioctl(control_fd, DM_TABLE_LOAD, info) < 0) {
		perror("DM_TABLE_LOAD");
		goto end;
	}
	printf("stage=dm-table-load\n");
	fflush(stdout);
	init_dm_ioctl(info, "proot-fake-apex-test");
	if (ioctl(control_fd, DM_DEV_SUSPEND, info) < 0) {
		perror("DM_DEV_SUSPEND");
		goto end;
	}
	printf("stage=dm-activate\n");
	fflush(stdout);
	printf("stage=opening-dm path=%s\n", dm_path);
	fflush(stdout);
	dm_fd = open(dm_path, O_RDONLY | O_CLOEXEC);
	if (dm_fd < 0) {
		perror("open fake dm device");
		goto end;
	}
	printf("stage=opened-dm\n");
	fflush(stdout);
	(void)snprintf(mount_path, sizeof(mount_path),
		       "/tmp/proot-fake-apex-%ld", (long)getpid());
	if (mkdir("/tmp", 0777) < 0 && errno != EEXIST) {
		perror("mkdir /tmp");
		goto end;
	}
	printf("stage=parent-created\n");
	fflush(stdout);
	if (mkdir(mount_path, 0777) < 0 && errno != EEXIST) {
		perror("mkdir mountpoint");
		goto end;
	}
	printf("stage=mountpoint-created\n");
	fflush(stdout);
	if (mount(dm_path, mount_path, filesystem, MS_RDONLY, NULL) < 0) {
		perror("fake APEX mount");
		goto end;
	}
	printf("stage=mount-returned\n");
	fflush(stdout);
	(void)snprintf(manifest_path, sizeof(manifest_path),
		       "%s/apex_manifest.pb", mount_path);
	if (access(manifest_path, R_OK) < 0) {
		perror("read extracted apex_manifest.pb");
		goto end;
	}
	printf("FAKE_APEX_MOUNT_PASS source=%s target=%s manifest=readable\n",
	       dm_path, mount_path);
	result = 0;
	(void)umount(mount_path);

end:
	if (dm_fd >= 0)
		close(dm_fd);
	if (control_fd >= 0) {
		init_dm_ioctl(info, "proot-fake-apex-test");
		(void)ioctl(control_fd, DM_DEV_REMOVE, info);
		close(control_fd);
	}
	if (loop_fd >= 0) {
		(void)ioctl(loop_fd, LOOP_CLR_FD, 0);
		close(loop_fd);
	}
	if (backing_fd >= 0)
		close(backing_fd);
	if (loop_control_fd >= 0)
		close(loop_control_fd);
	return result;
}
