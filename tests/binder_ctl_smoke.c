#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include <sys/ioctl.h>
#include <sys/vfs.h>
#include <unistd.h>
#include <stdlib.h>

struct binderfs_device {
	char name[256];
	uint32_t major;
	uint32_t minor;
};

struct binder_version {
	int32_t protocol_version;
};

struct binder_write_read {
	uint64_t write_size;
	uint64_t write_consumed;
	uint64_t write_buffer;
	uint64_t read_size;
	uint64_t read_consumed;
	uint64_t read_buffer;
};

#define BINDER_CTL_ADD _IOWR('b', 1, struct binderfs_device)
#define BINDER_VERSION _IOWR('b', 9, struct binder_version)
#define BINDER_WRITE_READ _IOWR('b', 1, struct binder_write_read)

#define TMPFS_MAGIC 0x01021994

static int probe_tmpfs_path(const char *path)
{
	struct statfs fs;
	char marker[] = "/dev/shm/procroot-shm-XXXXXX";
	int fd;

	if (statfs(path, &fs) < 0) {
		perror(path);
		return 1;
	}
	if ((unsigned long) fs.f_type != TMPFS_MAGIC) {
		fprintf(stderr, "%s: expected tmpfs, got 0x%lx\n", path,
			(unsigned long) fs.f_type);
		return 2;
	}
	fd = open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if (fd < 0) {
		perror(path);
		return 3;
	}
	if (fstatfs(fd, &fs) < 0) {
		perror("fstatfs");
		close(fd);
		return 4;
	}
	if ((unsigned long) fs.f_type != TMPFS_MAGIC) {
		fprintf(stderr, "%s: fstatfs expected tmpfs, got 0x%lx\n", path,
			(unsigned long) fs.f_type);
		close(fd);
		return 5;
	}
	close(fd);
	printf("TMPFS_STATFS_FSTATFS path=%s\n", path);
	if (strcmp(path, "/dev/shm") != 0)
		return 0;

	fd = mkstemp(marker);
	if (fd < 0) {
		perror("mkstemp(/dev/shm)");
		return 6;
	}
	if (write(fd, "x", 1) != 1) {
		perror("write(/dev/shm)");
		close(fd);
		unlink(marker);
		return 7;
	}
	if (close(fd) < 0 || unlink(marker) < 0) {
		perror("cleanup(/dev/shm)");
		return 8;
	}
	printf("DEV_SHM=tmpfs,writable\n");
	return 0;
}

static int probe_legacy_binder(const char *path)
{
	struct binder_version version = { .protocol_version = -1 };
	int binder;

	binder = open(path, O_RDONLY | O_CLOEXEC);
	if (binder < 0) {
		perror(path);
		return 1;
	}
	if (ioctl(binder, BINDER_VERSION, &version) < 0) {
		fprintf(stderr, "%s: ", path);
		perror("BINDER_VERSION");
		close(binder);
		return 2;
	}
	close(binder);
	if (version.protocol_version != 8) {
		fprintf(stderr, "%s: unexpected Binder protocol version %d\n",
			path, version.protocol_version);
		return 3;
	}
	printf("LEGACY_BINDER path=%s version=%d\n", path,
		version.protocol_version);
	return 0;
}

static int run_probe(void)
{
	struct binderfs_device device = { .name = "binder" };
	struct binder_version version = { .protocol_version = -1 };
	struct binder_write_read bwr = { 0 };
	int control, binder;
	int status;

	status = probe_tmpfs_path("/dev/shm");
	if (status != 0)
		return 14;
	status = probe_tmpfs_path("/dev/__properties__");
	if (status != 0)
		return 15;

	if (probe_legacy_binder("/dev/binder") != 0 ||
	    probe_legacy_binder("/dev/hwbinder") != 0 ||
	    probe_legacy_binder("/dev/vndbinder") != 0)
		return 8;
	binder = open("/dev/binderfs/binder", O_RDONLY | O_CLOEXEC);
	if (binder >= 0) {
		close(binder);
		fprintf(stderr, "unallocated BinderFS node unexpectedly opened\n");
		return 9;
	}
	if (errno != ENOENT) {
		perror("open unallocated BinderFS node");
		return 10;
	}
	printf("BINDERFS_PREALLOCATION=ENOENT\n");

	control = open("/dev/binder-control", O_RDONLY | O_CLOEXEC);
	if (control < 0) {
		perror("open binder-control");
		return 1;
	}
	if (ioctl(control, BINDER_CTL_ADD, &device) < 0) {
		perror("BINDER_CTL_ADD");
		return 2;
	}
	printf("BINDER_CTL_ADD major=%u minor=%u\n", device.major, device.minor);

	binder = open("/dev/binderfs/binder", O_RDONLY | O_CLOEXEC);
	if (binder < 0) {
		perror("open allocated BinderFS node");
		return 11;
	}
	version.protocol_version = -1;
	if (ioctl(binder, BINDER_VERSION, &version) < 0) {
		perror("allocated BinderFS BINDER_VERSION");
		close(binder);
		return 12;
	}
	close(binder);
	if (version.protocol_version != 8) {
		fprintf(stderr, "unexpected BinderFS protocol version %d\n",
			version.protocol_version);
		return 13;
	}
	printf("BINDERFS_VERSION=%d\n", version.protocol_version);

	binder = open("/dev/binder", O_RDONLY | O_CLOEXEC);
	if (binder < 0) {
		perror("open binder");
		return 3;
	}
	if (ioctl(binder, BINDER_VERSION, &version) < 0) {
		perror("BINDER_VERSION");
		return 4;
	}
	if (version.protocol_version != 8) {
		fprintf(stderr, "unexpected Binder protocol version %d\n", version.protocol_version);
		return 5;
	}
	printf("BINDER_VERSION=%d\n", version.protocol_version);

	if (ioctl(binder, BINDER_WRITE_READ, &bwr) < 0) {
		perror("empty BINDER_WRITE_READ");
		return 6;
	}
	printf("BINDER_WRITE_READ write=%llu read=%llu\n",
	       (unsigned long long)bwr.write_consumed,
	       (unsigned long long)bwr.read_consumed);
	close(binder);
	close(control);
	return 0;
}

static void *thread_probe(void *unused)
{
	(void) unused;
	return (void *)(intptr_t) run_probe();
}

int main(int argc, char **argv)
{
	if (argc > 1 && strcmp(argv[1], "threaded") == 0) {
		pthread_t thread;
		void *status;
		if (pthread_create(&thread, NULL, thread_probe, NULL) != 0 ||
		    pthread_join(thread, &status) != 0) {
			perror("pthread create/join");
			return 7;
		}
		return (int)(intptr_t)status;
	}
	return run_probe();
}
