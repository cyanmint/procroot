#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include <sys/ioctl.h>
#include <unistd.h>

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

static int run_probe(void)
{
	struct binderfs_device device = { .name = "binder" };
	struct binder_version version = { .protocol_version = -1 };
	struct binder_write_read bwr = { 0 };
	int control, binder;

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
