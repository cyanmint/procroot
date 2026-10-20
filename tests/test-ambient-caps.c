#define _GNU_SOURCE
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <linux/capability.h>
#include <linux/prctl.h>

static int set_cap_chown(uint32_t permitted, uint32_t inheritable)
{
	struct __user_cap_header_struct header = {
		.version = _LINUX_CAPABILITY_VERSION_3,
		.pid = 0,
	};
	struct __user_cap_data_struct data[_LINUX_CAPABILITY_U32S_3] = {{0}};
	uint32_t mask = 1U << (CAP_CHOWN % 32);
	unsigned int word = CAP_CHOWN / 32;

	data[word].permitted = permitted ? mask : 0;
	data[word].inheritable = inheritable ? mask : 0;
	return syscall(SYS_capset, &header, data);
}

int main(void)
{
	if (set_cap_chown(1, 0) < 0) {
		perror("capset(permitted only)");
		return 1;
	}
	errno = 0;
	if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, CAP_CHOWN, 0, 0) != -1 ||
	    errno != EPERM) {
		fprintf(stderr, "ambient raise without inheritable cap did not fail EPERM\n");
		return 2;
	}

	if (set_cap_chown(1, 1) < 0) {
		perror("capset(permitted and inheritable)");
		return 3;
	}
	if (setresuid(9999, 9999, 9999) < 0) {
		perror("setresuid");
		return 4;
	}
	if (set_cap_chown(1, 1) < 0) {
		perror("capset after uid drop");
		return 5;
	}
	if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, CAP_CHOWN, 0, 0) < 0) {
		perror("PR_CAP_AMBIENT_RAISE");
		return 6;
	}
	if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_IS_SET, CAP_CHOWN, 0, 0) != 1) {
		fprintf(stderr, "ambient capability was not recorded\n");
		return 7;
	}
	if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_LOWER, CAP_CHOWN, 0, 0) < 0 ||
	    prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_IS_SET, CAP_CHOWN, 0, 0) != 0) {
		fprintf(stderr, "ambient lower did not clear capability\n");
		return 8;
	}
	if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, CAP_CHOWN, 0, 0) < 0 ||
	    prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0) < 0 ||
	    prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_IS_SET, CAP_CHOWN, 0, 0) != 0) {
		fprintf(stderr, "ambient clear-all did not clear capability\n");
		return 9;
	}

	puts("AMBIENT_CAPABILITY_EMULATION=PASS");
	return 0;
}
