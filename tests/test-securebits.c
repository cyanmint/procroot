#include <errno.h>
#include <stdio.h>
#include <sys/prctl.h>
#include <linux/securebits.h>

int main(void)
{
	int initial;
	int actual;
	unsigned long requested;

	initial = prctl(PR_GET_SECUREBITS, 0, 0, 0, 0);
	if (initial < 0) {
		perror("prctl(PR_GET_SECUREBITS)");
		return 1;
	}

	requested = (unsigned long) initial | SECBIT_KEEP_CAPS |
		SECBIT_KEEP_CAPS_LOCKED;
	if (prctl(PR_SET_SECUREBITS, requested, 0, 0, 0) < 0) {
		perror("prctl(PR_SET_SECUREBITS)");
		return 2;
	}

	actual = prctl(PR_GET_SECUREBITS, 0, 0, 0, 0);
	if (actual < 0) {
		perror("prctl(PR_GET_SECUREBITS) after set");
		return 3;
	}
	if ((unsigned long) actual != requested) {
		fprintf(stderr, "securebits mismatch: expected %#lx got %#x\n",
			requested, actual);
		return 4;
	}
	if (prctl(PR_GET_KEEPCAPS, 0, 0, 0, 0) != 1) {
		fprintf(stderr, "PR_GET_KEEPCAPS did not reflect SECBIT_KEEP_CAPS\n");
		return 5;
	}

	errno = 0;
	if (prctl(PR_SET_SECUREBITS, requested & ~SECBIT_KEEP_CAPS,
		  0, 0, 0) != -1 || errno != EPERM) {
		fprintf(stderr, "locked securebit change did not fail with EPERM\n");
		return 6;
	}

	errno = 0;
	if (prctl(PR_SET_KEEPCAPS, 0, 0, 0, 0) != -1 || errno != EPERM) {
		fprintf(stderr, "locked PR_SET_KEEPCAPS change did not fail with EPERM\n");
		return 7;
	}

	printf("securebits emulation passed: %#lx\n", requested);
	return 0;
}
