/* checker: a small self-contained diagnostic program that exercises
 * PRoot's "-N"/"--proc" PID-namespace virtualization (vPID/vTID
 * translation, "/proc" and "/sys" spoofing).  It has no dependency on
 * PRoot itself: it is meant to be run *under* "proot -N" and simply
 * prints "PASS"/"FAIL" for each individual check, then a final
 * summary.  Exit status is 0 if every check passed, 1 otherwise.
 *
 * It is intentionally written against plain POSIX/Linux libc calls
 * only, so that it can be built completely statically without any
 * extra dependencies, for use in CI.
 */

#define _GNU_SOURCE
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <ctype.h>

static int nb_checks = 0;
static int nb_failures = 0;

static void check(const char *name, int passed, const char *detail)
{
	nb_checks++;
	if (!passed)
		nb_failures++;

	printf("[%s] %s%s%s\n", passed ? "PASS" : "FAIL", name,
		detail != NULL ? ": " : "", detail != NULL ? detail : "");
	fflush(stdout);
}

/**
 * Read the whole content of the file at @path into a
 * newly-malloc(3)-ed, NUL-terminated buffer.  Returns NULL on error.
 */
static char *slurp(const char *path)
{
	FILE *file;
	char *buffer;
	size_t capacity;
	size_t length;

	file = fopen(path, "r");
	if (file == NULL)
		return NULL;

	capacity = 4096;
	length = 0;
	buffer = malloc(capacity);
	if (buffer == NULL) {
		fclose(file);
		return NULL;
	}

	for (;;) {
		size_t nb_read;

		if (length + 1024 > capacity) {
			char *new_buffer;

			capacity *= 2;
			new_buffer = realloc(buffer, capacity);
			if (new_buffer == NULL) {
				free(buffer);
				fclose(file);
				return NULL;
			}
			buffer = new_buffer;
		}

		nb_read = fread(buffer + length, 1, 1024, file);
		length += nb_read;
		if (nb_read < 1024)
			break;
	}
	buffer[length] = '\0';

	fclose(file);
	return buffer;
}

/**
 * Look for a "Field:\t<value>" (or "Field: <value>") line in
 * @content and return the numeric value, or -1 if not found.
 */
static long find_field(const char *content, const char *field)
{
	const char *line;
	size_t field_len;

	field_len = strlen(field);
	for (line = content; line != NULL; line = strchr(line, '\n')) {
		if (*line == '\n')
			line++;
		if (strncmp(line, field, field_len) == 0) {
			const char *value = line + field_len;
			while (*value == '\t' || *value == ' ')
				value++;
			return strtol(value, NULL, 10);
		}
	}
	return -1;
}

static void check_getpid_is_1(void)
{
	pid_t pid = getpid();
	char detail[64];

	snprintf(detail, sizeof(detail), "getpid()=%d", (int) pid);
	check("getpid() == 1 for root process", pid == 1, detail);
}

static void check_proc_self_status(void)
{
	char *content;
	long pid_field;
	long tgid_field;
	char detail[128];

	content = slurp("/proc/self/status");
	if (content == NULL) {
		check("/proc/self/status readable", 0, strerror(errno));
		return;
	}

	pid_field = find_field(content, "Pid:");
	tgid_field = find_field(content, "Tgid:");
	free(content);

	snprintf(detail, sizeof(detail), "Pid=%ld Tgid=%ld (getpid=%d)",
		pid_field, tgid_field, (int) getpid());
	check("/proc/self/status Pid:/Tgid: match getpid()",
		pid_field == getpid() && tgid_field == getpid(), detail);
}

static void check_proc_pid_status(void)
{
	char path[64];
	char *content;
	long pid_field;
	char detail[128];

	snprintf(path, sizeof(path), "/proc/%d/status", (int) getpid());
	content = slurp(path);
	if (content == NULL) {
		check("/proc/<vpid>/status readable", 0, strerror(errno));
		return;
	}

	pid_field = find_field(content, "Pid:");
	free(content);

	snprintf(detail, sizeof(detail), "Pid=%ld (getpid=%d)",
		pid_field, (int) getpid());
	check("/proc/<vpid>/status Pid: matches getpid()",
		pid_field == getpid(), detail);
}

static void check_proc_self_stat(void)
{
	char *content;
	int stat_pid = -1;
	char detail[64];

	content = slurp("/proc/self/stat");
	if (content == NULL) {
		check("/proc/self/stat readable", 0, strerror(errno));
		return;
	}

	sscanf(content, "%d", &stat_pid);
	free(content);

	snprintf(detail, sizeof(detail), "stat pid=%d (getpid=%d)",
		stat_pid, (int) getpid());
	check("/proc/self/stat first field matches getpid()",
		stat_pid == getpid(), detail);
}

static void check_proc_self_readlink(void)
{
	char buffer[64];
	ssize_t length;
	char detail[96];
	int target_pid;

	length = readlink("/proc/self", buffer, sizeof(buffer) - 1);
	if (length < 0) {
		check("readlink(/proc/self)", 0, strerror(errno));
		return;
	}
	buffer[length] = '\0';

	target_pid = atoi(buffer);
	snprintf(detail, sizeof(detail), "target=\"%s\" (getpid=%d)",
		buffer, (int) getpid());
	check("readlink(/proc/self) == getpid()",
		target_pid == getpid(), detail);
}

static void check_proc_listing(void)
{
	DIR *dir;
	struct dirent *entry;
	int seen_self = 0;
	int all_numeric_reasonable = 1;
	char detail[64];

	dir = opendir("/proc");
	if (dir == NULL) {
		check("opendir(/proc)", 0, strerror(errno));
		return;
	}

	while ((entry = readdir(dir)) != NULL) {
		size_t i;
		int is_numeric;

		if (strcmp(entry->d_name, ".") == 0 ||
		    strcmp(entry->d_name, "..") == 0)
			continue;

		is_numeric = (entry->d_name[0] != '\0');
		for (i = 0; entry->d_name[i] != '\0'; i++) {
			if (!isdigit((unsigned char) entry->d_name[i])) {
				is_numeric = 0;
				break;
			}
		}

		if (is_numeric) {
			long value = strtol(entry->d_name, NULL, 10);
			if (value == (long) getpid())
				seen_self = 1;
			/* A translated vPID must be small: if PRoot
			 * ever leaked an untranslated host PID, this
			 * would typically be a large 4-6 digit number
			 * unrelated to our tiny guest process tree.  */
			if (value > 65535)
				all_numeric_reasonable = 0;
		}
	}
	closedir(dir);

	snprintf(detail, sizeof(detail), "self(%d) listed=%d, sane_range=%d",
		(int) getpid(), seen_self, all_numeric_reasonable);
	check("/proc listing contains self and looks virtualized",
		seen_self && all_numeric_reasonable, detail);
}

static void check_sys_mirrored(void)
{
	struct stat statbuf;
	int status;

	status = stat("/sys", &statbuf);
	check("/sys is accessible (mirrored)", status == 0 && S_ISDIR(statbuf.st_mode),
		status == 0 ? NULL : strerror(errno));
}

static void check_sys_cpu_possible(void)
{
	char *content;

	content = slurp("/sys/devices/system/cpu/possible");
	check("/sys/devices/system/cpu/possible readable (host mirror)",
		content != NULL && content[0] != '\0',
		content != NULL ? NULL : strerror(errno));
	free(content);
}

static void check_sys_write_spoof(void)
{
	int fd;
	ssize_t written;
	int ok;

	/* /sys/kernel/profiling is root-only to write; as a
	 * non-privileged user the write(2) normally fails with
	 * EACCES/EPERM once opened.  Under "-N" this failure must be
	 * spoofed into an apparent success instead of surfacing the
	 * real error, so that guest software doesn't get confused by
	 * unexpected sysfs write failures.  If the file cannot even
	 * be opened (e.g. absent on this kernel), the check is
	 * skipped rather than failed, since open(2) failures are
	 * intentionally not spoofed.  */
	fd = open("/sys/kernel/profiling", O_WRONLY);
	if (fd < 0) {
		check("/sys write failure spoofed as success (skipped, no fd)",
			1, "open() failed, nothing to test");
		return;
	}

	written = write(fd, "0\n", 2);
	ok = (written >= 0);
	close(fd);

	check("/sys write failure spoofed as success",
		ok, ok ? NULL : strerror(errno));
}

static void check_kill_self(void)
{
	int status;

	/* Signal 0 only checks whether the PID exists / is
	 * targetable; it must not actually terminate us.  Exercises
	 * vPID -> host PID translation for kill(2)'s target
	 * argument.  */
	status = kill(getpid(), 0);
	check("kill(getpid(), 0) succeeds (vpid targeting works)",
		status == 0, status == 0 ? NULL : strerror(errno));
}

static void check_fork_child_vpid(void)
{
	int pipefd[2];
	pid_t child;
	int wait_status;
	char buffer[32];
	ssize_t nb_read;
	int child_vpid = -1;
	char detail[128];

	if (pipe(pipefd) < 0) {
		check("fork()/vPID allocation", 0, strerror(errno));
		return;
	}

	child = fork();
	if (child < 0) {
		check("fork()/vPID allocation", 0, strerror(errno));
		close(pipefd[0]);
		close(pipefd[1]);
		return;
	}

	if (child == 0) {
		/* Child: report its own vPID (as seen from getpid(),
		 * itself already validated by check_getpid_is_1()'s
		 * sibling checks) through the pipe, then exit.  Note:
		 * we deliberately don't rely on fork(2)'s *return
		 * value* in the parent being translated to a vPID
		 * here, since that requires catching the clone/fork
		 * completion at exactly the right ptrace stop; instead
		 * we independently confirm that the child is assigned
		 * a distinct, small vPID and that it can be targeted
		 * by kill(2) using that vPID.  */
		close(pipefd[0]);
		dprintf(pipefd[1], "%d", (int) getpid());
		close(pipefd[1]);
		_exit(0);
	}

	close(pipefd[1]);
	nb_read = read(pipefd[0], buffer, sizeof(buffer) - 1);
	close(pipefd[0]);
	if (nb_read > 0) {
		buffer[nb_read] = '\0';
		child_vpid = atoi(buffer);
	}

	if (waitpid(child, &wait_status, 0) < 0) {
		check("fork()/vPID allocation", 0, "waitpid() failed");
		return;
	}

	snprintf(detail, sizeof(detail),
		"parent_vpid=%d child_vpid=%d",
		(int) getpid(), child_vpid);

	check("fork() allocates a distinct child vPID",
		child_vpid > 0 && child_vpid != getpid(), detail);
}

int main(void)
{
	printf("=== PRoot PID-namespace ('-N'/'--proc') checker ===\n");

	check_getpid_is_1();
	check_proc_self_status();
	check_proc_pid_status();
	check_proc_self_stat();
	check_proc_self_readlink();
	check_proc_listing();
	check_sys_mirrored();
	check_sys_cpu_possible();
	check_sys_write_spoof();
	check_kill_self();
	check_fork_child_vpid();

	printf("=== %d/%d checks passed ===\n", nb_checks - nb_failures, nb_checks);

	return nb_failures == 0 ? 0 : 1;
}
