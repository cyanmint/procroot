/* -*- c-set-style: "K&R"; c-basic-offset: 8 -*-
 *
 * This file is part of PRoot.
 *
 * User-space PID namespace virtualization, enabled with "-N" /
 * "--proc".  The initial guest process always appears as vPID 1 and
 * every other guest process/thread gets a small, sequential vPID
 * allocated in creation order (see @Tracee::vpid in tracee/tracee.c).
 *
 * This extension is responsible for:
 *   - translating PID-retrieval syscalls (getpid, getppid, gettid,
 *     getpgid, getsid) from host PID to vPID at sys-exit;
 *   - translating PID-targeting syscalls (kill, tgkill, tkill,
 *     ptrace, sched_{set,get}affinity) from vPID to host PID at
 *     sys-enter;
 *   - patching back the vPID/vTID into CLONE_PARENT_SETTID /
 *     CLONE_CHILD_SETTID target addresses;
 *   - virtualizing /proc: rewriting "/proc/<vpid>/..." guest accesses
 *     to "/proc/<host_pid>/...", filtering and renaming entries
 *     returned by getdents64() on the "/proc" directory, and patching
 *     the PID fields found in "status"/"stat" file contents.
 */

#include <string.h>      /* str*(3), mem*(3), */
#include <stdlib.h>      /* atoll(3), strtoll(3), */
#include <stdio.h>       /* snprintf(3), */
#include <errno.h>       /* E*, */
#include <ctype.h>       /* isdigit(3), */
#include <inttypes.h>    /* PRIu64, */
#include <fcntl.h>       /* O_*, AT_FDCWD, */
#include <linux/sched.h> /* CLONE_*, */

#include "extension/extension.h"
#include "extension/pid_virt/pid_virt.h"
#include "syscall/syscall.h"
#include "syscall/sysnum.h"
#include "syscall/chain.h"
#include "tracee/tracee.h"
#include "tracee/reg.h"
#include "tracee/mem.h"
#include "path/path.h"
#include "path/binding.h"
#include "cli/note.h"
#include "attribute.h"
#include "arch.h"
#include "syscall/seccomp.h"

/* List of syscalls this extension needs to see at sys-exit.  */
static FilteredSysnum filtered_sysnums[] = {
	{ PR_getpid,		FILTER_SYSEXIT },
	{ PR_getppid,		FILTER_SYSEXIT },
	{ PR_gettid,		FILTER_SYSEXIT },
	{ PR_getpgid,		FILTER_SYSEXIT },
	{ PR_getsid,		FILTER_SYSEXIT },
	{ PR_kill,		0 },
	{ PR_tgkill,		0 },
	{ PR_tkill,		0 },
	{ PR_ptrace,		0 },
	{ PR_sched_setaffinity,	0 },
	{ PR_sched_getaffinity,	0 },
	{ PR_getdents64,	FILTER_SYSEXIT },
	{ PR_read,		FILTER_SYSEXIT },
	{ PR_readlink,		FILTER_SYSEXIT },
	{ PR_readlinkat,	FILTER_SYSEXIT },
	{ PR_openat,		FILTER_SYSEXIT },
	{ PR_open,		FILTER_SYSEXIT },
	{ PR_close,		0 },
	{ PR_clone,		0 },
	{ PR_clone3,		0 },
	{ PR_fork,		0 },
	{ PR_vfork,		0 },
	/* /sys write-failure spoofing: report success without doing
	 * anything when these fail while targeting "/sys".  */
	{ PR_write,		FILTER_SYSEXIT },
	{ PR_pwrite64,		FILTER_SYSEXIT },
	{ PR_pwritev,		FILTER_SYSEXIT },
	{ PR_pwritev2,		FILTER_SYSEXIT },
	{ PR_writev,		FILTER_SYSEXIT },
	{ PR_ioctl,		FILTER_SYSEXIT },
	{ PR_chmod,		FILTER_SYSEXIT },
	{ PR_fchmod,		FILTER_SYSEXIT },
	{ PR_fchmodat,		FILTER_SYSEXIT },
	{ PR_chown,		FILTER_SYSEXIT },
	{ PR_chown32,		FILTER_SYSEXIT },
	{ PR_fchown,		FILTER_SYSEXIT },
	{ PR_fchown32,		FILTER_SYSEXIT },
	{ PR_fchownat,		FILTER_SYSEXIT },
	{ PR_lchown,		FILTER_SYSEXIT },
	{ PR_lchown32,		FILTER_SYSEXIT },
	{ PR_truncate,		FILTER_SYSEXIT },
	{ PR_truncate64,	FILTER_SYSEXIT },
	{ PR_ftruncate,		FILTER_SYSEXIT },
	{ PR_ftruncate64,	FILTER_SYSEXIT },
	{ PR_utimensat,		FILTER_SYSEXIT },
	{ PR_utimes,		FILTER_SYSEXIT },
	{ PR_futimesat,		FILTER_SYSEXIT },
	{ PR_mkdir,		FILTER_SYSEXIT },
	{ PR_mkdirat,		FILTER_SYSEXIT },
	{ PR_mknod,		FILTER_SYSEXIT },
	{ PR_mknodat,		FILTER_SYSEXIT },
	{ PR_unlink,		FILTER_SYSEXIT },
	{ PR_unlinkat,		FILTER_SYSEXIT },
	{ PR_rename,		FILTER_SYSEXIT },
	{ PR_renameat,		FILTER_SYSEXIT },
	{ PR_renameat2,		FILTER_SYSEXIT },
	{ PR_symlink,		FILTER_SYSEXIT },
	{ PR_symlinkat,		FILTER_SYSEXIT },
	{ PR_setxattr,		FILTER_SYSEXIT },
	{ PR_lsetxattr,		FILTER_SYSEXIT },
	{ PR_fsetxattr,		FILTER_SYSEXIT },
	FILTERED_SYSNUM_END,
};

/* Number of file descriptors we track per tracee for /proc content
 * virtualization (directory listing + status/stat file patching).  */
#define MAX_TRACKED_FDS 32

typedef enum {
	PROC_FD_NONE = 0,
	PROC_FD_ROOT,    /* fd opened on "/proc" itself (getdents64).  */
	PROC_FD_STATUS,  /* fd opened on "/proc/<pid>/status".         */
	PROC_FD_STAT,    /* fd opened on "/proc/<pid>/stat".           */
	PROC_FD_STATM,   /* fd opened on "/proc/<pid>/statm".          */
	SYS_FD_GENERIC,  /* fd opened somewhere under "/sys".          */
} ProcFdKind;

typedef struct {
	int fd;
	pid_t host_pid; /* Meaningful for STATUS/STAT/STATM only.  */
	ProcFdKind kind;
} TrackedFd;

typedef struct {
	/* vPID of the thread-group leader, i.e. what getpid() returns.  */
	uint64_t tgid_vpid;

	/* vPID of the parent process, i.e. what getppid() returns.
	 * 0 for the initial guest process (like a real init).  */
	uint64_t ppid_vpid;

	TrackedFd fds[MAX_TRACKED_FDS];

	/* Scratch state filled in by the GUEST_PATH handler and
	 * consumed right after by the SYSCALL_EXIT_END handler for
	 * open(at)(2), to remember what kind of /proc entry was just
	 * opened.  */
	bool last_path_is_proc;
	bool last_path_is_root;
	pid_t last_path_host_pid;
	char last_path_leaf[32];

	/* Set by the GUEST_PATH handler when the just-translated path
	 * targets "/sys", consumed right after by the SYSCALL_EXIT_END
	 * handler for the same syscall (open(at)(2) fd tracking, or
	 * fail->success spoofing for metadata-only syscalls).  */
	bool last_path_is_sys;

	/* Set when the just-translated path is exactly "/proc/self"
	 * or "/proc/thread-self" (no further components): their
	 * readlink(2) target is a host PID (and, for thread-self, a
	 * host TID) that must be patched back to the vPID/vTID.  */
	bool last_path_is_self;

	/* Set right after an open(at)(2) targeting "/sys" (or a
	 * non-PID "/proc" entry) that failed at open() time was
	 * transparently redirected to a fake, always-openable file;
	 * consumed by the SYSCALL_CHAINED_EXIT handler to finish the
	 * fd-tracking spoofing.  */
	bool open_redirect_pending;

	/* Address, in the tracee's memory, of a pre-written
	 * FAKE_OPEN_TARGET path, reserved at sysenter (see
	 * prepare_open_redirect_target()) for a possible open() failure
	 * spoofing at sysexit; 0 if none was reserved for the current
	 * syscall.  */
	word_t open_redirect_target_addr;
} Config;

/**
 * Return true if a pending binding targets the host "/proc" or
 * "/sys" directory, which conflicts with "-N"/"--proc" (PID/sysfs
 * virtualization replaces standard bind-mounting for both).
 */
bool pid_virt_binding_conflicts(Tracee *tracee)
{
	Binding *binding;

	if (tracee->fs->bindings.pending == NULL)
		return false;

	CIRCLEQ_FOREACH(binding, tracee->fs->bindings.pending, link.pending) {
		if (strcmp(binding->host.path, "/proc") == 0
		    || strcmp(binding->host.path, "/sys") == 0)
			return true;
	}

	return false;
}

static void reset_last_path(Config *config)
{
	config->last_path_is_proc = false;
	config->last_path_is_root = false;
	config->last_path_host_pid = 0;
	config->last_path_leaf[0] = '\0';
	config->last_path_is_sys = false;
	config->last_path_is_self = false;
}

static TrackedFd *find_tracked_fd(Config *config, int fd)
{
	int i;

	for (i = 0; i < MAX_TRACKED_FDS; i++) {
		if (config->fds[i].kind != PROC_FD_NONE && config->fds[i].fd == fd)
			return &config->fds[i];
	}

	return NULL;
}

static void track_fd(Config *config, int fd, pid_t host_pid, ProcFdKind kind)
{
	int i;
	int free_slot = -1;

	for (i = 0; i < MAX_TRACKED_FDS; i++) {
		if (config->fds[i].kind != PROC_FD_NONE && config->fds[i].fd == fd) {
			free_slot = i;
			break;
		}
		if (free_slot < 0 && config->fds[i].kind == PROC_FD_NONE)
			free_slot = i;
	}

	if (free_slot < 0)
		return; /* Table full, silently drop tracking.  */

	config->fds[free_slot].fd = fd;
	config->fds[free_slot].host_pid = host_pid;
	config->fds[free_slot].kind = kind;
}

static void untrack_fd(Config *config, int fd)
{
	int i;

	for (i = 0; i < MAX_TRACKED_FDS; i++) {
		if (config->fds[i].kind != PROC_FD_NONE && config->fds[i].fd == fd) {
			config->fds[i].kind = PROC_FD_NONE;
			return;
		}
	}
}

/**
 * Rewrite a guest path targeting "/proc" so that it is directly
 * usable on the host, translating any leading "/proc/<vpid>"
 * component into "/proc/<host_pid>".  @full is the absolute,
 * uncanonicalized guest path (may still contain a leading "/proc").
 * Returns 1 if @full was a /proc path (in which case @result was
 * filled in), 0 if it isn't a /proc path, or a negative errno.
 */
static int rewrite_proc_path(Tracee *tracee UNUSED, Config *config,
			char result[PATH_MAX], const char *full)
{
	const char *rest;
	const char *slash;
	char component[NAME_MAX + 1];
	size_t complen;
	pid_t host_pid = 0;
	bool is_root = false;
	bool is_self = false;
	const char *leaf = "";

	if (strcmp(full, "/proc") == 0) {
		strcpy(result, "/proc");
		is_root = true;
		goto done;
	}

	if (strncmp(full, "/proc/", 6) != 0)
		return 0;

	rest = full + 6;
	slash = strchr(rest, '/');
	complen = slash != NULL ? (size_t) (slash - rest) : strlen(rest);
	if (complen == 0 || complen > NAME_MAX)
		return 0;

	memcpy(component, rest, complen);
	component[complen] = '\0';
	leaf = slash != NULL ? slash + 1 : "";

	if (strcmp(component, "self") == 0 || strcmp(component, "thread-self") == 0) {
		/* Resolved directly by the host kernel with respect to
		 * the tracee performing the real syscall: nothing to
		 * translate.  Still PID-related (e.g. "status"/"stat"
		 * content patching applies), so not treated as a plain
		 * mirrored/spoofed "/sys"-like entry.  */
		strcpy(result, full);
		is_self = true;
		goto done;
	}

	if (complen > 0 && strspn(component, "0123456789") == complen) {
		uint64_t vpid;
		Tracee *target;
		int status;

		vpid = strtoull(component, NULL, 10);
		target = get_tracee_by_vpid(vpid);
		if (target == NULL)
			return -ENOENT;

		host_pid = target->pid;
		status = snprintf(result, PATH_MAX, "/proc/%d%s%s",
				host_pid, leaf[0] != '\0' ? "/" : "", leaf);
		if (status < 0 || status >= PATH_MAX)
			return -ENAMETOOLONG;
		goto done;
	}

	/* Not a PID entry (e.g. /proc/cpuinfo, /proc/self/...
	 * already handled above): pass it through unchanged, just
	 * bypassing the (possibly nonexistent) guest binding.  */
	strcpy(result, full);

done:
	config->last_path_is_proc = true;
	config->last_path_is_root = is_root;
	config->last_path_host_pid = host_pid;
	strncpy(config->last_path_leaf, leaf, sizeof(config->last_path_leaf) - 1);
	config->last_path_leaf[sizeof(config->last_path_leaf) - 1] = '\0';

	/* Only the bare "/proc/self" or "/proc/thread-self" symlinks
	 * themselves have a PID-shaped readlink(2) target; anything
	 * under them (e.g. "/proc/self/fd/3") doesn't.  */
	config->last_path_is_self = is_self && leaf[0] == '\0';

	/* Non-PID "/proc" entries (e.g. "/proc/cpuinfo", "/proc/sys/...",
	 * "/proc/version") aren't part of PID virtualization proper:
	 * just like "/sys", mirror the host content as-is and spoof
	 * failures as successful no-ops.  */
	if (!is_root && !is_self && host_pid == 0)
		config->last_path_is_sys = true;

	return 1;
}

/**
 * Mirror a guest path targeting "/sys" directly onto the host "/sys"
 * (no component translation is needed there, unlike "/proc"), always
 * bypassing PRoot's normal binding/canonicalization so that "-N"
 * transparently mirrors the host sysfs tree.  Returns 1 if @full is
 * a /sys path (@result is filled in), 0 otherwise.
 */
static int rewrite_sys_path(Tracee *tracee UNUSED, Config *config,
			char result[PATH_MAX], const char *full)
{
	if (strcmp(full, "/sys") != 0 && strncmp(full, "/sys/", 5) != 0)
		return 0;

	strcpy(result, full);
	config->last_path_is_sys = true;
	return 1;
}

static int handle_guest_path(Tracee *tracee, Config *config,
			char result[PATH_MAX], const char *user_path)
{
	char full[PATH_MAX];
	int status;

	reset_last_path(config);

	status = join_paths(2, full, result, user_path);
	if (status < 0)
		return 0; /* Let PRoot's own handling deal with the error.  */

	status = rewrite_proc_path(tracee, config, result, full);
	if (status != 0)
		return status;

	return rewrite_sys_path(tracee, config, result, full);
}

/**
 * Translate the @reg argument of the current syscall of @tracee from
 * a vPID to the corresponding host PID.  Values <= 0 are left
 * untouched (they don't designate a single vPID).
 */
static void translate_vpid_arg(Tracee *tracee, Reg reg)
{
	word_t value;
	int64_t svalue;
	Tracee *target;

	value = peek_reg(tracee, CURRENT, reg);
	svalue = (int64_t) value;

	if (svalue <= 0)
		return;

	target = get_tracee_by_vpid((uint64_t) svalue);
	if (target == NULL)
		return;

	poke_reg(tracee, reg, (word_t) target->pid);
}

static int handle_sysenter(Tracee *tracee)
{
	Sysnum sysnum = get_sysnum(tracee, ORIGINAL);

	switch (sysnum) {
	case PR_kill:
	case PR_tkill:
		translate_vpid_arg(tracee, SYSARG_1);
		break;

	case PR_tgkill:
		translate_vpid_arg(tracee, SYSARG_1);
		translate_vpid_arg(tracee, SYSARG_2);
		break;

	case PR_ptrace:
		translate_vpid_arg(tracee, SYSARG_2);
		break;

	case PR_sched_setaffinity:
	case PR_sched_getaffinity:
		translate_vpid_arg(tracee, SYSARG_1);
		break;

	default:
		break;
	}

	return 0;
}

static uint64_t host_pid_to_vpid(pid_t pid)
{
	Tracee *target = get_tracee(NULL, pid, false);
	return target != NULL ? target->vpid : (uint64_t) pid;
}

static void handle_getdents64_exit(Tracee *tracee, Config *config)
{
	int fd;
	word_t buf_addr;
	int64_t result;
	char *inbuf, *outbuf;
	size_t total, in_off, out_off;

	if (peek_reg(tracee, CURRENT, SYSARG_RESULT) == (word_t) -1)
		return;

	fd = (int) peek_reg(tracee, ORIGINAL, SYSARG_1);
	if (find_tracked_fd(config, fd) == NULL
	    || find_tracked_fd(config, fd)->kind != PROC_FD_ROOT)
		return;

	result = (int64_t) peek_reg(tracee, CURRENT, SYSARG_RESULT);
	if (result <= 0)
		return;

	total = (size_t) result;
	buf_addr = peek_reg(tracee, ORIGINAL, SYSARG_2);

	inbuf = talloc_size(tracee->ctx, total);
	outbuf = talloc_size(tracee->ctx, total);
	if (inbuf == NULL || outbuf == NULL)
		goto out;

	if (read_data(tracee, inbuf, buf_addr, total) < 0)
		goto out;

	in_off = 0;
	out_off = 0;
	while (in_off + 19 <= total) {
		uint16_t reclen;
		uint8_t d_type;
		char *name;
		size_t namelen;

		memcpy(&reclen, inbuf + in_off + 16, sizeof(reclen));
		if (reclen < 19 || in_off + reclen > total)
			break;

		d_type = (uint8_t) inbuf[in_off + 18];
		name = inbuf + in_off + 19;
		namelen = strnlen(name, reclen - 19);

		if (namelen == 0 || strspn(name, "0123456789") != namelen) {
			/* Not a PID entry: copy it unchanged.  */
			memcpy(outbuf + out_off, inbuf + in_off, reclen);
			out_off += reclen;
		} else {
			pid_t host_pid = (pid_t) strtoul(name, NULL, 10);
			Tracee *target = get_tracee(tracee, host_pid, false);

			if (target == NULL) {
				/* Not part of the PRoot process tree:
				 * filter this entry out entirely.  */
			} else {
				char new_name[32];
				size_t new_len;
				size_t avail = reclen - 19;

				snprintf(new_name, sizeof(new_name), "%" PRIu64, target->vpid);
				new_len = strlen(new_name);

				memcpy(outbuf + out_off, inbuf + in_off, 19);
				if (new_len + 1 <= avail) {
					memset(outbuf + out_off + 19, 0, avail);
					memcpy(outbuf + out_off + 19, new_name, new_len);
				} else {
					/* Extremely unlikely (vpid needs
					 * more digits than the host pid):
					 * keep the original name.  */
					memcpy(outbuf + out_off + 19, name, avail);
				}
				(void) d_type;
				out_off += reclen;
			}
		}

		in_off += reclen;
	}

	if (out_off != total) {
		if (write_data(tracee, buf_addr, outbuf, out_off) == 0)
			poke_reg(tracee, SYSARG_RESULT, (word_t) out_off);
	}

out:
	TALLOC_FREE(inbuf);
	TALLOC_FREE(outbuf);
}

/**
 * Replace, in @buf (of length @len), every whole decimal number that
 * matches a host PID known to PRoot with the equivalent vPID.  The
 * result (which may be shorter than @len, never longer) is stored
 * into @out and its length into @out_len.
 */
static void patch_pid_tokens(Tracee *tracee UNUSED, const char *buf, size_t len,
			char *out, size_t *out_len)
{
	size_t i = 0, o = 0;

	while (i < len) {
		if (isdigit((unsigned char) buf[i])
		    && (i == 0 || !isalnum((unsigned char) buf[i - 1]))) {
			size_t start = i;
			size_t numlen;
			char numbuf[24];

			while (i < len && isdigit((unsigned char) buf[i]) && i - start < sizeof(numbuf) - 1)
				i++;
			numlen = i - start;
			/* Only substitute if not immediately followed by
			 * another alnum char (i.e. it really is a whole
			 * token, not truncated by our buffer size).  */
			if (i < len && isalnum((unsigned char) buf[i])) {
				memcpy(out + o, buf + start, numlen);
				o += numlen;
				continue;
			}

			memcpy(numbuf, buf + start, numlen);
			numbuf[numlen] = '\0';

			{
				pid_t host_pid = (pid_t) strtoul(numbuf, NULL, 10);
				Tracee *target = (host_pid > 0) ? get_tracee(tracee, host_pid, false) : NULL;

				if (target != NULL) {
					int written = snprintf(out + o, 24, "%" PRIu64, target->vpid);
					o += (size_t) written;
				} else {
					memcpy(out + o, numbuf, numlen);
					o += numlen;
				}
			}
			continue;
		}

		out[o++] = buf[i++];
	}

	*out_len = o;
}

static void handle_read_exit(Tracee *tracee, Config *config)
{
	int fd;
	TrackedFd *tracked;
	word_t buf_addr;
	int64_t result;
	char *inbuf, *outbuf;
	size_t out_len;

	if (peek_reg(tracee, CURRENT, SYSARG_RESULT) == (word_t) -1)
		return;

	fd = (int) peek_reg(tracee, ORIGINAL, SYSARG_1);
	tracked = find_tracked_fd(config, fd);
	if (tracked == NULL
	    || (tracked->kind != PROC_FD_STATUS && tracked->kind != PROC_FD_STAT))
		return;

	result = (int64_t) peek_reg(tracee, CURRENT, SYSARG_RESULT);
	if (result <= 0)
		return;

	buf_addr = peek_reg(tracee, ORIGINAL, SYSARG_2);

	inbuf = talloc_size(tracee->ctx, (size_t) result);
	outbuf = talloc_size(tracee->ctx, (size_t) result + 64);
	if (inbuf == NULL || outbuf == NULL)
		goto out;

	if (read_data(tracee, inbuf, buf_addr, (size_t) result) < 0)
		goto out;

	patch_pid_tokens(tracee, inbuf, (size_t) result, outbuf, &out_len);

	if (out_len != (size_t) result) {
		if (write_data(tracee, buf_addr, outbuf, out_len) == 0)
			poke_reg(tracee, SYSARG_RESULT, (word_t) out_len);
	} else if (memcmp(inbuf, outbuf, out_len) != 0) {
		write_data(tracee, buf_addr, outbuf, out_len);
	}

out:
	TALLOC_FREE(inbuf);
	TALLOC_FREE(outbuf);
}

/**
 * Patch the readlink(2)/readlinkat(2) target of "/proc/self" or
 * "/proc/thread-self" (the only two "/proc" symlinks with a
 * PID-shaped target) from host PID/TID to vPID/vTID.
 */
static void handle_readlink_exit(Tracee *tracee, Config *config, Sysnum sysnum)
{
	int64_t result;
	word_t buf_addr;
	char *inbuf, *outbuf;
	size_t out_len;

	if (!config->last_path_is_self)
		return;

	result = (int64_t) peek_reg(tracee, CURRENT, SYSARG_RESULT);
	if (result <= 0)
		return;

	buf_addr = (sysnum == PR_readlink)
		? peek_reg(tracee, ORIGINAL, SYSARG_2)
		: peek_reg(tracee, ORIGINAL, SYSARG_3);

	inbuf = talloc_size(tracee->ctx, (size_t) result);
	outbuf = talloc_size(tracee->ctx, (size_t) result + 64);
	if (inbuf == NULL || outbuf == NULL)
		goto out2;

	if (read_data(tracee, inbuf, buf_addr, (size_t) result) < 0)
		goto out2;

	patch_pid_tokens(tracee, inbuf, (size_t) result, outbuf, &out_len);

	if (out_len != (size_t) result || memcmp(inbuf, outbuf, out_len) != 0) {
		if (write_data(tracee, buf_addr, outbuf, out_len) == 0)
			poke_reg(tracee, SYSARG_RESULT, (word_t) out_len);
	}

out2:
	TALLOC_FREE(inbuf);
	TALLOC_FREE(outbuf);
}

/* Always-openable stand-in used to spoof open(2)/openat(2) failures
 * against "/sys" (and non-PID "/proc" entries).  */
#define FAKE_OPEN_TARGET "/dev/null"

/**
 * Reserve space in @tracee's memory (sysenter stack only, see
 * alloc_mem()) for FAKE_OPEN_TARGET and remember its address in
 * @config, so that redirect_failed_sys_open() can use it later, at
 * sysexit, without itself needing to touch the stack (alloc_mem()
 * requires sysenter).  Called for every open(2)/openat(2) targeting
 * "/sys" (or a non-PID "/proc" entry), regardless of whether the real
 * call will actually fail.
 */
static void prepare_open_redirect_target(Tracee *tracee, Config *config)
{
	word_t addr;

	config->open_redirect_target_addr = 0;

	addr = alloc_mem(tracee, sizeof(FAKE_OPEN_TARGET));
	if (addr == 0)
		return;

	/* If this fails, config->open_redirect_target_addr stays 0 (no
	 * redirect attempted for this syscall); the sysenter-reserved
	 * stack space itself is automatically reclaimed when the
	 * tracee's original registers are restored at the end of the
	 * sysexit stage, so nothing is leaked.  */
	if (write_data(tracee, addr, FAKE_OPEN_TARGET, sizeof(FAKE_OPEN_TARGET)) < 0)
		return;

	config->open_redirect_target_addr = addr;
}

/**
 * An open(at)(2) targeting "/sys" (or a non-PID "/proc" entry) that
 * fails at open() time itself -- e.g. lacking real host privileges to
 * open a cpufreq governor or a cgroup control file for writing --
 * can't be spoofed to success by merely rewriting the result: unlike
 * write()/ioctl() failures on an already-open fd, there is no fd to
 * later fake writes/ioctls on.  So instead transparently redirect the
 * whole syscall to FAKE_OPEN_TARGET, an always-openable file, letting
 * the guest get a valid fd it can freely read/write/ioctl on (those
 * are, in turn, spoofed to success too when they fail).
 */
static void redirect_failed_sys_open(Tracee *tracee, Config *config, Sysnum sysnum)
{
	Reg flags_reg;
	word_t flags;
	word_t target_addr;
	int status;

	target_addr = config->open_redirect_target_addr;
	config->open_redirect_target_addr = 0;
	if (target_addr == 0)
		return;

	flags_reg = (sysnum == PR_openat) ? SYSARG_3 : SYSARG_2;
	flags = peek_reg(tracee, ORIGINAL, flags_reg);

	/* Only the access-mode bits (and harmless flags like
	 * O_CLOEXEC/O_NONBLOCK) still matter once redirected: creation,
	 * truncation, exclusivity, or directory-only flags would be
	 * meaningless -- or outright rejected -- against a character
	 * device.  */
	flags &= ~(word_t) (O_CREAT | O_EXCL | O_TRUNC | O_DIRECTORY | O_NOCTTY);

	status = register_chained_syscall(tracee, PR_openat,
					AT_FDCWD, target_addr, flags, 0, 0, 0);
	if (status < 0)
		return;

	config->open_redirect_pending = true;
}

static void handle_openat_exit(Tracee *tracee, Config *config)
{
	int64_t result;
	ProcFdKind kind;

	result = (int64_t) peek_reg(tracee, CURRENT, SYSARG_RESULT);

	if (config->last_path_is_sys) {
		if (result >= 0) {
			track_fd(config, (int) result, 0, SYS_FD_GENERIC);
			return;
		}

		redirect_failed_sys_open(tracee, config, get_sysnum(tracee, ORIGINAL));
		return;
	}

	if (!config->last_path_is_proc)
		return;

	if (result < 0)
		return;

	if (config->last_path_is_root)
		kind = PROC_FD_ROOT;
	else if (strcmp(config->last_path_leaf, "status") == 0)
		kind = PROC_FD_STATUS;
	else if (strcmp(config->last_path_leaf, "stat") == 0)
		kind = PROC_FD_STAT;
	else if (strcmp(config->last_path_leaf, "statm") == 0)
		kind = PROC_FD_STATM;
	else
		return;

	track_fd(config, (int) result, config->last_path_host_pid, kind);
}

/**
 * "/sys" writes that fail (typically due to lacking real host
 * privileges, e.g. writing to a cpufreq governor or a cgroup
 * control file) are spoofed as fully successful no-ops: report
 * success and do nothing, rather than surfacing the real failure to
 * the guest.
 */
static void handle_sys_write_exit(Tracee *tracee, Config *config, Reg count_reg)
{
	int fd;
	int64_t result;
	word_t requested;

	result = (int64_t) peek_reg(tracee, CURRENT, SYSARG_RESULT);
	if (result >= 0)
		return;

	fd = (int) peek_reg(tracee, ORIGINAL, SYSARG_1);
	if (find_tracked_fd(config, fd) == NULL
	    || find_tracked_fd(config, fd)->kind != SYS_FD_GENERIC)
		return;

	requested = peek_reg(tracee, ORIGINAL, count_reg);
	poke_reg(tracee, SYSARG_RESULT, requested);
}

/**
 * Same idea as handle_sys_write_exit(), but for fd-based syscalls
 * that report success as a plain "0" (ioctl(2), fsync-like calls).
 */
static void handle_sys_fd_noop_exit(Tracee *tracee, Config *config)
{
	int fd;
	int64_t result;

	result = (int64_t) peek_reg(tracee, CURRENT, SYSARG_RESULT);
	if (result >= 0)
		return;

	fd = (int) peek_reg(tracee, ORIGINAL, SYSARG_1);
	if (find_tracked_fd(config, fd) == NULL
	    || find_tracked_fd(config, fd)->kind != SYS_FD_GENERIC)
		return;

	poke_reg(tracee, SYSARG_RESULT, 0);
}

/**
 * Metadata-only syscalls (chmod/chown/utimes/mkdir/unlink/rename/...)
 * targeting "/sys" that fail are spoofed the same way: success,
 * without actually doing anything on the host.
 */
static void handle_sys_path_noop_exit(Tracee *tracee, Config *config)
{
	int64_t result;

	if (!config->last_path_is_sys)
		return;

	result = (int64_t) peek_reg(tracee, CURRENT, SYSARG_RESULT);
	if (result >= 0)
		return;

	poke_reg(tracee, SYSARG_RESULT, 0);
}

static void handle_close_enter(Tracee *tracee, Config *config)
{
	int fd = (int) peek_reg(tracee, ORIGINAL, SYSARG_1);
	untrack_fd(config, fd);
}

/**
 * Write @vpid into the tracee's memory at @addr, if @addr isn't NULL.
 * The kernel writes an "int" (32-bit) there, regardless of the ABI.
 */
static void write_back_tid(Tracee *tracee, word_t addr, uint64_t vpid)
{
	uint32_t value;

	if (addr == 0)
		return;

	value = (uint32_t) vpid;
	(void) write_data(tracee, addr, &value, sizeof(value));
}

/**
 * Rewrite the return value of a just-completed clone(2)/clone3(2)/
 * fork(2)/vfork(2) from the host child pid to the child's vPID (this
 * is what $! captures in shells, for instance), and, for legacy
 * clone(2), write back the vPID/vTID into CLONE_PARENT_SETTID /
 * CLONE_CHILD_SETTID target addresses.
 */
static void handle_clone_exit(Tracee *tracee, Sysnum sysnum)
{
	int64_t result;
	Tracee *child;

	result = (int64_t) peek_reg(tracee, CURRENT, SYSARG_RESULT);
	if (result <= 0)
		return; /* Not the parent's return, or an error.  */

	child = get_tracee(tracee, (pid_t) result, false);
	if (child == NULL)
		return;

	poke_reg(tracee, SYSARG_RESULT, (word_t) child->vpid);

	/* Only legacy clone(2) has a well-known, stable argument
	 * order for the tid pointers; clone3(2) takes a "struct
	 * clone_args" pointer instead, and fork(2)/vfork(2) take no
	 * arguments at all.  */
	if (sysnum == PR_clone) {
		word_t flags = peek_reg(tracee, ORIGINAL, SYSARG_1);

		/* This matches the argument order used by glibc's
		 * clone(2) wrapper on most architectures (arm,
		 * aarch64, x86_64, ...).  A handful of architectures
		 * swap SYSARG_1/SYSARG_2 or use a different order for
		 * the tid pointers; on those this best-effort
		 * write-back may be skipped.  */
		word_t parent_tidptr = peek_reg(tracee, ORIGINAL, SYSARG_3);
		word_t child_tidptr  = peek_reg(tracee, ORIGINAL, SYSARG_5);

		if ((flags & CLONE_PARENT_SETTID) != 0)
			write_back_tid(tracee, parent_tidptr, child->vpid);

		if ((flags & CLONE_CHILD_SETTID) != 0)
			write_back_tid(tracee, child_tidptr, child->vpid);
	}
}

static void handle_sysexit(Tracee *tracee, Config *config)
{
	Sysnum sysnum = get_sysnum(tracee, ORIGINAL);
	word_t result;

	switch (sysnum) {
	case PR_getpid:
		poke_reg(tracee, SYSARG_RESULT, (word_t) config->tgid_vpid);
		break;

	case PR_gettid:
		poke_reg(tracee, SYSARG_RESULT, (word_t) tracee->vpid);
		break;

	case PR_getppid:
		poke_reg(tracee, SYSARG_RESULT, (word_t) config->ppid_vpid);
		break;

	case PR_getpgid:
	case PR_getsid:
		result = peek_reg(tracee, CURRENT, SYSARG_RESULT);
		if ((int64_t) result > 0)
			poke_reg(tracee, SYSARG_RESULT,
				(word_t) host_pid_to_vpid((pid_t) result));
		break;

	case PR_clone:
	case PR_clone3:
	case PR_fork:
	case PR_vfork:
		handle_clone_exit(tracee, sysnum);
		break;

	case PR_getdents64:
		handle_getdents64_exit(tracee, config);
		break;

	case PR_read:
		handle_read_exit(tracee, config);
		break;

	case PR_readlink:
	case PR_readlinkat:
		handle_readlink_exit(tracee, config, sysnum);
		break;

	case PR_openat:
	case PR_open:
		handle_openat_exit(tracee, config);
		break;

	case PR_write:
		handle_sys_write_exit(tracee, config, SYSARG_3);
		break;

	case PR_pwrite64:
		handle_sys_write_exit(tracee, config, SYSARG_3);
		break;

	case PR_writev:
	case PR_pwritev:
	case PR_pwritev2:
		/* No easy total-length computation without walking the
		 * iovec array; fall back to a plain success no-op.  */
		handle_sys_fd_noop_exit(tracee, config);
		break;

	case PR_ioctl:
		handle_sys_fd_noop_exit(tracee, config);
		break;

	case PR_fchmod:
	case PR_fchown:
	case PR_fchown32:
	case PR_ftruncate:
	case PR_ftruncate64:
	case PR_fsetxattr:
		handle_sys_fd_noop_exit(tracee, config);
		break;

	case PR_chmod:
	case PR_fchmodat:
	case PR_chown:
	case PR_chown32:
	case PR_fchownat:
	case PR_lchown:
	case PR_lchown32:
	case PR_truncate:
	case PR_truncate64:
	case PR_utimensat:
	case PR_utimes:
	case PR_futimesat:
	case PR_mkdir:
	case PR_mkdirat:
	case PR_mknod:
	case PR_mknodat:
	case PR_unlink:
	case PR_unlinkat:
	case PR_rename:
	case PR_renameat:
	case PR_renameat2:
	case PR_symlink:
	case PR_symlinkat:
	case PR_setxattr:
	case PR_lsetxattr:
		handle_sys_path_noop_exit(tracee, config);
		break;

	default:
		break;
	}
}

int pid_virt_callback(Extension *extension, ExtensionEvent event,
		intptr_t data1, intptr_t data2)
{
	switch (event) {
	case INITIALIZATION: {
		Tracee *tracee = TRACEE(extension);
		Config *config;

		config = talloc_zero(extension, Config);
		if (config == NULL)
			return -1;

		/* The very first guest process is always vPID 1, with
		 * no visible parent (like a real init process).  */
		config->tgid_vpid = tracee->vpid;
		config->ppid_vpid = 0;

		extension->config = config;
		extension->filtered_sysnums = filtered_sysnums;
		return 0;
	}

	case INHERIT_PARENT:
		/* Always inheritable, with a dedicated (non-shared)
		 * configuration since PID relationships differ for
		 * each tracee.  */
		return 1;

	case INHERIT_CHILD: {
		Tracee *tracee = TRACEE(extension);
		Extension *parent_extension = (Extension *) data1;
		word_t clone_flags = (word_t) data2;
		Config *parent_config = talloc_get_type_abort(parent_extension->config, Config);
		Config *config;

		config = talloc_zero(extension, Config);
		if (config == NULL)
			return -1;

		if (clone_flags != CLONE_RECONF && (clone_flags & CLONE_THREAD) != 0) {
			/* New thread: shares the same thread-group id
			 * and the same (grand-)parent as the caller.  */
			config->tgid_vpid = parent_config->tgid_vpid;
			config->ppid_vpid = parent_config->ppid_vpid;
		}
		else {
			/* New process: it is its own thread-group
			 * leader, and its parent is the caller's
			 * thread-group.  */
			config->tgid_vpid = tracee->vpid;
			config->ppid_vpid = parent_config->tgid_vpid;
		}

		extension->config = config;
		extension->filtered_sysnums = filtered_sysnums;
		return 0;
	}

	case GUEST_PATH: {
		Tracee *tracee = TRACEE(extension);
		Config *config = talloc_get_type_abort(extension->config, Config);
		return handle_guest_path(tracee, config, (char *) data1, (const char *) data2);
	}

	case SYSCALL_ENTER_START: {
		Tracee *tracee = TRACEE(extension);
		Config *config = talloc_get_type_abort(extension->config, Config);
		Sysnum sysnum = get_sysnum(tracee, ORIGINAL);

		if (sysnum == PR_close)
			handle_close_enter(tracee, config);

		return handle_sysenter(tracee);
	}

	case SYSCALL_ENTER_END: {
		Tracee *tracee = TRACEE(extension);
		Config *config = talloc_get_type_abort(extension->config, Config);
		Sysnum sysnum = get_sysnum(tracee, ORIGINAL);

		/* By now the GUEST_PATH handler (invoked from within
		 * translate_syscall_enter()) has already resolved this
		 * syscall's path, so config->last_path_is_sys reflects
		 * whether it targets "/sys"/non-PID "/proc".  Reserve
		 * the fake open() target now, while still in sysenter,
		 * for possible use at sysexit.  */
		if ((sysnum == PR_open || sysnum == PR_openat) && config->last_path_is_sys)
			prepare_open_redirect_target(tracee, config);

		return 0;
	}

	case SYSCALL_EXIT_END: {
		Tracee *tracee = TRACEE(extension);
		Config *config = talloc_get_type_abort(extension->config, Config);

		handle_sysexit(tracee, config);
		return 0;
	}

	case SYSCALL_CHAINED_EXIT: {
		Tracee *tracee = TRACEE(extension);
		Config *config = talloc_get_type_abort(extension->config, Config);

		if (config->open_redirect_pending) {
			int64_t result = (int64_t) peek_reg(tracee, CURRENT, SYSARG_RESULT);

			config->open_redirect_pending = false;
			if (result >= 0)
				track_fd(config, (int) result, 0, SYS_FD_GENERIC);
		}
		return 0;
	}

	default:
		return 0;
	}
}
