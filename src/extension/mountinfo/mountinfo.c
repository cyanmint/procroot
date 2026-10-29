#include "extension/extension.h"
#include "path/path.h"           /* translate_path,  */
#include "path/binding.h"        /* Binding, bindings */
#include "path/temp.h"           /* create_temp_file,  */
#include <limits.h>              /* INT_MAX,  */
#include <linux/limits.h>        /* PATH_MAX,  */
#include <string.h>              /* strlen, strcmp */
#include <stdio.h>               /* FILE, getline, fprintf */
#include <stdlib.h>              /* free,  */
#include <sys/queue.h>           /* CIRCLEQ_*,  */

/**
 * Append a synthesized mount-table line to @fp for each runtime
 * binding (i.e. one that wasn't part of the static -r/-b set).  This
 * is what lets sandbox helpers like bubblewrap find the mount they
 * just asked PRoot to create via emulate_mount().
 */
static void append_runtime_binding_lines(Tracee *target_tracee, FILE *fp)
{
	Binding *binding;
	int next_id = 1000000;
	int parent_id = 1;

	if (target_tracee->fs->bindings.guest == NULL)
		return;

	for (binding = CIRCLEQ_FIRST(target_tracee->fs->bindings.guest);
	     binding != (void *) target_tracee->fs->bindings.guest;
	     binding = CIRCLEQ_NEXT(binding, link.guest)) {
		/* Skip the root binding "/" — already present as the kernel root.  */
		if (strcmp(binding->guest.path, "/") == 0)
			continue;

		fprintf(fp,
			"%d %d 0:1 / %s rw,relatime - bind %s rw,relatime\n",
			next_id++, parent_id,
			binding->guest.path, binding->host.path);
	}
}

static void append_runtime_binding_mounts(Tracee *target_tracee, FILE *fp)
{
	Binding *binding;

	if (target_tracee->fs->bindings.guest == NULL)
		return;

	for (binding = CIRCLEQ_FIRST(target_tracee->fs->bindings.guest);
	     binding != (void *) target_tracee->fs->bindings.guest;
	     binding = CIRCLEQ_NEXT(binding, link.guest)) {
		if (strcmp(binding->guest.path, "/") == 0)
			continue;

		fprintf(fp, "%s %s bind rw,relatime 0 0\n",
			binding->host.path, binding->guest.path);
	}
}

static bool is_apex_mountpoint(const char *path, size_t length)
{
	return (length == 5 && memcmp(path, "/apex", 5) == 0) ||
	       (length >= 6 && memcmp(path, "/apex/", 6) == 0);
}

static void mountinfo_check_open_path(Tracee *tracee, char path[PATH_MAX]) {
	/* Keep PID 1's global mount table on procfs. Redirecting this exact path
	 * prevents Android init from booting on the target device. */
	if (tracee->vpid == 1 && strcmp(path, "/proc/mounts") == 0)
		return;

	/* Try matching mountinfo/mounts paths in /proc. */
	size_t len = strlen(path);
	bool is_mountinfo = false;
	bool is_mounts = false;
	bool is_self = false;
	const char *pid_path = NULL;
	const char *table_suffix = NULL;
	const char *table_name;
	if (strcmp(path, "/proc/mounts") == 0) {
		is_mounts = true;
		is_self = true;
	} else if (len > 6 && 0 == strncmp(path, "/proc/", 6)) {
		if (len > (6 + 10) &&
		    0 == strcmp(path + (len - 10), "/mountinfo")) {
			is_mountinfo = true;
			table_suffix = path + (len - 10);
		} else if (len > (6 + 7) &&
			   0 == strcmp(path + (len - 7), "/mounts")) {
			is_mounts = true;
			table_suffix = path + (len - 7);
		} else {
			return;
		}
		pid_path = path + 6;
		if ((table_suffix - pid_path == 4 &&
		     0 == memcmp(pid_path, "self", 4)) ||
		    (table_suffix - pid_path == 11 &&
		     0 == memcmp(pid_path, "thread-self", 11)))
			is_self = true;
	} else {
		return;
	}
	table_name = is_mountinfo ? "mountinfo" : "mounts";

	{
		char real_path[PATH_MAX];
		const char *path_to_open = path;
		Tracee *target_tracee;
		long target_pid;

		/* PID virtualization leaves /proc/self intact so the kernel can
		 * resolve it for the calling tracee.  Resolve it here as well,
		 * otherwise this extension cannot filter the real mount table. */
		if (is_self) {
			target_tracee = tracee;
			int status = snprintf(real_path, sizeof(real_path),
					     "/proc/%d/%s", target_tracee->pid,
					     table_name);
			if (status < 0 || (size_t) status >= sizeof(real_path))
				return;
			path_to_open = real_path;
		} else {
			char *path_end = NULL;
			target_pid = strtol(pid_path, &path_end, 10);
			if (path_end != table_suffix || target_pid <= 0 ||
			    target_pid > INT_MAX) {
				return;
			}
			target_tracee = get_tracee(tracee, target_pid, false);
			if (target_tracee == NULL)
				return;
		}
		/* A root under /data needs a filtered view of the host mount table:
		 * mountinfo gets its Android-specific root rewrite below, while the
		 * mounts view hides host APEX mounts that belong to another runtime.
		 *
		 * https://github.com/termux/proot/issues/294
		 */
		/* Read the root binding directly.  Calling translate_path() here
		 * would re-enter extension callbacks and overwrite per-syscall
		 * path state while handling TRANSLATED_PATH. */
		const char *root_path = get_root(target_tracee);
		if (root_path == NULL)
			return;
		Comparison compare_result = compare_paths(root_path, "/data");
		bool is_android_data = (compare_result == PATH2_IS_PREFIX || compare_result == PATHS_ARE_EQUAL);

		/* Are there bindings to expose as fake mounts (mount(2)
		 * calls from sandbox helpers are converted into
		 * bindings — see emulate_mount).  Skip the root
		 * binding, which the real kernel mount table already
		 * covers.  */
		bool has_extra_bindings = false;
		if (target_tracee->fs->bindings.guest != NULL) {
			Binding *b;
			for (b = CIRCLEQ_FIRST(target_tracee->fs->bindings.guest);
			     b != (void *) target_tracee->fs->bindings.guest;
			     b = CIRCLEQ_NEXT(b, link.guest)) {
				if (strcmp(b->guest.path, "/") != 0) {
					has_extra_bindings = true;
					break;
				}
			}
		}

		if (!is_android_data && !has_extra_bindings)
			return;

		/* Open real /proc/<PID>/mountinfo  */
		FILE *real_mountinfo_fp = fopen(path_to_open, "r");
		if (real_mountinfo_fp == NULL) {
			return;
		}

		/* Prepare faked mountinfo  */
		const char *new_path = create_temp_file(tracee->ctx, "mountinfo");
		FILE *new_mountinfo_fp = fopen(new_path, "w");
		if (new_mountinfo_fp == NULL) {
			fclose(real_mountinfo_fp);
			return;
		}

		char *line = NULL;
		size_t line_buf_len = 0;
		ssize_t line_len = 0;
		bool found_line = false;

		if (is_android_data && is_mounts) {
			while ((line_len = getline(&line, &line_buf_len,
						   real_mountinfo_fp)) > 0) {
				char *source_end = strchr(line, ' ');
				char *mountpoint;
				char *mountpoint_end;
				size_t mount_len;

				if (source_end == NULL)
					continue;
				mountpoint = source_end + 1;
				mountpoint_end = strchr(mountpoint, ' ');
				if (mountpoint_end == NULL)
					continue;
				mount_len = mountpoint_end - mountpoint;
				if (is_apex_mountpoint(mountpoint, mount_len))
					continue;

				fwrite(line, line_len, 1, new_mountinfo_fp);
				if (mount_len == 1 && mountpoint[0] == '/')
					found_line = true;
			}
		} else if (is_android_data) {
			while ((line_len = getline(&line, &line_buf_len, real_mountinfo_fp)) > 0) {
				char *chunk = line;
				/* Skip columns before 'root'  */
				for (int i = 0; i < 4 && chunk - line < line_len; i++) {
					chunk = strchr(chunk, ' ');
					if (chunk == NULL) goto end_line_scan;
					chunk++;
				}

				/* Match path  */
				char *chunk_end = strchr(chunk, ' ');
				if (chunk_end == NULL) continue;

				if (chunk_end - chunk == 5 && 0 == memcmp(chunk, "/data", 5)) {
					/* Write line into new file keeping only "/" from root column  */
					fwrite(line, chunk - line + 1, 1, new_mountinfo_fp);
					fwrite(chunk_end, line_len - (chunk_end - line), 1, new_mountinfo_fp);
					found_line = true;
					break;
				}
end_line_scan: ;
			}

			/* Once root was added, rescan and add other standard mounts  */
			if (found_line) {
				fseek(real_mountinfo_fp, 0, SEEK_SET);
				while ((line_len = getline(&line, &line_buf_len, real_mountinfo_fp)) > 0) {
					char *chunk = line;
					/* Skip columns before 'root'  */
					for (int i = 0; i < 4 && chunk - line < line_len; i++) {
						chunk = strchr(chunk, ' ');
						if (chunk == NULL) goto end_line_scan2;
						chunk++;
					}

					/* Match path  */
					char *chunk_end = strchr(chunk, ' ');
					if (chunk_end == NULL) continue;

					size_t mount_len = chunk_end - chunk;
					if (
							(mount_len == 4 && 0 == memcmp(chunk, "/dev", 4)) ||
							(mount_len >= 5 && 0 == memcmp(chunk, "/dev/", 5)) ||
							(mount_len == 5 && 0 == memcmp(chunk, "/proc", 5)) ||
							(mount_len == 4 && 0 == memcmp(chunk, "/sys", 4)) ||
							(mount_len >= 5 && 0 == memcmp(chunk, "/sys/", 5)) ||
							(mount_len == 4 && 0 == memcmp(chunk, "/tmp", 4))
							) {
						/* Copy line into new file verbatim  */
						fwrite(line, line_len, 1, new_mountinfo_fp);
					}
end_line_scan2: ;
				}
			}
		} else {
			/* Non-Android case: copy real mountinfo verbatim.  */
			while ((line_len = getline(&line, &line_buf_len, real_mountinfo_fp)) > 0)
				fwrite(line, line_len, 1, new_mountinfo_fp);
			found_line = true;
		}

		/* Append synthesized entries for runtime bindings so
		 * helpers like bubblewrap find the mounts they think
		 * they just created.  */
		if (is_mounts)
			append_runtime_binding_mounts(target_tracee, new_mountinfo_fp);
		else
			append_runtime_binding_lines(target_tracee, new_mountinfo_fp);

		free(line);
		fclose(new_mountinfo_fp);
		fclose(real_mountinfo_fp);

		/* Redirect open to our temp file  */
		if (found_line) {
			strncpy(path, new_path, PATH_MAX);
		}
		return;
	}
}

int mountinfo_callback(Extension *extension, ExtensionEvent event,
        intptr_t data1 UNUSED, intptr_t data2 UNUSED)
{
    switch (event) {
    case TRANSLATED_PATH:
	{
		Tracee *tracee = TRACEE(extension);
		Sysnum num = get_sysnum(tracee, ORIGINAL);
		if (num == PR_open || num == PR_openat) {
			mountinfo_check_open_path(tracee, (char*) data1);
		}
        return 0;
	}

    default:
        return 0;
    }
}
