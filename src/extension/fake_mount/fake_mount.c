/*
 * SPDX-FileCopyrightText: NONE
 * SPDX-License-Identifier: GPL-2.0-or-later
 * Note: AI-generated contribution; no legal determination implied.
 */
#include <errno.h>
#include <dirent.h>
#include <fcntl.h>
#include <linux/fs.h>
#include <linux/limits.h>
#include <linux/dm-ioctl.h>
#include <linux/loop.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sched.h>
#include <sys/wait.h>
#include <sys/eventfd.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <unistd.h>

#include "extension/extension.h"
#include "path/binding.h"
#include "path/canon.h"
#include "path/path.h"
#include "path/temp.h"
#include "syscall/syscall.h"
#include "tracee/mem.h"
#include "tracee/reg.h"

#define FAKE_MOUNT_MAX_FDS 256
#define FAKE_MOUNT_MAX_PENDING 64
#define FAKE_MOUNT_MAX_LOOPS 256
#define FAKE_MOUNT_MAX_NAMESPACES 8

enum FakeFdKind {
	FAKE_FD_NONE,
	FAKE_FD_LOOP_CONTROL,
	FAKE_FD_LOOP,
	FAKE_FD_DM_CONTROL,
	FAKE_FD_DM,
	FAKE_FD_MOUNT_NAMESPACE,
};

typedef struct {
	bool active;
	uint64_t files_table_id;
	int fd;
	enum FakeFdKind kind;
	int device_number;
	uint64_t mount_namespace_id;
} FakeFd;

typedef struct {
	bool active;
	pid_t pid;
	bool open_pending;
	enum FakeFdKind open_kind;
	int open_device_number;
	uint64_t open_namespace_id;
	bool bootstrap_mount_pending;
	char bootstrap_mount_guest_path[PATH_MAX];
	bool mount_namespace_readlink_pending;
	uint64_t mount_namespace_readlink_id;
	bool ioctl_pending;
	int ioctl_result;
} FakePending;

typedef struct {
	bool active;
	uint64_t id;
	Bindings *guest;
	Bindings *host;
	FileSystemNameSpace *owner;
} FakeMountNamespace;

typedef struct {
	bool allocated;
	bool attached;
	bool node_created;
	char backing_path[PATH_MAX];
	uint64_t offset;
	uint64_t size_limit;
	struct loop_info64 info;
	char extracted_root[PATH_MAX];
} FakeLoop;

typedef struct {
	bool active;
	bool node_created;
	bool table_loaded;
	bool suspended;
	char name[DM_NAME_LEN];
	dev_t dev;
	int loop_number;
} FakeDm;

typedef struct {
	FakeFd fds[FAKE_MOUNT_MAX_FDS];
	FakePending pending[FAKE_MOUNT_MAX_PENDING];
	FakeLoop loops[FAKE_MOUNT_MAX_LOOPS];
	FakeDm dms[FAKE_MOUNT_MAX_LOOPS];
	FakeMountNamespace namespaces[FAKE_MOUNT_MAX_NAMESPACES];
	bool block_dir_created;
	bool loop_control_node_created;
	char root_path[PATH_MAX];
	unsigned int next_loop;
	unsigned int next_dm;
	uint64_t next_mount_namespace_id;
	uint64_t bootstrap_namespace_id;
	uint64_t default_namespace_id;
} FakeMountConfig;

static FilteredSysnum filtered_sysnums[] = {
	{ PR_access, 0 },
	{ PR_faccessat, 0 },
	{ PR_faccessat2, 0 },
	{ PR_fstatat64, 0 },
	{ PR_newfstatat, 0 },
	{ PR_open, FILTER_SYSEXIT },
	{ PR_openat, FILTER_SYSEXIT },
	{ PR_openat2, FILTER_SYSEXIT },
	{ PR_readlink, FILTER_SYSEXIT },
	{ PR_readlinkat, FILTER_SYSEXIT },
	{ PR_unshare, 0 },
	{ PR_setns, 0 },
	{ PR_ioctl, FILTER_SYSEXIT },
	{ PR_x32_ioctl, FILTER_SYSEXIT },
	FILTERED_SYSNUM_END,
};

static FakePending *pending_for(FakeMountConfig *config, pid_t pid, bool create)
{
	size_t i;
	FakePending *free_slot = NULL;

	for (i = 0; i < FAKE_MOUNT_MAX_PENDING; i++) {
		if (config->pending[i].active && config->pending[i].pid == pid)
			return &config->pending[i];
		if (!config->pending[i].active && free_slot == NULL)
			free_slot = &config->pending[i];
	}
	if (!create || free_slot == NULL)
		return NULL;

	memset(free_slot, 0, sizeof(*free_slot));
	free_slot->active = true;
	free_slot->pid = pid;
	return free_slot;
}

static FakeFd *find_fake_fd(FakeMountConfig *config, uint64_t files_table_id,
			    int fd)
{
	size_t i;

	for (i = 0; i < FAKE_MOUNT_MAX_FDS; i++)
		if (config->fds[i].active &&
		    config->fds[i].files_table_id == files_table_id &&
		    config->fds[i].fd == fd)
			return &config->fds[i];
	return NULL;
}

static FakeMountNamespace *find_mount_namespace(FakeMountConfig *config,
						 uint64_t id)
{
	size_t i;

	for (i = 0; i < FAKE_MOUNT_MAX_NAMESPACES; i++)
		if (config->namespaces[i].active && config->namespaces[i].id == id)
			return &config->namespaces[i];
	return NULL;
}

static FakeMountNamespace *mount_namespace_for_tracee(
		FakeMountConfig *config, Tracee *tracee, bool create)
{
	size_t i;
	FakeMountNamespace *free_slot = NULL;

	if (tracee->fs == NULL || tracee->fs->bindings.guest == NULL ||
	    tracee->fs->bindings.host == NULL)
		return NULL;
	for (i = 0; i < FAKE_MOUNT_MAX_NAMESPACES; i++) {
		FakeMountNamespace *ns = &config->namespaces[i];

		if (!ns->active) {
			if (free_slot == NULL)
				free_slot = ns;
			continue;
		}
		if (ns->guest == tracee->fs->bindings.guest &&
		    ns->host == tracee->fs->bindings.host)
			return ns;
	}
	if (!create || free_slot == NULL || config->next_mount_namespace_id == 0)
		return NULL;

	free_slot->owner = talloc_reference(config, tracee->fs);
	if (free_slot->owner == NULL)
		return NULL;
	free_slot->active = true;
	free_slot->id = config->next_mount_namespace_id++;
	free_slot->guest = tracee->fs->bindings.guest;
	free_slot->host = tracee->fs->bindings.host;
	return free_slot;
}

static int copy_mount_namespace_bindings(Tracee *tracee,
					 FakeMountConfig *config,
					 FileSystemNameSpace *source,
					 FileSystemNameSpace *destination)
{
	Binding *binding;

	destination->bindings.guest = talloc_zero(config, Bindings);
	destination->bindings.host = talloc_zero(config, Bindings);
	if (destination->bindings.guest == NULL ||
	    destination->bindings.host == NULL)
		return -ENOMEM;
	CIRCLEQ_INIT(destination->bindings.guest);
	CIRCLEQ_INIT(destination->bindings.host);
	if (source->bindings.pending != NULL)
		destination->bindings.pending =
			talloc_reference(destination, source->bindings.pending);

	tracee->fs = destination;
	for (binding = CIRCLEQ_FIRST(source->bindings.guest);
	     binding != (void *)source->bindings.guest;
	     binding = CIRCLEQ_NEXT(binding, link.guest)) {
		if (insort_binding3(tracee, config, binding->host.path,
				    binding->guest.path) == NULL) {
			tracee->fs = source;
			return -ENOMEM;
		}
	}
	return 0;
}

static int unshare_mount_namespace(Tracee *tracee, FakeMountConfig *config)
{
	FakeMountNamespace *source_ns;
	FakeMountNamespace *destination_ns;
	FileSystemNameSpace *source_fs = tracee->fs;
	FileSystemNameSpace *destination_fs;
	int status;

	source_ns = mount_namespace_for_tracee(config, tracee, true);
	if (source_ns == NULL)
		return -ENOMEM;
	if (config->bootstrap_namespace_id == 0)
		config->bootstrap_namespace_id = source_ns->id;

	destination_fs = talloc_zero(tracee, FileSystemNameSpace);
	if (destination_fs == NULL)
		return -ENOMEM;
	destination_fs->cwd = talloc_strdup(destination_fs, source_fs->cwd);
	if (destination_fs->cwd == NULL)
		return -ENOMEM;
	talloc_set_name_const(destination_fs->cwd, "$cwd");
	status = copy_mount_namespace_bindings(tracee, config, source_fs,
					       destination_fs);
	if (status < 0)
		return status;

	destination_ns = mount_namespace_for_tracee(config, tracee, true);
	if (destination_ns == NULL) {
		tracee->fs = source_fs;
		return -ENOMEM;
	}
	if (config->default_namespace_id == 0)
		config->default_namespace_id = destination_ns->id;
	return 0;
}

static int switch_mount_namespace(Tracee *tracee,
				  FakeMountNamespace *target_ns)
{
	FileSystemNameSpace *destination;

	if (target_ns == NULL || target_ns->owner == NULL)
		return -EINVAL;
	if (tracee->fs->bindings.guest == target_ns->guest &&
	    tracee->fs->bindings.host == target_ns->host)
		return 0;
	destination = talloc_zero(tracee, FileSystemNameSpace);
	if (destination == NULL)
		return -ENOMEM;
	destination->cwd = talloc_strdup(destination, tracee->fs->cwd);
	if (destination->cwd == NULL)
		return -ENOMEM;
	talloc_set_name_const(destination->cwd, "$cwd");
	destination->bindings.guest =
		talloc_reference(destination, target_ns->guest);
	destination->bindings.host =
		talloc_reference(destination, target_ns->host);
	if (destination->bindings.guest == NULL ||
	    destination->bindings.host == NULL)
		return -ENOMEM;
	tracee->fs = destination;
	return 0;
}

static bool is_mount_namespace_path(const char *path)
{
	return path != NULL &&
		(strcmp(path, "/proc/self/ns/mnt") == 0 ||
		 strcmp(path, "/proc/thread-self/ns/mnt") == 0);
}

static void rewrite_mount_namespace_readlink(Tracee *tracee,
					     Sysnum syscall,
					     FakePending *pending)
{
	char target[64];
	word_t buffer_address;
	word_t buffer_size;
	int length;
	int64_t result;

	if (!pending->mount_namespace_readlink_pending)
		return;
	pending->mount_namespace_readlink_pending = false;
	result = (int64_t)peek_reg(tracee, CURRENT, SYSARG_RESULT);
	if (result <= 0)
		return;
	buffer_address = syscall == PR_readlink ?
		peek_reg(tracee, ORIGINAL, SYSARG_2) :
		peek_reg(tracee, ORIGINAL, SYSARG_3);
	buffer_size = syscall == PR_readlink ?
		peek_reg(tracee, ORIGINAL, SYSARG_3) :
		peek_reg(tracee, ORIGINAL, SYSARG_4);
	length = snprintf(target, sizeof(target), "mnt:[%llu]",
		  (unsigned long long)pending->mount_namespace_readlink_id);
	if (length <= 0 || (word_t)length > buffer_size)
		return;
	if (write_data(tracee, buffer_address, target, (size_t)length) == 0)
		poke_reg(tracee, SYSARG_RESULT, (word_t)length);
}

static void forget_fake_fd(FakeMountConfig *config, uint64_t files_table_id,
			   int fd)
{
	FakeFd *entry = find_fake_fd(config, files_table_id, fd);

	if (entry != NULL)
		memset(entry, 0, sizeof(*entry));
}

static void remember_fake_fd(FakeMountConfig *config, uint64_t files_table_id,
			     int fd, enum FakeFdKind kind, int device_number)
{
	size_t i;
	FakeFd *entry = find_fake_fd(config, files_table_id, fd);

	if (entry == NULL)
		for (i = 0; i < FAKE_MOUNT_MAX_FDS; i++)
			if (!config->fds[i].active) {
				entry = &config->fds[i];
				break;
			}
	if (entry == NULL)
		return;

	entry->active = true;
	entry->files_table_id = files_table_id;
	entry->fd = fd;
	entry->kind = kind;
	entry->device_number = device_number;
	entry->mount_namespace_id = 0;
}

static void copy_fake_fds(Tracee *tracee, FakeMountConfig *config,
			  const FilesTableChange *change)
{
	size_t i;

	if (change->new_id == 0 || change->old_id == change->new_id)
		return;

	for (i = 0; i < FAKE_MOUNT_MAX_FDS; i++) {
		FakeFd entry = config->fds[i];
		char fd_path[PATH_MAX];

		if (!entry.active || entry.files_table_id != change->old_id)
			continue;
		if (readlink_proc_pid_fd(tracee->pid, entry.fd, fd_path) < 0)
			continue;

		remember_fake_fd(config, change->new_id, entry.fd, entry.kind,
				 entry.device_number);
		if (entry.kind == FAKE_FD_MOUNT_NAMESPACE) {
			FakeFd *copy = find_fake_fd(config, change->new_id, entry.fd);
			if (copy != NULL)
				copy->mount_namespace_id = entry.mount_namespace_id;
		}
	}
}

static int format_block_path(const char *root_path, const char *name,
			     char path[PATH_MAX])
{
	int length = snprintf(path, PATH_MAX, "%s/dev/block/%s", root_path,
			      name);

	return length < 0 || length >= PATH_MAX ? -ENAMETOOLONG : 0;
}

static int ensure_root_path(Tracee *tracee, FakeMountConfig *config)
{
	const char *root_path = get_root(tracee);
	int length;

	if (root_path == NULL || strcmp(root_path, "/") == 0)
		return -EINVAL;
	if (config->root_path[0] == '\0') {
		length = snprintf(config->root_path, sizeof(config->root_path), "%s",
				  root_path);
		if (length < 0 || (size_t)length >= sizeof(config->root_path))
			return -ENAMETOOLONG;
	} else if (strcmp(config->root_path, root_path) != 0)
		return -EINVAL;
	return 0;
}

static int ensure_loop_control_node(Tracee *tracee, FakeMountConfig *config)
{
	char node_path[PATH_MAX];
	int length;
	int fd;
	int status = ensure_root_path(tracee, config);

	if (status < 0)
		return status;
	length = snprintf(node_path, sizeof(node_path), "%s/dev/loop-control",
			  config->root_path);
	if (length < 0 || (size_t)length >= sizeof(node_path))
		return -ENAMETOOLONG;
	fd = open(node_path, O_CREAT | O_EXCL | O_WRONLY | O_CLOEXEC, 0600);
	if (fd >= 0) {
		config->loop_control_node_created = true;
		(void)close(fd);
		return 0;
	}
	return errno == EEXIST ? 0 : -errno;
}

static int ensure_block_directory(Tracee *tracee, FakeMountConfig *config)
{
	char block_dir[PATH_MAX];
	struct stat stat_buffer;
	int length;
	int status = ensure_root_path(tracee, config);

	if (status < 0)
		return status;
	length = snprintf(block_dir, sizeof(block_dir), "%s/dev/block",
			  config->root_path);
	if (length < 0 || (size_t)length >= sizeof(block_dir))
		return -ENAMETOOLONG;
	if (mkdir(block_dir, 0777) == 0)
		config->block_dir_created = true;
	else if (errno != EEXIST)
		return -errno;
	if (stat(block_dir, &stat_buffer) < 0)
		return -errno;
	return S_ISDIR(stat_buffer.st_mode) ? 0 : -ENOTDIR;
}

static int create_block_node(Tracee *tracee, FakeMountConfig *config,
			     const char *name, bool *created)
{
	char node_path[PATH_MAX];
	int fd;
	int status = ensure_block_directory(tracee, config);

	if (status < 0)
		return status;
	status = format_block_path(config->root_path, name, node_path);
	if (status < 0)
		return status;
	fd = open(node_path, O_CREAT | O_EXCL | O_WRONLY | O_CLOEXEC, 0600);
	if (fd >= 0) {
		*created = true;
		(void)close(fd);
		return 0;
	}
	return errno == EEXIST ? 0 : -errno;
}

static void remove_block_node(FakeMountConfig *config, const char *name,
			      bool *created)
{
	char node_path[PATH_MAX];

	if (*created && format_block_path(config->root_path, name, node_path) == 0)
		(void)unlink(node_path);
	*created = false;
}

static int ensure_loop_node(Tracee *tracee, FakeMountConfig *config,
			    int number)
{
	char name[32];
	int length = snprintf(name, sizeof(name), "loop%d", number);

	if (length < 0 || (size_t)length >= sizeof(name))
		return -ENAMETOOLONG;
	return create_block_node(tracee, config, name,
				 &config->loops[number].node_created);
}

static int ensure_dm_node(Tracee *tracee, FakeMountConfig *config,
			  int number)
{
	char name[32];
	int length = snprintf(name, sizeof(name), "dm-%d", number);

	if (length < 0 || (size_t)length >= sizeof(name))
		return -ENAMETOOLONG;
	return create_block_node(tracee, config, name,
				 &config->dms[number].node_created);
}

static void remove_loop_node(FakeMountConfig *config, int number)
{
	char name[32];

	if (snprintf(name, sizeof(name), "loop%d", number) < (int)sizeof(name))
		remove_block_node(config, name,
				  &config->loops[number].node_created);
}

static void remove_dm_node(FakeMountConfig *config, int number)
{
	char name[32];

	if (snprintf(name, sizeof(name), "dm-%d", number) < (int)sizeof(name))
		remove_block_node(config, name, &config->dms[number].node_created);
}

static void cleanup_fake_nodes(FakeMountConfig *config)
{
	unsigned int i;
	char block_dir[PATH_MAX];
	int length;

	for (i = 0; i < FAKE_MOUNT_MAX_LOOPS; i++)
		remove_loop_node(config, (int)i);
	for (i = 0; i < FAKE_MOUNT_MAX_LOOPS; i++)
		remove_dm_node(config, (int)i);
	if (config->loop_control_node_created) {
		char node_path[PATH_MAX];
		int length = snprintf(node_path, sizeof(node_path),
				      "%s/dev/loop-control", config->root_path);
		if (length >= 0 && (size_t)length < sizeof(node_path))
			(void)unlink(node_path);
		config->loop_control_node_created = false;
	}
	if (!config->block_dir_created)
		return;
	length = snprintf(block_dir, sizeof(block_dir), "%s/dev/block",
			  config->root_path);
	if (length >= 0 && (size_t)length < sizeof(block_dir))
		(void)rmdir(block_dir);
}

static int allocate_loop(Tracee *tracee, FakeMountConfig *config)
{
	unsigned int i;

	for (i = 0; i < FAKE_MOUNT_MAX_LOOPS; i++) {
		unsigned int candidate = (config->next_loop + i) % FAKE_MOUNT_MAX_LOOPS;

		if (!config->loops[candidate].allocated) {
			config->loops[candidate].allocated = true;
			if (ensure_loop_node(tracee, config,
					     (int)candidate) < 0) {
				memset(&config->loops[candidate], 0,
				       sizeof(config->loops[candidate]));
				return -EIO;
			}
			config->next_loop = (candidate + 1) % FAKE_MOUNT_MAX_LOOPS;
			return (int)candidate;
		}
	}
	return -ENOSPC;
}

static int add_loop(Tracee *tracee, FakeMountConfig *config, int number)
{
	FakeLoop *loop;
	int status;

	if (number < 0 || number >= FAKE_MOUNT_MAX_LOOPS)
		return -EINVAL;
	loop = &config->loops[number];
	if (loop->allocated)
		return -EEXIST;
	loop->allocated = true;
	status = ensure_loop_node(tracee, config, number);
	if (status < 0) {
		memset(loop, 0, sizeof(*loop));
		return status;
	}
	return number;
}

static bool is_preallocated_host_loop(int number)
{
	char path[64];
	int length;

	/* apexd assumes loop0 was preallocated during bootstrap. */
	if (number == 0)
		return true;
	length = snprintf(path, sizeof(path), "/sys/block/loop%d/loop", number);
	if (length < 0 || (size_t)length >= sizeof(path))
		return false;
	return access(path, F_OK) == 0;
}

static bool parse_device_number(const char *path, const char *prefix,
				int *device_number)
{
	char *end;
	long number;
	size_t prefix_length = strlen(prefix);

	if (strncmp(path, prefix, prefix_length) != 0 ||
	    path[prefix_length] < '0' || path[prefix_length] > '9')
		return false;
	number = strtol(path + prefix_length, &end, 10);
	if (*end != '\0' || number < 0 || number >= FAKE_MOUNT_MAX_LOOPS)
		return false;
	*device_number = (int)number;
	return true;
}

static enum FakeFdKind fake_device_path(FakeMountConfig *config,
					const char *base, const char *path,
					int *device_number)
{
	char combined[PATH_MAX];
	int number;

	if (path == NULL)
		return FAKE_FD_NONE;
	if (path[0] == '/') {
		if (strnlen(path, PATH_MAX) >= PATH_MAX)
			return FAKE_FD_NONE;
		strcpy(combined, path);
	} else if (base == NULL || join_paths(2, combined, base, path) < 0)
		return FAKE_FD_NONE;

	if (strcmp(combined, "/dev/loop-control") == 0)
	{
		*device_number = -1;
		return FAKE_FD_LOOP_CONTROL;
	}
	if (strcmp(combined, "/dev/device-mapper") == 0 ||
	    strcmp(combined, "/dev/mapper/control") == 0) {
		*device_number = -1;
		return FAKE_FD_DM_CONTROL;
	}
	if (parse_device_number(combined, "/dev/block/loop", &number) ||
	    parse_device_number(combined, "/dev/loop", &number)) {
		if (config->loops[number].allocated) {
			*device_number = number;
			return FAKE_FD_LOOP;
		}
	}
	if (parse_device_number(combined, "/dev/block/dm-", &number) ||
	    parse_device_number(combined, "/dev/dm-", &number)) {
		if (config->dms[number].active) {
			*device_number = number;
			return FAKE_FD_DM;
		}
	}
	return FAKE_FD_NONE;
}

static bool replace_open_with_eventfd(Tracee *tracee, Sysnum syscall)
{
	uint64_t open_flags;
	unsigned int event_flags = 0;

	switch (syscall) {
	case PR_open:
		open_flags = peek_reg(tracee, CURRENT, SYSARG_2);
		break;
	case PR_openat:
		open_flags = peek_reg(tracee, CURRENT, SYSARG_3);
		break;
	case PR_openat2: {
		struct {
			uint64_t flags;
			uint64_t mode;
			uint64_t resolve;
		} how;
		word_t address = peek_reg(tracee, CURRENT, SYSARG_3);
		word_t size = peek_reg(tracee, CURRENT, SYSARG_4);

		if (size < sizeof(how) ||
		    read_data(tracee, &how, address, sizeof(how)) < 0)
			return false;
		open_flags = how.flags;
		break;
	}
	default:
		return false;
	}

	if ((open_flags & O_CLOEXEC) != 0)
		event_flags |= EFD_CLOEXEC;
	if ((open_flags & O_NONBLOCK) != 0)
		event_flags |= EFD_NONBLOCK;
	set_sysnum(tracee, PR_eventfd2);
	poke_reg(tracee, SYSARG_1, 0);
	poke_reg(tracee, SYSARG_2, event_flags);
	return true;
}

static bool is_open_syscall(Sysnum syscall)
{
	return syscall == PR_open || syscall == PR_openat || syscall == PR_openat2;
}

static bool is_path_probe_syscall(Sysnum syscall)
{
	return syscall == PR_access || syscall == PR_faccessat ||
	       syscall == PR_faccessat2 || syscall == PR_fstatat64 ||
	       syscall == PR_newfstatat;
}

static int finish_fake_ioctl(FakeMountConfig *config, Tracee *tracee,
			     int result, bool from_sigsys)
{
	if (from_sigsys) {
		poke_reg(tracee, SYSARG_RESULT, (word_t)result);
		return 2;
	}
	{
		FakePending *pending = pending_for(config, tracee->pid, true);
		if (pending == NULL)
			return -ENOMEM;
		pending->ioctl_pending = true;
		pending->ioctl_result = result;
	}
	set_sysnum(tracee, PR_getpid);
	return 1;
}

static int fake_loop_control_ioctl(Extension *extension, Tracee *tracee,
				   bool from_sigsys)
{
	FakeMountConfig *config = talloc_get_type_abort(extension->config,
							FakeMountConfig);
	int fd = (int)peek_reg(tracee, CURRENT, SYSARG_1);
	unsigned long request = (unsigned long)peek_reg(tracee, CURRENT, SYSARG_2);
	word_t argument = peek_reg(tracee, CURRENT, SYSARG_3);
	FakeFd *fake_fd;
	int result;

	fake_fd = find_fake_fd(config, tracee->files_table_id, fd);
	if (fake_fd == NULL || fake_fd->kind != FAKE_FD_LOOP_CONTROL)
		return 0;
	switch (request) {
	case LOOP_CTL_GET_FREE:
		result = allocate_loop(tracee, config);
		break;
	case LOOP_CTL_ADD:
		if (argument >= FAKE_MOUNT_MAX_LOOPS)
			result = -EINVAL;
		else if (is_preallocated_host_loop((int)argument))
			result = -EEXIST;
		else
			result = add_loop(tracee, config, (int)argument);
		break;
	default:
		return 0;
	}
	return finish_fake_ioctl(config, tracee, result, from_sigsys);
}

static int set_loop_backing(Tracee *tracee, FakeLoop *loop, int backing_fd)
{
	int status = readlink_proc_pid_fd(tracee->pid, backing_fd,
					  loop->backing_path);

	if (status < 0)
		return status;
	if (!belongs_to_guestfs(tracee, loop->backing_path)) {
		loop->backing_path[0] = '\0';
		return -EINVAL;
	}
	loop->attached = true;
	return 0;
}

static int fake_loop_device_ioctl(Extension *extension, Tracee *tracee,
				  bool from_sigsys)
{
	FakeMountConfig *config = talloc_get_type_abort(extension->config,
							FakeMountConfig);
	int fd = (int)peek_reg(tracee, CURRENT, SYSARG_1);
	unsigned long request = (unsigned long)peek_reg(tracee, CURRENT, SYSARG_2);
	word_t argument = peek_reg(tracee, CURRENT, SYSARG_3);
	FakeFd *fake_fd = find_fake_fd(config, tracee->files_table_id, fd);
	FakeLoop *loop;
	int result;

	if (fake_fd == NULL || fake_fd->kind != FAKE_FD_LOOP)
		return 0;
	loop = &config->loops[fake_fd->device_number];

	switch (request) {
	case LOOP_SET_FD:
		result = set_loop_backing(tracee, loop, (int)argument);
		break;
	case LOOP_SET_STATUS64: {
		struct loop_info64 info;
		result = read_data(tracee, &info, argument, sizeof(info));
		if (result >= 0) {
			loop->info = info;
			loop->offset = info.lo_offset;
			loop->size_limit = info.lo_sizelimit;
			result = 0;
		}
		break;
	}
	case LOOP_CONFIGURE: {
		struct loop_config loop_config;
		result = read_data(tracee, &loop_config, argument,
				   sizeof(loop_config));
		if (result >= 0) {
			result = set_loop_backing(tracee, loop,
						  (int)loop_config.fd);
			if (result == 0) {
				loop->info = loop_config.info;
				loop->offset = loop_config.info.lo_offset;
				loop->size_limit = loop_config.info.lo_sizelimit;
			}
		}
		break;
	}
	case LOOP_GET_STATUS64: {
		struct loop_info64 info = loop->info;
		info.lo_number = (uint32_t)fake_fd->device_number;
		info.lo_offset = loop->offset;
		info.lo_sizelimit = loop->size_limit;
		result = write_data(tracee, argument, &info, sizeof(info));
		if (result >= 0)
			result = 0;
		break;
	}
	case LOOP_CLR_FD:
		remove_loop_node(config, fake_fd->device_number);
		memset(loop, 0, sizeof(*loop));
		result = 0;
		break;
	case LOOP_SET_CAPACITY:
	case LOOP_SET_DIRECT_IO:
	case LOOP_SET_BLOCK_SIZE:
	case BLKFLSBUF:
		result = 0;
		break;
	default:
		return 0;
	}
	return finish_fake_ioctl(config, tracee, result, from_sigsys);
}

static int find_apex_loop_from_table(Tracee *tracee, word_t argument,
				    const struct dm_ioctl *info,
				    FakeMountConfig *config)
{
	struct dm_target_spec spec;
	char parameters[4096];
	char *save_pointer = NULL;
	char *version;
	char *data_device;
	word_t spec_address;
	size_t parameters_size;
	int number;
	int status;

	if (info->data_start < sizeof(*info) ||
	    info->data_start > info->data_size ||
	    info->data_size - info->data_start < sizeof(spec))
		return -EINVAL;
	spec_address = argument + info->data_start;
	status = read_data(tracee, &spec, spec_address, sizeof(spec));
	if (status < 0)
		return status;
	spec.target_type[sizeof(spec.target_type) - 1] = '\0';
	if (strcmp(spec.target_type, "verity") != 0)
		return -ENOENT;
	parameters_size = info->data_size - info->data_start - sizeof(spec);
	if (parameters_size == 0 || parameters_size >= sizeof(parameters))
		return -EINVAL;
	status = read_data(tracee, parameters, spec_address + sizeof(spec),
			   parameters_size);
	if (status < 0)
		return status;
	parameters[parameters_size] = '\0';
	version = strtok_r(parameters, " \t\n", &save_pointer);
	data_device = strtok_r(NULL, " \t\n", &save_pointer);
	if (version == NULL || data_device == NULL)
		return -EINVAL;
	if (parse_device_number(data_device, "/dev/block/loop", &number) &&
	    parse_device_number(data_device, "/dev/loop", &number))
		return -ENOENT;
	if (!config->loops[number].attached ||
	    strstr(config->loops[number].backing_path, ".apex") == NULL)
		return -ENOENT;
	return number;
}

static FakeDm *find_fake_dm(FakeMountConfig *config,
			    const struct dm_ioctl *info)
{
	unsigned int i;
	int device_number = (int)minor((dev_t)info->dev);

	for (i = 0; i < FAKE_MOUNT_MAX_LOOPS; i++) {
		FakeDm *dm = &config->dms[i];
		if (!dm->active)
			continue;
		if (info->name[0] != '\0' && strcmp(dm->name, info->name) == 0)
			return dm;
		if (info->dev != 0 && (int)minor(dm->dev) == device_number)
			return dm;
	}
	return NULL;
}

static int fake_dm_ioctl(Extension *extension, Tracee *tracee,
			 bool from_sigsys)
{
	FakeMountConfig *config = talloc_get_type_abort(extension->config,
							FakeMountConfig);
	int fd = (int)peek_reg(tracee, CURRENT, SYSARG_1);
	unsigned long request = (unsigned long)peek_reg(tracee, CURRENT, SYSARG_2);
	word_t argument = peek_reg(tracee, CURRENT, SYSARG_3);
	FakeFd *fake_fd = find_fake_fd(config, tracee->files_table_id, fd);
	struct dm_ioctl info;
	FakeDm *dm;
	unsigned int i;
	int result;

	if (fake_fd == NULL || fake_fd->kind != FAKE_FD_DM_CONTROL)
		return 0;
	result = read_data(tracee, &info, argument, sizeof(info));
	if (result < 0)
		return finish_fake_ioctl(config, tracee, result, from_sigsys);
	info.name[sizeof(info.name) - 1] = '\0';

	switch (request) {
	case DM_VERSION:
		info.version[0] = DM_VERSION_MAJOR;
		info.version[1] = DM_VERSION_MINOR;
		info.version[2] = DM_VERSION_PATCHLEVEL;
		result = write_data(tracee, argument, &info, sizeof(info));
		if (result >= 0)
			result = 0;
		break;
	case DM_DEV_CREATE:
		if (info.name[0] == '\0' || find_fake_dm(config, &info) != NULL) {
			result = -EINVAL;
			break;
		}
		for (i = 0; i < FAKE_MOUNT_MAX_LOOPS; i++) {
			unsigned int candidate = (config->next_dm + i) %
					FAKE_MOUNT_MAX_LOOPS;
			if (config->dms[candidate].active)
				continue;
			dm = &config->dms[candidate];
			memset(dm, 0, sizeof(*dm));
			dm->active = true;
			dm->loop_number = -1;
			strncpy(dm->name, info.name, sizeof(dm->name) - 1);
			dm->dev = makedev(253, candidate);
			result = ensure_dm_node(tracee, config, (int)candidate);
			if (result < 0) {
				memset(dm, 0, sizeof(*dm));
				break;
			}
			config->next_dm = (candidate + 1) % FAKE_MOUNT_MAX_LOOPS;
			info.dev = (uint64_t)dm->dev;
			result = write_data(tracee, argument, &info, sizeof(info));
			if (result >= 0)
				result = 0;
			break;
		}
		if (i == FAKE_MOUNT_MAX_LOOPS)
			result = -ENOSPC;
		break;
	case DM_DEV_REMOVE:
		dm = find_fake_dm(config, &info);
		if (dm == NULL) {
			result = -ENXIO;
			break;
		}
		remove_dm_node(config, (int)minor(dm->dev));
		memset(dm, 0, sizeof(*dm));
		result = 0;
		break;
	case DM_DEV_STATUS:
	case DM_DEV_WAIT:
		dm = find_fake_dm(config, &info);
		if (dm == NULL) {
			result = -ENXIO;
			break;
		}
		info.dev = (uint64_t)dm->dev;
		info.flags = DM_ACTIVE_PRESENT_FLAG |
			(dm->table_loaded ? DM_INACTIVE_PRESENT_FLAG : 0);
		info.open_count = 0;
		info.event_nr = 0;
		result = write_data(tracee, argument, &info, sizeof(info));
		if (result >= 0)
			result = 0;
		break;
	case DM_DEV_SUSPEND:
		dm = find_fake_dm(config, &info);
		if (dm == NULL) {
			result = -ENXIO;
			break;
		}
		dm->suspended = (info.flags & DM_SUSPEND_FLAG) != 0;
		result = 0;
		break;
	case DM_TABLE_LOAD:
		dm = find_fake_dm(config, &info);
		if (dm == NULL) {
			result = -ENXIO;
			break;
		}
		dm->table_loaded = true;
		dm->loop_number = find_apex_loop_from_table(tracee, argument,
							   &info, config);
		result = 0;
		break;
	case DM_TABLE_CLEAR:
		dm = find_fake_dm(config, &info);
		if (dm == NULL) {
			result = -ENXIO;
			break;
		}
		dm->table_loaded = false;
		dm->loop_number = -1;
		result = 0;
		break;
	default:
		return 0;
	}
	return finish_fake_ioctl(config, tracee, result, from_sigsys);
}

static int copy_apex_payload(const FakeLoop *loop, const char *image_path)
{
	char buffer[64 * 1024];
	struct stat stat_buffer;
	uint64_t size;
	uint64_t copied = 0;
	int input_fd;
	int output_fd;
	int result = 0;

	input_fd = open(loop->backing_path, O_RDONLY | O_CLOEXEC);
	if (input_fd < 0)
		return -errno;
	if (fstat(input_fd, &stat_buffer) < 0) {
		result = -errno;
		goto end_input;
	}
	if (stat_buffer.st_size < 0 || loop->offset > (uint64_t)stat_buffer.st_size) {
		result = -EINVAL;
		goto end_input;
	}
	size = loop->size_limit != 0 ? loop->size_limit :
		(uint64_t)stat_buffer.st_size - loop->offset;
	if (size > (uint64_t)stat_buffer.st_size - loop->offset ||
	    loop->offset > INT64_MAX || size > INT64_MAX - loop->offset) {
		result = -EINVAL;
		goto end_input;
	}
	output_fd = open(image_path, O_CREAT | O_EXCL | O_WRONLY | O_CLOEXEC,
			 0600);
	if (output_fd < 0) {
		result = -errno;
		goto end_input;
	}
	while (copied < size) {
		size_t wanted = sizeof(buffer);
		ssize_t read_size;
		size_t written = 0;
		if (size - copied < wanted)
			wanted = (size_t)(size - copied);
		read_size = pread(input_fd, buffer, wanted,
				  (off_t)(loop->offset + copied));
		if (read_size < 0) {
			if (errno == EINTR)
				continue;
			result = -errno;
			break;
		}
		if (read_size == 0) {
			result = -EIO;
			break;
		}
		while (written < (size_t)read_size) {
			ssize_t write_size = write(output_fd, buffer + written,
						   (size_t)read_size - written);
			if (write_size < 0 && errno == EINTR)
				continue;
			if (write_size <= 0) {
				result = write_size < 0 ? -errno : -EIO;
				break;
			}
			written += (size_t)write_size;
		}
		if (result < 0)
			break;
		copied += (uint64_t)read_size;
	}
	(void)close(output_fd);
end_input:
	(void)close(input_fd);
	return result;
}

static int run_extractor(const char *program, char *const arguments[])
{
	pid_t child = fork();
	int status;

	if (child < 0)
		return -errno;
	if (child == 0) {
		execvp(program, arguments);
		_exit(127);
	}
	while (waitpid(child, &status, 0) < 0) {
		if (errno != EINTR)
			return -errno;
	}
	return WIFEXITED(status) && WEXITSTATUS(status) == 0 ? 0 : -EIO;
}

static int extract_apex_payload(FakeMountConfig *config, FakeLoop *loop,
				const char *filesystem)
{
	const char *tool;
	const char *temporary_directory;
	char image_path[PATH_MAX];
	char root_path[PATH_MAX];
	char debug_command[PATH_MAX + 32];
	int length;
	int status;

	temporary_directory = create_temp_directory((TALLOC_CTX *)config,
						     "proot-fake-apex-");
	if (temporary_directory == NULL)
		return -ENOMEM;
	length = snprintf(image_path, sizeof(image_path), "%s/payload.img",
			  temporary_directory);
	if (length < 0 || (size_t)length >= sizeof(image_path))
		return -ENAMETOOLONG;
	length = snprintf(root_path, sizeof(root_path), "%s/root",
			  temporary_directory);
	if (length < 0 || (size_t)length >= sizeof(root_path))
		return -ENAMETOOLONG;
	if (mkdir(root_path, 0777) < 0)
		return -errno;
	status = copy_apex_payload(loop, image_path);
	if (status < 0)
		return status;

	if (strcmp(filesystem, "ext4") == 0) {
		char *arguments[] = { NULL, "-R", debug_command, image_path, NULL };
		tool = getenv("PROOT_FAKE_MOUNT_DEBUGFS");
		if (tool == NULL || tool[0] == '\0')
			tool = "debugfs";
		length = snprintf(debug_command, sizeof(debug_command),
				  "rdump / \"%s\"", root_path);
		if (length < 0 || (size_t)length >= sizeof(debug_command))
			return -ENAMETOOLONG;
		arguments[0] = (char *)tool;
		status = run_extractor(tool, arguments);
	} else {
		char extract_option[PATH_MAX + 16];
		char *arguments[] = { NULL, extract_option, image_path, NULL };
		tool = getenv("PROOT_FAKE_MOUNT_FSCK_EROFS");
		if (tool == NULL || tool[0] == '\0')
			tool = "fsck.erofs";
		length = snprintf(extract_option, sizeof(extract_option),
				  "--extract=%s", root_path);
		if (length < 0 || (size_t)length >= sizeof(extract_option))
			return -ENAMETOOLONG;
		arguments[0] = (char *)tool;
		status = run_extractor(tool, arguments);
	}
	if (status < 0)
		return status;
	length = snprintf(loop->extracted_root, sizeof(loop->extracted_root),
			  "%s", root_path);
	return length < 0 || (size_t)length >= sizeof(loop->extracted_root) ?
		-ENAMETOOLONG : 0;
}

static int propagate_bootstrap_apex_mount(Tracee *tracee,
					  FakeMountConfig *config,
					  const char *host_path,
					  const char *guest_path)
{
	FakeMountNamespace *current_ns;
	FakeMountNamespace *default_ns;
	FileSystemNameSpace *current_fs;
	int status;

	if (config->bootstrap_namespace_id == 0 ||
	    config->default_namespace_id == 0 ||
	    strncmp(guest_path, "/bootstrap-apex/",
		    sizeof("/bootstrap-apex/") - 1) != 0)
		return 0;
	current_ns = mount_namespace_for_tracee(config, tracee, false);
	if (current_ns == NULL ||
	    current_ns->id != config->bootstrap_namespace_id)
		return 0;
	default_ns = find_mount_namespace(config,
					 config->default_namespace_id);
	if (default_ns == NULL || default_ns->owner == NULL)
		return -EINVAL;

	current_fs = tracee->fs;
	tracee->fs = default_ns->owner;
	status = insort_binding3(tracee, (TALLOC_CTX *)config, host_path,
				 guest_path) == NULL ? -ENOMEM : 0;
	tracee->fs = current_fs;
	return status;
}

static void remember_bootstrap_mount_target(Tracee *tracee,
					    FakeMountConfig *config,
					    FakePending *pending)
{
	FakeMountNamespace *current_ns;
	char target[PATH_MAX];
	char guest_path[PATH_MAX];
	unsigned long flags;
	int status;

	pending->bootstrap_mount_pending = false;
	if (get_sysnum(tracee, ORIGINAL) != PR_mount)
		return;
	flags = (unsigned long)peek_reg(tracee, CURRENT, SYSARG_4);
	if ((flags & MS_BIND) == 0)
		return;
	current_ns = mount_namespace_for_tracee(config, tracee, false);
	if (current_ns == NULL ||
	    current_ns->id != config->bootstrap_namespace_id)
		return;
	if (read_path(tracee, target,
		      peek_reg(tracee, CURRENT, SYSARG_2)) < 0)
		return;
	if (target[0] == '/')
		strcpy(guest_path, "/");
	else if (getcwd2(tracee, guest_path) < 0)
		return;
	status = canonicalize(tracee, target, true, guest_path, 0);
	if (status < 0)
		return;
	chop_finality(guest_path);
	if (strncmp(guest_path, "/bootstrap-apex/",
		    sizeof("/bootstrap-apex/") - 1) != 0)
		return;
	strncpy(pending->bootstrap_mount_guest_path, guest_path,
		sizeof(pending->bootstrap_mount_guest_path) - 1);
	pending->bootstrap_mount_guest_path[
		sizeof(pending->bootstrap_mount_guest_path) - 1] = '\0';
	pending->bootstrap_mount_pending = true;
}

static int fake_apex_mount(Extension *extension, Tracee *tracee)
{
	FakeMountConfig *config = talloc_get_type_abort(extension->config,
							FakeMountConfig);
	char source[PATH_MAX];
	char target[PATH_MAX];
	char filesystem[PATH_MAX];
	char guest_path[PATH_MAX];
	int number;
	int status;
	FakeLoop *loop;

	if (get_sysnum(tracee, CURRENT) != PR_mount)
		return 0;
	if (read_path(tracee, source, peek_reg(tracee, CURRENT, SYSARG_1)) < 0 ||
	    read_path(tracee, target, peek_reg(tracee, CURRENT, SYSARG_2)) < 0 ||
	    read_path(tracee, filesystem, peek_reg(tracee, CURRENT, SYSARG_3)) < 0)
		return 0;

	if (strcmp(filesystem, "ext4") != 0 && strcmp(filesystem, "erofs") != 0)
		return 0;
	if (!parse_device_number(source, "/dev/block/loop", &number) &&
	    !parse_device_number(source, "/dev/loop", &number)) {
		if (!parse_device_number(source, "/dev/block/dm-", &number) &&
		    !parse_device_number(source, "/dev/dm-", &number))
			return 0;
		if (!config->dms[number].active ||
		    config->dms[number].loop_number < 0)
			return 0;
		number = config->dms[number].loop_number;
	}
	if (number < 0 || number >= FAKE_MOUNT_MAX_LOOPS ||
	    !config->loops[number].attached)
		return 0;
	loop = &config->loops[number];

	if (strstr(loop->backing_path, ".apex") == NULL)
		return 0;
	if (loop->extracted_root[0] == '\0') {
		status = extract_apex_payload(config, loop, filesystem);
		if (status < 0)
			return status;
	}
	if (target[0] == '/')
		strcpy(guest_path, "/");
	else {
		status = getcwd2(tracee, guest_path);
		if (status < 0)
			return status;
	}
	status = canonicalize(tracee, target, true, guest_path, 0);

	if (status < 0)
		return status;
	chop_finality(guest_path);
	if (insort_binding3(tracee, tracee->fs, loop->extracted_root,
			    guest_path) == NULL)
		return -ENOMEM;
	status = propagate_bootstrap_apex_mount(tracee, config,
						loop->extracted_root,
						guest_path);
	if (status < 0)
		return status;

	set_sysnum(tracee, PR_void);
	poke_reg(tracee, SYSARG_RESULT, 0);
	return 1;
}

int fake_mount_callback(Extension *extension, ExtensionEvent event,
			intptr_t data1, intptr_t data2)
{
	Tracee *tracee = TRACEE(extension);
	FakeMountConfig *config;
	FakePending *pending;
	Sysnum syscall;

	switch (event) {
	case INITIALIZATION:
		extension->config = talloc_zero(extension, FakeMountConfig);
		if (extension->config == NULL)
			return -ENOMEM;
		config = talloc_get_type_abort(extension->config, FakeMountConfig);
		config->next_mount_namespace_id = 1;
		extension->filtered_sysnums = filtered_sysnums;
		return 0;

	case INHERIT_PARENT:
		return 0;

	case FILES_TABLE_CHANGED:
		config = talloc_get_type_abort(extension->config, FakeMountConfig);
		copy_fake_fds(tracee, config, (const FilesTableChange *)data1);
		return 0;

	default:
		break;
	}

	config = talloc_get_type_abort(extension->config, FakeMountConfig);
	pending = pending_for(config, tracee->pid, event != REMOVED);

	switch (event) {
	case GUEST_PATH:
		syscall = get_sysnum(tracee, ORIGINAL);
		if (pending != NULL && is_open_syscall(syscall)) {
			const char *host_path = (const char *)data1;
			const char *guest_path = (const char *)data2;

			if (is_mount_namespace_path(host_path) ||
			    is_mount_namespace_path(guest_path)) {
				FakeMountNamespace *ns =
					mount_namespace_for_tracee(config, tracee, true);
				pending->open_kind = FAKE_FD_MOUNT_NAMESPACE;
				pending->open_device_number = -1;
				pending->open_namespace_id = ns == NULL ? 0 : ns->id;
			} else {
				pending->open_kind = fake_device_path(config,
						 host_path, guest_path,
						 &pending->open_device_number);
				pending->open_namespace_id = 0;
			}
			pending->open_pending = pending->open_kind != FAKE_FD_NONE;
		}
		else if (pending != NULL &&
			 (syscall == PR_readlink || syscall == PR_readlinkat)) {
			const char *host_path = (const char *)data1;
			const char *guest_path = (const char *)data2;

			pending->mount_namespace_readlink_pending = false;
			if (is_mount_namespace_path(host_path) ||
			    is_mount_namespace_path(guest_path)) {
				FakeMountNamespace *ns =
					mount_namespace_for_tracee(config, tracee, true);
				if (ns != NULL) {
					pending->mount_namespace_readlink_pending = true;
					pending->mount_namespace_readlink_id = ns->id;
				}
			}
		}
		else if (is_path_probe_syscall(syscall)) {
			int device_number;
			if (fake_device_path(config, (const char *)data1,
					     (const char *)data2, &device_number) ==
			    FAKE_FD_LOOP_CONTROL)
			return ensure_loop_control_node(tracee, config);
		}
		return 0;

	case SYSCALL_ENTER_END:
		if (pending != NULL && pending->bootstrap_mount_pending) {
			Binding *binding = NULL;
			int status = 0;

			if ((intptr_t)data1 >= 0) {
				binding = get_binding(tracee, GUEST,
					pending->bootstrap_mount_guest_path);
				if (binding != NULL &&
				    strcmp(binding->guest.path,
					   pending->bootstrap_mount_guest_path) == 0)
					status = propagate_bootstrap_apex_mount(
						tracee, config, binding->host.path,
						binding->guest.path);
			}
			pending->bootstrap_mount_pending = false;
			if (status < 0)
				return status;
		}
		if (pending != NULL && pending->open_pending) {
			syscall = get_sysnum(tracee, ORIGINAL);
			(void)replace_open_with_eventfd(tracee, syscall);
		}
		return 0;

	case SYSCALL_ENTER_START:
		syscall = get_sysnum(tracee, ORIGINAL);
		if (pending != NULL)
			remember_bootstrap_mount_target(tracee, config, pending);
		if (pending != NULL &&
		    (syscall == PR_readlink || syscall == PR_readlinkat))
			pending->mount_namespace_readlink_pending = false;
		if (syscall == PR_unshare &&
		    (peek_reg(tracee, CURRENT, SYSARG_1) & CLONE_NEWNS) != 0) {
			int status = unshare_mount_namespace(tracee, config);
			if (status < 0)
				return status;
		}
		if (syscall == PR_setns &&
		    (peek_reg(tracee, CURRENT, SYSARG_2) & CLONE_NEWNS) != 0) {
			int fd = (int)peek_reg(tracee, CURRENT, SYSARG_1);
			FakeFd *entry = find_fake_fd(config, tracee->files_table_id, fd);

			if (entry != NULL && entry->kind == FAKE_FD_MOUNT_NAMESPACE) {
				FakeMountNamespace *ns = find_mount_namespace(
					config, entry->mount_namespace_id);
				int status = switch_mount_namespace(tracee, ns);
				if (status < 0)
					return status;
			}
		}
		if (syscall == PR_mount) {
			int status = fake_apex_mount(extension, tracee);
			if (status != 0)
				return status;
		}
		if (is_open_syscall(syscall) && pending != NULL) {
			pending->open_pending = false;
			pending->open_kind = FAKE_FD_NONE;
			pending->open_device_number = -1;
		}
		if (syscall == PR_close)
			forget_fake_fd(config, tracee->files_table_id,
				       (int)peek_reg(tracee, CURRENT, SYSARG_1));
		if (syscall == PR_ioctl) {
			int status = fake_loop_control_ioctl(extension, tracee, false);
			if (status != 0)
				return status;
			status = fake_loop_device_ioctl(extension, tracee, false);
			if (status != 0)
				return status;
			return fake_dm_ioctl(extension, tracee, false);
		}
		return 0;

	case SYSCALL_EXIT_END:
		if (pending == NULL)
			return 0;
		if (get_sysnum(tracee, ORIGINAL) == PR_readlink ||
		    get_sysnum(tracee, ORIGINAL) == PR_readlinkat)
			rewrite_mount_namespace_readlink(tracee,
				get_sysnum(tracee, ORIGINAL), pending);
		if (pending->open_pending) {
			long fd = (long)peek_reg(tracee, CURRENT, SYSARG_RESULT);
			if (fd >= 0 && pending->open_kind != FAKE_FD_NONE) {
				remember_fake_fd(config, tracee->files_table_id, (int)fd,
						pending->open_kind,
						pending->open_device_number);
				if (pending->open_kind == FAKE_FD_MOUNT_NAMESPACE) {
					FakeFd *entry = find_fake_fd(config,
						tracee->files_table_id, (int)fd);
					if (entry != NULL)
						entry->mount_namespace_id =
							pending->open_namespace_id;
				}
			}
			pending->open_pending = false;
			pending->open_kind = FAKE_FD_NONE;
			pending->open_namespace_id = 0;
		}
		if (pending->ioctl_pending) {
			poke_reg(tracee, SYSARG_RESULT, (word_t)pending->ioctl_result);
			pending->ioctl_pending = false;
		}
		return 0;

	case SIGSYS_OCC:
		if (get_sysnum(tracee, CURRENT) == PR_ioctl) {
			int status = fake_loop_control_ioctl(extension, tracee, true);
			if (status != 0)
				return status;
			status = fake_loop_device_ioctl(extension, tracee, true);
			if (status != 0)
				return status;
			return fake_dm_ioctl(extension, tracee, true);
		}
		return 0;

	case REMOVED:
		/* Reuse the per-tracee slot after its extension is detached. */
		if (pending != NULL)
			memset(pending, 0, sizeof(*pending));
		cleanup_fake_nodes(config);
		return 0;

	default:
		return 0;
	}
}
