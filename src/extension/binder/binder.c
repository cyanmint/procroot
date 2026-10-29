/*
 * SPDX-FileCopyrightText: NONE
 * SPDX-License-Identifier: GPL-2.0-or-later
 * Note: AI-generated contribution; no legal determination implied.
 */
/*
 * Userspace Binder UAPI compatibility layer.
 *
 * The protocol definitions and object translation rules are implemented from
 * the upstream Linux Binder UAPI reference copied in upstream/binder_uapi.h.
 * The copied reference retains its upstream copyright and SPDX notices; this
 * procroot broker is an independent userspace implementation and does not
 * compile the GPL kernel driver.
 */
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sched.h>
#include <sys/ioctl.h>
#include <sys/eventfd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/uio.h>
#include <sys/syscall.h>
#include <poll.h>
#include <time.h>
#include <unistd.h>
#include <linux/netlink.h>
#include <sys/reboot.h>
#include <sys/mman.h>
#include <talloc.h>

#include "extension/extension.h"
#include "syscall/syscall.h"
#include "syscall/sysnum.h"
#include "syscall/chain.h"
#include "extension/binder/fda_courier.h"
#include "tracee/mem.h"
#include "tracee/reg.h"
#include "tracee/tracee.h"

#define BINDER_IOCTL_TYPE 'b'
#define BINDER_CURRENT_PROTOCOL_VERSION 8

typedef uint64_t binder_uintptr_t;
typedef uint64_t binder_size_t;
struct binder_version { int32_t protocol_version; };
struct flat_binder_object {
	uint32_t hdr_type;
	uint32_t flags;
	union { uint32_t handle; uint64_t binder; } b;
	uint64_t cookie;
};
struct binder_buffer_object {
	uint32_t hdr_type;
	uint32_t flags;
	uint64_t buffer;
	uint64_t length;
	uint64_t parent;
	uint64_t parent_offset;
};
struct binder_fd_array_object {
	uint32_t hdr_type;
	uint32_t pad;
	uint64_t num_fds;
	uint64_t parent;
	uint64_t parent_offset;
};
#define BINDER_BUFFER_FLAG_HAS_PARENT 0x01
struct binder_context_mgr_ext { struct flat_binder_object obj; };
struct binder_handle_cookie {
	uint32_t handle;
	binder_uintptr_t cookie;
} __attribute__((packed));
struct binder_ptr_cookie {
	binder_uintptr_t ptr;
	binder_uintptr_t cookie;
};
struct binder_transaction_data {
	binder_uintptr_t target;
	binder_uintptr_t cookie;
	uint32_t code;
	uint32_t flags;
	int32_t sender_pid;
	uint32_t sender_euid;
	binder_size_t data_size;
	binder_size_t offsets_size;
	binder_uintptr_t data_buffer;
	binder_uintptr_t offsets_buffer;
};
struct binder_transaction_data_secctx {
	struct binder_transaction_data transaction_data;
	binder_uintptr_t secctx;
};
struct binder_transaction_data_sg {
	struct binder_transaction_data transaction_data;
	binder_size_t buffers_size;
};
struct binder_write_read {
	binder_size_t write_size;
	binder_size_t write_consumed;
	binder_uintptr_t write_buffer;
	binder_size_t read_size;
	binder_size_t read_consumed;
	binder_uintptr_t read_buffer;
};
#define BC_TRANSACTION _IOW('c', 0, struct binder_transaction_data)
#define BC_REPLY _IOW('c', 1, struct binder_transaction_data)
#define BC_FREE_BUFFER _IOW('c', 3, binder_uintptr_t)
#define BC_INCREFS _IOW('c', 4, uint32_t)
#define BC_ACQUIRE _IOW('c', 5, uint32_t)
#define BC_RELEASE _IOW('c', 6, uint32_t)
#define BC_DECREFS _IOW('c', 7, uint32_t)
#define BC_INCREFS_DONE _IOW('c', 8, struct binder_ptr_cookie)
#define BC_ACQUIRE_DONE _IOW('c', 9, struct binder_ptr_cookie)
#define BC_TRANSACTION_SG _IOW('c', 17, struct binder_transaction_data_sg)
#define BC_REPLY_SG _IOW('c', 18, struct binder_transaction_data_sg)
#define BC_REGISTER_LOOPER _IO('c', 11)
#define BC_ENTER_LOOPER _IO('c', 12)
#define BC_EXIT_LOOPER _IO('c', 13)
#define BC_REQUEST_DEATH_NOTIFICATION _IOW('c', 14, struct binder_handle_cookie)
#define BC_CLEAR_DEATH_NOTIFICATION _IOW('c', 15, struct binder_handle_cookie)
#define BC_DEAD_BINDER_DONE _IOW('c', 16, binder_uintptr_t)
#define BR_TRANSACTION _IOR('r', 2, struct binder_transaction_data)
#define BR_TRANSACTION_SEC_CTX \
	_IOR('r', 2, struct binder_transaction_data_secctx)
#define BR_REPLY _IOR('r', 3, struct binder_transaction_data)
#define BR_TRANSACTION_COMPLETE _IO('r', 6)
#define BR_INCREFS _IOR('r', 7, struct binder_ptr_cookie)
#define BR_ACQUIRE _IOR('r', 8, struct binder_ptr_cookie)
#define BR_RELEASE _IOR('r', 9, struct binder_ptr_cookie)
#define BR_DECREFS _IOR('r', 10, struct binder_ptr_cookie)
#define BR_NOOP _IO('r', 12)
#define BR_DEAD_BINDER _IOR('r', 15, binder_uintptr_t)
#define BR_CLEAR_DEATH_NOTIFICATION_DONE _IOR('r', 16, binder_uintptr_t)
#define BR_FAILED_REPLY _IO('r', 17)
#define BR_DEAD_REPLY _IO('r', 5)
#define BINDER_VERSION _IOWR(BINDER_IOCTL_TYPE, 9, struct binder_version)
#define BINDER_SET_MAX_THREADS _IOW(BINDER_IOCTL_TYPE, 5, uint32_t)
#define BINDER_SET_CONTEXT_MGR _IOW(BINDER_IOCTL_TYPE, 7, uint32_t)
#define BINDER_SET_CONTEXT_MGR_EXT _IOW(BINDER_IOCTL_TYPE, 13, struct binder_context_mgr_ext)
#define BINDER_THREAD_EXIT _IOW(BINDER_IOCTL_TYPE, 8, uint32_t)
#define BINDER_WRITE_READ _IOWR(BINDER_IOCTL_TYPE, 1, struct binder_write_read)
struct procroot_binderfs_device {
	char name[256];
	uint32_t major;
	uint32_t minor;
};
#define BINDER_CTL_ADD _IOWR(BINDER_IOCTL_TYPE, 1, struct procroot_binderfs_device)
#define IS_BINDER_CTL(req) (((req >> 8) & 0xff) == BINDER_IOCTL_TYPE && \
	((req & 0xff) == 1) && (((req >> 16) & 0x3fff) > sizeof(struct binder_write_read)))
#define MAX_BINDER_FDS 64
#define MAX_BINDER_QUEUE 64
#define MAX_BINDER_REPLY_WORDS 256
#define MAX_BINDER_ENDPOINTS 128
#define MAX_BINDER_TRANSACTIONS 32
#define MAX_BINDER_THREADS 256
#define MAX_BINDER_TRANSACTION_DEPTH 64
#define MAX_BINDER_PAYLOAD 65536
#define MAX_BINDER_OFFSETS (MAX_BINDER_PAYLOAD / sizeof(uint64_t))
#define MAX_BINDER_BUFFERS 256
#define B_PACK_CHARS(c1, c2, c3, c4) \
	((((uint32_t)(c1)) << 24) | (((uint32_t)(c2)) << 16) | \
	 (((uint32_t)(c3)) << 8) | (uint32_t)(c4))
#define B_TYPE_LARGE 0x85
#define BINDER_TYPE_BINDER B_PACK_CHARS('s', 'b', '*', B_TYPE_LARGE)
#define BINDER_TYPE_WEAK_BINDER B_PACK_CHARS('w', 'b', '*', B_TYPE_LARGE)
#define BINDER_TYPE_HANDLE B_PACK_CHARS('s', 'h', '*', B_TYPE_LARGE)
#define BINDER_TYPE_WEAK_HANDLE B_PACK_CHARS('w', 'h', '*', B_TYPE_LARGE)
#define BINDER_TYPE_FD B_PACK_CHARS('f', 'd', '*', B_TYPE_LARGE)
#define BINDER_TYPE_FDA B_PACK_CHARS('f', 'd', 'a', B_TYPE_LARGE)
#define BINDER_TYPE_PTR B_PACK_CHARS('p', 't', '*', B_TYPE_LARGE)
#define BINDER_TF_ONE_WAY 0x01u
#define BINDER_TF_ACCEPT_FDS 0x10u
#define FLAT_BINDER_FLAG_TXN_SECURITY_CTX 0x1000u

enum BinderDomain {
	BINDER_DOMAIN_BINDER = 0,
	BINDER_DOMAIN_HWBINDER,
	BINDER_DOMAIN_VNDBINDER,
	BINDER_DOMAIN_COUNT,
	BINDER_DOMAIN_NONE = -1,
};

typedef struct BinderEndpoint BinderEndpoint;
typedef struct BinderConfig BinderConfig;
enum BinderTransactionFrameType {
	BINDER_TRANSACTION_INBOUND,
	BINDER_TRANSACTION_OUTBOUND,
};
typedef struct {
	BinderConfig *previous_sender;
	enum BinderDomain previous_domain;
	enum BinderDomain domain;
	enum BinderTransactionFrameType type;
	uint32_t request_flags;
	uint64_t transaction_id;
} BinderTransactionFrame;
typedef struct {
	BinderEndpoint *endpoint;
	uint64_t owner_generation;
	binder_uintptr_t node;
	binder_uintptr_t cookie;
	uint32_t weak_refs;
	uint32_t strong_refs;
	bool transaction_security_context;
	bool death_notification;
	bool death_pending;
	binder_uintptr_t death_cookie;
} BinderHandle;
typedef struct {
	int fd;
	bool active;
	enum BinderDomain domain;
	bool uevent_socket;
	bool context_manager;
	uint32_t max_threads;
	uint32_t read_words[MAX_BINDER_REPLY_WORDS];
	size_t read_count;
} BinderFd;
typedef struct {
	word_t address;
	size_t size;
	bool active;
	enum BinderDomain domain;
	struct BinderBufferReference *references;
	size_t reference_count;
	size_t references_released;
} BinderBuffer;
typedef struct BinderBufferReference {
	uint32_t handle;
	bool strong;
} BinderBufferReference;
typedef struct {
	word_t address;
	size_t size;
} BinderMapping;
typedef struct {
	int source_fd;
	int staged_fd;
	enum BinderDomain domain;
	size_t slot_offset;
	bool slot_in_extra;
	word_t recipient_slot_address;
} BinderFdTransfer;
typedef struct {
	uint32_t command;
	struct binder_transaction_data transaction;
	enum BinderDomain domain;
	size_t payload_size;
	size_t extra_size;
	size_t offsets_size;
	bool scatter_gather;
	bool security_context;
	uint64_t id;
	uint64_t reply_frame_id;
	BinderConfig *reply_sender;
	bool fda_reply;
	BinderFdTransfer *fd_transfers;
	size_t fd_transfer_count;
	int courier_listener;
	bool delivery_pending;
	struct BinderBufferReference *references;
	size_t reference_count;
	size_t references_released;
	uint8_t *payload;
	uint64_t *offsets;
	BinderConfig *sender;
	BinderConfig *target_thread;
} BinderTransaction;
enum BinderFdaChainStage {
	BINDER_FDA_CHAIN_IDLE,
	BINDER_FDA_CHAIN_SOCKET,
	BINDER_FDA_CHAIN_CONNECT,
	BINDER_FDA_CHAIN_RECVMSG,
	BINDER_FDA_CHAIN_CLOSE_RECIPIENT,
	BINDER_FDA_CHAIN_CLOSE_SOCKET,
};
struct BinderEndpoint {
	Tracee *tracee;
	uint64_t generation;
	pid_t host_pid;
	size_t references;
	bool context_manager;
	bool context_security_context;
	binder_uintptr_t context_node;
	binder_uintptr_t context_cookie;
	BinderTransaction queue[MAX_BINDER_TRANSACTIONS];
	size_t queue_count;
	BinderBuffer buffers[MAX_BINDER_BUFFERS];
	BinderMapping mappings[BINDER_DOMAIN_COUNT];
	BinderHandle handles[BINDER_DOMAIN_COUNT][256];
	BinderConfig *threads[MAX_BINDER_THREADS];
	size_t thread_count;
};
struct BinderConfig {
	Tracee *tracee;
	bool last_binder_path;
	enum BinderDomain last_domain;
	bool uevent_socket_pending;
	bool ioctl_pending;
	int pending_fd;
	unsigned long pending_request;
	word_t pending_arg;
	bool mmap_pending;
	enum BinderDomain pending_mmap_domain;
	size_t pending_mmap_size;
	BinderEndpoint *endpoint;
	BinderConfig *last_sender;
	enum BinderDomain last_sender_domain;
	BinderTransactionFrame transaction_stack[MAX_BINDER_TRANSACTION_DEPTH];
	size_t transaction_depth;
	enum BinderFdaChainStage fda_chain_stage;
	uint64_t fda_transaction_id;
	word_t fda_bwr_arg;
	word_t fda_delivery_buffer;
	size_t fda_read_consumed;
	size_t fda_scratch_size;
	struct binder_write_read fda_bwr;
	word_t fda_scratch;
	int fda_courier_fd;
	int fda_recipient_fds[MAX_BINDER_FDS];
	size_t fda_recipient_fd_count;
	size_t fda_recipient_fd_close_index;
	int fda_chain_result;
	BinderFd fds[MAX_BINDER_FDS];
};
struct BinderFdaCourierReceiveScratch {
	struct msghdr message;
	union {
		struct cmsghdr align;
		unsigned char bytes[CMSG_SPACE(sizeof(int) * MAX_BINDER_FDS)];
	} control;
};
#define BINDER_FDA_COURIER_NAME_MAX 38
struct BinderFdaCourierScratch {
	union {
		unsigned char address[
			offsetof(struct sockaddr_un, sun_path) + 1 +
			BINDER_FDA_COURIER_NAME_MAX];
		struct BinderFdaCourierReceiveScratch receive;
	} data;
};
static struct {
	BinderEndpoint endpoints[MAX_BINDER_ENDPOINTS];
	size_t count;
	BinderEndpoint *context_manager[BINDER_DOMAIN_COUNT];
} binder_broker;
static uint32_t binderfs_next_minor;
static bool binderfs_allocated[BINDER_DOMAIN_COUNT];

static int release_buffer_references(BinderEndpoint *endpoint,
		BinderBuffer *buffer);
static int enqueue_death_work(BinderEndpoint *target,
		enum BinderDomain domain, uint32_t command,
		binder_uintptr_t cookie, BinderConfig *target_thread);
static void close_transaction_fda(BinderTransaction *item);
static void free_transaction_buffers(BinderTransaction *item);
static int release_transaction_references(BinderEndpoint *endpoint,
		BinderTransaction *item);
static int prepare_transaction_references(BinderEndpoint *recipient,
		BinderTransaction *item);

static uint64_t binder_next_transaction_id = 1;
static uint64_t binder_next_endpoint_generation = 1;

static uint64_t new_endpoint_generation(void)
{
	uint64_t generation = binder_next_endpoint_generation++;

	if (generation == 0)
		generation = binder_next_endpoint_generation++;
	return generation;
}

static uint64_t new_transaction_id(void)
{
	uint64_t id = binder_next_transaction_id++;

	if (id == 0)
		id = binder_next_transaction_id++;
	return id;
}

static bool transaction_stack_has_room(const BinderConfig *config)
{
	return config->transaction_depth < MAX_BINDER_TRANSACTION_DEPTH;
}

static int push_transaction_frame(BinderConfig *config,
		enum BinderTransactionFrameType type, enum BinderDomain domain,
		uint32_t request_flags, uint64_t transaction_id)
{
	BinderTransactionFrame *frame;

	if (!transaction_stack_has_room(config))
		return -EOVERFLOW;
	frame = &config->transaction_stack[config->transaction_depth++];
	frame->previous_sender = config->last_sender;
	frame->previous_domain = config->last_sender_domain;
	frame->domain = domain;
	frame->type = type;
	frame->request_flags = request_flags;
	frame->transaction_id = transaction_id;
	return 0;
}

static bool transaction_frame_matches(const BinderConfig *config,
		enum BinderTransactionFrameType type, enum BinderDomain domain,
		uint64_t transaction_id)
{
	const BinderTransactionFrame *frame;

	if (config->transaction_depth == 0)
		return false;
	frame = &config->transaction_stack[config->transaction_depth - 1];
	return frame->type == type && frame->domain == domain &&
		(transaction_id == 0 || frame->transaction_id == transaction_id);
}

static bool reply_frames_match(const BinderConfig *reply_sender,
		const BinderConfig *reply_target, enum BinderDomain domain,
		uint64_t transaction_id)
{
	if (reply_target == NULL)
		return false;
	if (reply_sender == NULL)
		return transaction_frame_matches(reply_target,
			BINDER_TRANSACTION_OUTBOUND, domain, transaction_id);
	if (reply_sender != reply_target)
		return transaction_frame_matches(reply_sender,
			BINDER_TRANSACTION_INBOUND, domain, transaction_id) &&
			transaction_frame_matches(reply_target,
			BINDER_TRANSACTION_OUTBOUND, domain, transaction_id);
	if (reply_sender->transaction_depth < 2)
		return false;
	{
		const BinderTransactionFrame *inbound =
			&reply_sender->transaction_stack[
				reply_sender->transaction_depth - 1];
		const BinderTransactionFrame *outbound =
			&reply_sender->transaction_stack[
				reply_sender->transaction_depth - 2];
		return inbound->type == BINDER_TRANSACTION_INBOUND &&
			inbound->domain == domain &&
			inbound->transaction_id == transaction_id &&
			outbound->type == BINDER_TRANSACTION_OUTBOUND &&
			outbound->domain == domain &&
			outbound->transaction_id == transaction_id;
	}
}

static int pop_transaction_frame(BinderConfig *config,
		enum BinderTransactionFrameType type, enum BinderDomain domain,
		uint64_t transaction_id)
{
	BinderTransactionFrame *frame;

	if (!transaction_frame_matches(config, type, domain, transaction_id))
		return -EINVAL;
	frame = &config->transaction_stack[--config->transaction_depth];
	config->last_sender = frame->previous_sender;
	config->last_sender_domain = frame->previous_domain;
	memset(frame, 0, sizeof(*frame));
	return 0;
}

static void forget_sender_references(BinderConfig *config,
		BinderConfig *sender, BinderEndpoint *endpoint)
{
	size_t i;

	if (config->last_sender != NULL &&
	    (config->last_sender == sender ||
	     (endpoint != NULL && config->last_sender->endpoint == endpoint))) {
		config->last_sender = NULL;
		config->last_sender_domain = BINDER_DOMAIN_NONE;
	}
	for (i = 0; i < config->transaction_depth; i++) {
		BinderTransactionFrame *frame = &config->transaction_stack[i];

		if ((sender != NULL && frame->previous_sender == sender) ||
		    (frame->previous_sender != NULL && endpoint != NULL &&
		     frame->previous_sender->endpoint == endpoint)) {
			frame->previous_sender = NULL;
			frame->previous_domain = BINDER_DOMAIN_NONE;
		}
	}
}

static FilteredSysnum filtered_sysnums[] = {
	{ PR_open, FILTER_SYSEXIT }, { PR_openat, FILTER_SYSEXIT },
	{ PR_openat2, FILTER_SYSEXIT }, { PR_eventfd2, FILTER_SYSEXIT },
	{ PR_ioctl, FILTER_SYSEXIT },
	{ PR_x32_ioctl, FILTER_SYSEXIT },
	{ PR_mmap, FILTER_SYSEXIT }, { PR_mmap2, FILTER_SYSEXIT },
	{ PR_mknod, FILTER_SYSEXIT }, { PR_mknodat, FILTER_SYSEXIT },
	{ PR_socket, FILTER_SYSEXIT }, { PR_bind, 0 }, { PR_close, 0 },
	FILTERED_SYSNUM_END,
};
static enum BinderDomain binder_domain(const char *p)
{
	const char *name;

	if (strcmp(p, "/dev/hwbinder") == 0)
		return BINDER_DOMAIN_HWBINDER;
	if (strcmp(p, "/dev/vndbinder") == 0)
		return BINDER_DOMAIN_VNDBINDER;
	if (strcmp(p, "/dev/binder") == 0 ||
	    strcmp(p, "/dev/binder-control") == 0)
		return BINDER_DOMAIN_BINDER;
	if (strncmp(p, "/dev/binderfs/", 14) != 0)
		return BINDER_DOMAIN_NONE;

	name = p + 14;
	if (strchr(name, '/') != NULL)
		return BINDER_DOMAIN_NONE;
	if (strcmp(name, "hwbinder") == 0)
		return BINDER_DOMAIN_HWBINDER;
	if (strcmp(name, "vndbinder") == 0)
		return BINDER_DOMAIN_VNDBINDER;
	if (strcmp(name, "binder") == 0 || strcmp(name, "binder-control") == 0)
		return BINDER_DOMAIN_BINDER;
	return BINDER_DOMAIN_NONE;
}
static BinderFd *find_fd(BinderConfig *c, int fd)
{
	int i; for (i = 0; i < MAX_BINDER_FDS; i++)
		if (c->fds[i].active && c->fds[i].fd == fd) return &c->fds[i];
	return NULL;
}
static pid_t tracee_host_pid(const Tracee *tracee)
{
	char path[64];
	char line[128];
	FILE *status;
	pid_t host_pid = tracee->pid;

	if (snprintf(path, sizeof(path), "/proc/%d/status", tracee->pid) < 0)
		return host_pid;
	status = fopen(path, "r");
	if (status == NULL)
		return host_pid;
	while (fgets(line, sizeof(line), status) != NULL)
		if (sscanf(line, "Tgid: %d", &host_pid) == 1)
			break;
	fclose(status);
	return host_pid;
}
static void remember_fd_for_config(BinderConfig *config, int fd,
		enum BinderDomain domain)
{
	int i;
	BinderFd *binder_fd = find_fd(config, fd);

	if (binder_fd != NULL) {
		if (binder_fd->domain != domain) {
			memset(binder_fd, 0, sizeof(*binder_fd));
			binder_fd->active = true;
			binder_fd->fd = fd;
			binder_fd->domain = domain;
		}
		return;
	}
	for (i = 0; i < MAX_BINDER_FDS; i++)
		if (!config->fds[i].active) {
			config->fds[i].active = true;
			config->fds[i].fd = fd;
			config->fds[i].domain = domain;
			return;
		}
}

static void remember_fd(BinderConfig *c, int fd, enum BinderDomain domain)
{
	BinderEndpoint *endpoint = c->endpoint;
	size_t i;

	if (endpoint != NULL && c->tracee != NULL)
		endpoint->host_pid = tracee_host_pid(c->tracee);
	if (fd < 0)
		return;
	if (endpoint == NULL) {
		remember_fd_for_config(c, fd, domain);
		return;
	}
	/* CLONE_THREAD shares its file table, so every thread's BinderConfig
	 * must agree on the domain associated with a newly opened/reused fd. */
	for (i = 0; i < endpoint->thread_count; i++)
		if (endpoint->threads[i] != NULL)
			remember_fd_for_config(endpoint->threads[i], fd, domain);
}
static bool endpoint_has_pending(const BinderEndpoint *endpoint,
		enum BinderDomain domain)
{
	size_t i;
	for (i = 0; i < endpoint->queue_count; i++)
		if (endpoint->queue[i].domain == domain)
			return true;
	return false;
}
static int open_endpoint_eventfd(const BinderEndpoint *endpoint,
		const BinderFd *binder_fd)
{
	char path[64];
	char target[64];
	int length;
	ssize_t target_length;
	int pid_fd;
	int event_fd;

	pid_fd = (int)syscall(SYS_pidfd_open, endpoint->host_pid, 0);
	if (pid_fd < 0)
		return -1;
	event_fd = (int)syscall(SYS_pidfd_getfd, pid_fd, binder_fd->fd, 0);
	close(pid_fd);
	if (event_fd < 0)
		return -1;
	length = snprintf(path, sizeof(path), "/proc/self/fd/%d", event_fd);
	if (length < 0 || (size_t)length >= sizeof(path))
		goto error;
	target_length = readlink(path, target, sizeof(target) - 1);
	if (target_length < 0)
		goto error;
	target[target_length] = '\0';
	if (strcmp(target, "anon_inode:[eventfd]") != 0) {
		errno = EINVAL;
		goto error;
	}
	return event_fd;

error:
	close(event_fd);
	return -1;
}
static void notify_endpoint(BinderEndpoint *endpoint,
		enum BinderDomain domain)
{
	uint64_t increment = 1;
	size_t i;

	for (i = 0; i < endpoint->thread_count; i++) {
		BinderConfig *config = endpoint->threads[i];
		size_t j;

		for (j = 0; j < MAX_BINDER_FDS; j++) {
			BinderFd *binder_fd = &config->fds[j];
			int event_fd;

			if (!binder_fd->active || binder_fd->domain != domain)
				continue;
			event_fd = open_endpoint_eventfd(endpoint, binder_fd);
			if (event_fd < 0)
				continue;
			(void)write(event_fd, &increment, sizeof(increment));
			close(event_fd);
		}
	}
}
static void clear_endpoint_eventfd(BinderEndpoint *endpoint,
		enum BinderDomain domain)
{
	size_t i;

	for (i = 0; i < endpoint->thread_count; i++) {
		BinderConfig *config = endpoint->threads[i];
		size_t j;

		for (j = 0; j < MAX_BINDER_FDS; j++) {
			BinderFd *binder_fd = &config->fds[j];
			struct pollfd poll_fd;
			uint64_t count;
			int event_fd;

			if (!binder_fd->active || binder_fd->domain != domain)
				continue;
			event_fd = open_endpoint_eventfd(endpoint, binder_fd);
			if (event_fd < 0)
				continue;
			poll_fd = (struct pollfd) {
				.fd = event_fd,
				.events = POLLIN,
			};
			if (poll(&poll_fd, 1, 0) > 0 &&
			    (poll_fd.revents & POLLIN) != 0)
				(void)read(event_fd, &count, sizeof(count));
			close(event_fd);
		}
	}
}
static bool replace_binder_open_with_eventfd(Tracee *tracee, Sysnum syscall)
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
		word_t how = peek_reg(tracee, CURRENT, SYSARG_3);
		word_t size = peek_reg(tracee, CURRENT, SYSARG_4);

		if (size < sizeof(open_flags) ||
		    read_data(tracee, &open_flags, how, sizeof(open_flags)) < 0)
			return false;
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
static void remember_uevent_socket(BinderConfig *c, int fd)
{
	int i;
	BinderFd *f;

	if (fd < 0)
		return;
	f = find_fd(c, fd);
	if (f != NULL) {
		f->uevent_socket = true;
		return;
	}
	for (i = 0; i < MAX_BINDER_FDS; i++) {
		if (!c->fds[i].active) {
			c->fds[i].active = true;
			c->fds[i].fd = fd;
			c->fds[i].domain = BINDER_DOMAIN_NONE;
			c->fds[i].uevent_socket = true;
			return;
		}
	}
}
static bool is_uevent_socket(BinderConfig *c, int fd)
{
	BinderFd *f = find_fd(c, fd);
	return f != NULL && f->uevent_socket;
}
static BinderEndpoint *endpoint_for(Tracee *tracee)
{
	size_t i;
	size_t free_slot = MAX_BINDER_ENDPOINTS;

	for (i = 0; i < binder_broker.count; i++) {
		if (binder_broker.endpoints[i].tracee == tracee)
			return &binder_broker.endpoints[i];
		if (binder_broker.endpoints[i].tracee == NULL &&
		    free_slot == MAX_BINDER_ENDPOINTS)
			free_slot = i;
	}
	if (free_slot == MAX_BINDER_ENDPOINTS) {
		if (binder_broker.count == MAX_BINDER_ENDPOINTS)
			return NULL;
		free_slot = binder_broker.count++;
	}
	memset(&binder_broker.endpoints[free_slot], 0,
	       sizeof(binder_broker.endpoints[free_slot]));
	binder_broker.endpoints[free_slot].tracee = tracee;
	binder_broker.endpoints[free_slot].generation =
		new_endpoint_generation();
	binder_broker.endpoints[free_slot].host_pid = tracee->pid;
	return &binder_broker.endpoints[free_slot];
}

static int register_thread_config(BinderEndpoint *endpoint, BinderConfig *config)
{
	if (endpoint == NULL || config == NULL ||
	    endpoint->thread_count == MAX_BINDER_THREADS)
		return -ENOSPC;
	endpoint->threads[endpoint->thread_count++] = config;
	config->endpoint = endpoint;
	config->last_sender = NULL;
	config->last_sender_domain = BINDER_DOMAIN_NONE;
	config->transaction_depth = 0;
	endpoint->references++;
	return 0;
}

static int free_buffer(BinderEndpoint *endpoint, word_t address);

static void unregister_thread_config(BinderEndpoint *endpoint,
		BinderConfig *config)
{
	BinderEndpoint *owned_endpoint = config->endpoint;
	size_t i;
	if (owned_endpoint != NULL && config->fda_delivery_buffer != 0)
		(void)free_buffer(owned_endpoint, config->fda_delivery_buffer);
	config->fda_delivery_buffer = 0;
	config->fda_chain_stage = BINDER_FDA_CHAIN_IDLE;
	config->fda_transaction_id = 0;
	config->fda_courier_fd = -1;
	config->fda_recipient_fd_count = 0;
	config->fda_recipient_fd_close_index = 0;
	size_t j;

	for (i = 0; i < binder_broker.count; i++) {
		BinderEndpoint *other = &binder_broker.endpoints[i];

		if (other->tracee == NULL)
			continue;
		for (j = 0; j < other->thread_count; j++) {
			if (other->threads[j] != config)
				forget_sender_references(other->threads[j], config, NULL);
		}
		j = 0;
		while (j < other->queue_count) {
			BinderTransaction *item = &other->queue[j];
			enum BinderDomain item_domain;

			if (item->command == BR_REPLY &&
			    item->reply_sender == config &&
			    item->target_thread != config && item->sender != config) {
				/* The reply has been accepted into the broker queue.  Its
				 * source thread may exit before the recipient reads it; the
				 * recipient's outbound frame is the remaining commit key. */
				item->reply_sender = NULL;
				j++;
				continue;
			}
			if (item->sender != config && item->target_thread != config &&
			    item->reply_sender != config) {
				j++;
				continue;
			}
			item_domain = item->domain;
			if (release_transaction_references(other, item) < 0)
				fprintf(stderr,
					"[BINDER_REF_RELEASE_FAIL] queued transaction cleanup\n");
			close_transaction_fda(item);
			free_transaction_buffers(item);
			if (j + 1 < other->queue_count)
				memmove(item, item + 1,
					(other->queue_count - j - 1) * sizeof(*item));
			other->queue_count--;
			memset(&other->queue[other->queue_count], 0,
				sizeof(other->queue[0]));
			other->queue[other->queue_count].courier_listener = -1;
			if (!endpoint_has_pending(other, item_domain))
				clear_endpoint_eventfd(other, item_domain);
		}
	}
	if (endpoint != NULL) {
		for (i = 0; i < endpoint->thread_count; i++) {
			if (endpoint->threads[i] != config)
				continue;
			if (i + 1 < endpoint->thread_count)
				memmove(&endpoint->threads[i], &endpoint->threads[i + 1],
					(endpoint->thread_count - i - 1) *
					sizeof(endpoint->threads[0]));
			endpoint->thread_count--;
			break;
		}
		if (endpoint->references > 0)
			endpoint->references--;
		if (endpoint->tracee == config->tracee)
			endpoint->tracee = endpoint->thread_count != 0
				? endpoint->threads[0]->tracee : NULL;
	}
	config->last_sender = NULL;
	config->last_sender_domain = BINDER_DOMAIN_NONE;
	config->transaction_depth = 0;
	config->endpoint = NULL;
	config->tracee = NULL;
}

static void release_endpoint(BinderEndpoint *endpoint)
{
	size_t i;
	size_t j;
	size_t k;

	if (endpoint == NULL)
		return;
	for (i = 0; i < MAX_BINDER_BUFFERS; i++) {
		BinderBuffer *buffer = &endpoint->buffers[i];

		if (buffer->references == NULL)
			continue;
		(void)release_buffer_references(endpoint, buffer);
		free(buffer->references);
		buffer->references = NULL;
	}
	endpoint->tracee = NULL;
	for (i = 0; i < endpoint->queue_count; i++) {
		if (release_transaction_references(endpoint,
				&endpoint->queue[i]) < 0)
			fprintf(stderr,
				"[BINDER_REF_RELEASE_FAIL] endpoint cleanup\n");
		close_transaction_fda(&endpoint->queue[i]);
		free_transaction_buffers(&endpoint->queue[i]);
	}
	for (i = 0; i < BINDER_DOMAIN_COUNT; i++) {
		if (binder_broker.context_manager[i] == endpoint)
			binder_broker.context_manager[i] = NULL;
	}
	for (i = 0; i < binder_broker.count; i++) {
		BinderEndpoint *other = &binder_broker.endpoints[i];

		if (other->tracee == NULL || other == endpoint)
			continue;
		for (j = 0; j < other->thread_count; j++)
			forget_sender_references(other->threads[j], NULL, endpoint);
		for (j = 0; j < BINDER_DOMAIN_COUNT; j++) {
			for (k = 0; k < sizeof(other->handles[j]) /
					sizeof(other->handles[j][0]); k++) {
				BinderHandle *reference = &other->handles[j][k];

				if (reference->endpoint != endpoint)
					continue;
				if (!reference->death_notification) {
					reference->endpoint = NULL;
					/* Preserve the dead node identity for later transfers. */
					reference->death_cookie = 0;
					if (reference->strong_refs == 0 &&
					    reference->weak_refs == 0 &&
					    !reference->death_pending)
						memset(reference, 0, sizeof(*reference));
					continue;
				}
				if (enqueue_death_work(other, (enum BinderDomain)j,
					BR_DEAD_BINDER, reference->death_cookie,
					NULL) < 0)
					fprintf(stderr,
						"[BINDER_DEATH_ENQUEUE_FAIL] domain=%zu\n",
						j);
				reference->endpoint = NULL;
				reference->death_notification = false;
				reference->death_pending = true;
			}
		}
	}
	memset(endpoint, 0, sizeof(*endpoint));
}

static BinderEndpoint *target_for(BinderEndpoint *sender,
		enum BinderDomain domain, uint32_t handle,
		binder_uintptr_t *node, binder_uintptr_t *cookie)
{
	if (node != NULL)
		*node = 0;
	if (cookie != NULL)
		*cookie = 0;
	if (domain < 0 || domain >= BINDER_DOMAIN_COUNT)
		return NULL;
	if (handle == 0) {
		BinderEndpoint *manager = binder_broker.context_manager[domain];
		if (manager != NULL) {
			if (node != NULL)
				*node = manager->context_node;
			if (cookie != NULL)
				*cookie = manager->context_cookie;
		}
		return manager;
	}
	if (sender == NULL || handle >= 256 ||
	    sender->handles[domain][handle].endpoint == NULL)
		return NULL;
	if (node != NULL)
		*node = sender->handles[domain][handle].node;
	if (cookie != NULL)
		*cookie = sender->handles[domain][handle].cookie;
	return sender->handles[domain][handle].endpoint;
}

static uint32_t target_failure_command(const BinderEndpoint *sender,
		enum BinderDomain domain, binder_uintptr_t handle)
{
	const BinderHandle *reference;

	if (domain < 0 || domain >= BINDER_DOMAIN_COUNT)
		return BR_FAILED_REPLY;
	if (handle == 0)
		return binder_broker.context_manager[domain] == NULL
			? BR_DEAD_REPLY : BR_FAILED_REPLY;
	if (sender == NULL || handle >= 256)
		return BR_FAILED_REPLY;
	reference = &sender->handles[domain][handle];
	if (reference->endpoint == NULL &&
	    (reference->strong_refs != 0 || reference->weak_refs != 0 ||
	     reference->death_pending))
		return BR_DEAD_REPLY;
	return BR_FAILED_REPLY;
}

static int handle_for(BinderEndpoint *recipient, enum BinderDomain domain,
		BinderEndpoint *owner, binder_uintptr_t node,
		binder_uintptr_t cookie, uint64_t owner_generation, bool weak,
		bool transaction_security_context)
{
	uint32_t i;
	(void)weak;
	if (domain < 0 || domain >= BINDER_DOMAIN_COUNT ||
	    owner_generation == 0 ||
	    (owner != NULL && owner->generation != owner_generation))
		return -1;
	for (i = 1; i < 256; i++)
		if (recipient->handles[domain][i].owner_generation ==
				owner_generation &&
		    recipient->handles[domain][i].node == node &&
		    recipient->handles[domain][i].cookie == cookie) {
			recipient->handles[domain][i].transaction_security_context =
				transaction_security_context;
			return (int)i;
		}
	for (i = 1; i < 256; i++)
		if (recipient->handles[domain][i].owner_generation == 0 &&
		    recipient->handles[domain][i].strong_refs == 0 &&
		    recipient->handles[domain][i].weak_refs == 0 &&
		    !recipient->handles[domain][i].death_pending) {
			recipient->handles[domain][i].endpoint = owner;
			recipient->handles[domain][i].owner_generation =
				owner_generation;
			recipient->handles[domain][i].node = node;
			recipient->handles[domain][i].cookie = cookie;
			recipient->handles[domain][i].transaction_security_context =
				transaction_security_context;
			return (int)i;
		}
	return -1;
}

static BinderHandle *reference_for_handle(BinderEndpoint *sender,
		enum BinderDomain domain, uint32_t handle)
{
	BinderHandle *reference;
	BinderEndpoint *owner;
	binder_uintptr_t node;
	binder_uintptr_t cookie;

	if (sender == NULL || domain < 0 || domain >= BINDER_DOMAIN_COUNT ||
	    handle >= 256)
		return NULL;
	if (handle == 0) {
		owner = binder_broker.context_manager[domain];
		if (owner == NULL)
			return NULL;
		node = owner->context_node;
		cookie = owner->context_cookie;
		reference = &sender->handles[domain][0];
		if (reference->death_pending)
			return NULL;
		if (reference->endpoint == NULL) {
			reference->endpoint = owner;
			reference->owner_generation = owner->generation;
			reference->node = node;
			reference->cookie = cookie;
		} else if (reference->endpoint != owner ||
			   reference->node != node || reference->cookie != cookie) {
			return NULL;
		}
		return reference;
	}
	reference = &sender->handles[domain][handle];
	return reference->endpoint == NULL ? NULL : reference;
}

static int enqueue_reference_work(BinderEndpoint *owner,
		enum BinderDomain domain, uint32_t command,
		binder_uintptr_t node, binder_uintptr_t cookie)
{
	BinderTransaction *item;

	if (owner == NULL || domain < 0 || domain >= BINDER_DOMAIN_COUNT ||
	    owner->queue_count == MAX_BINDER_TRANSACTIONS)
		return -ENOSPC;
	item = &owner->queue[owner->queue_count++];
	memset(item, 0, sizeof(*item));
	item->command = command;
	item->transaction.target = node;
	item->transaction.cookie = cookie;
	item->domain = domain;
	notify_endpoint(owner, domain);
	return 0;
}

static int enqueue_death_work(BinderEndpoint *target,
		enum BinderDomain domain, uint32_t command,
		binder_uintptr_t cookie, BinderConfig *target_thread)
{
	BinderTransaction *item;

	if (target == NULL || domain < 0 || domain >= BINDER_DOMAIN_COUNT ||
	    (command != BR_DEAD_BINDER &&
	     command != BR_CLEAR_DEATH_NOTIFICATION_DONE) ||
	    target->queue_count == MAX_BINDER_TRANSACTIONS)
		return -ENOSPC;
	item = &target->queue[target->queue_count++];
	memset(item, 0, sizeof(*item));
	item->command = command;
	item->transaction.cookie = cookie;
	item->domain = domain;
	item->target_thread = target_thread;
	item->courier_listener = -1;
	notify_endpoint(target, domain);
	return 0;
}

static int update_handle_reference(BinderEndpoint *sender,
		enum BinderDomain domain, uint32_t handle, bool strong,
		bool increment)
{
	BinderHandle *reference;
	uint32_t *count;
	uint32_t command;
	int status;

	if (sender == NULL || domain < 0 || domain >= BINDER_DOMAIN_COUNT ||
	    handle >= 256)
		return -EINVAL;
	if (handle != 0 && sender->handles[domain][handle].endpoint == NULL) {
		reference = &sender->handles[domain][handle];
		count = strong ? &reference->strong_refs : &reference->weak_refs;
		if (reference->owner_generation == 0)
			return -EINVAL;
		if (increment) {
			if (*count == UINT32_MAX)
				return -EOVERFLOW;
			(*count)++;
			return 0;
		}
		if (*count == 0)
			return -EINVAL;
		(*count)--;
		if (reference->strong_refs == 0 && reference->weak_refs == 0 &&
		    !reference->death_pending)
			memset(reference, 0, sizeof(*reference));
		return 0;
	}
	reference = reference_for_handle(sender, domain, handle);
	if (reference == NULL)
		return -EINVAL;
	count = strong ? &reference->strong_refs : &reference->weak_refs;
	if (increment) {
		if (*count == UINT32_MAX)
			return -EOVERFLOW;
		if ((*count)++ != 0 ||
		    (reference->node == 0 && reference->cookie == 0))
			return 0;
		command = strong ? BR_ACQUIRE : BR_INCREFS;
	} else {
		if (*count == 0)
			return -EINVAL;
		if (--(*count) != 0 ||
		    (reference->node == 0 && reference->cookie == 0))
			return 0;
		command = strong ? BR_RELEASE : BR_DECREFS;
	}
	status = enqueue_reference_work(reference->endpoint, domain, command,
		reference->node, reference->cookie);
	if (status < 0) {
		if (increment)
			(*count)--;
		else
			(*count)++;
	}
	return status;
}

static size_t align_binder_size(size_t value)
{
	return (value + sizeof(uint64_t) - 1) & ~(sizeof(uint64_t) - 1);
}

static int copy_scatter_gather_buffers(Tracee *tracee, uint8_t *payload,
		size_t payload_size, uint64_t *offsets, size_t offsets_size,
		size_t buffers_size, size_t *extra_size)
{
	size_t copied = 0;
	size_t last_bbo_index = 0;
	size_t offsets_count = offsets_size / sizeof(uint64_t);
	size_t i;
	bool have_last_bbo = false;

	if (buffers_size % sizeof(uint64_t) != 0 ||
	    payload_size > MAX_BINDER_PAYLOAD ||
	    buffers_size > MAX_BINDER_PAYLOAD - payload_size)
		return -E2BIG;
	memset(payload + payload_size, 0, buffers_size);
	for (i = 0; i < offsets_count; i++) {
		struct binder_buffer_object object;
		uint32_t object_type;
		uint64_t offset = offsets[i];
		size_t length;
		size_t aligned_length;
		size_t fixup_offset = 0;
		uint64_t source;
		uint64_t fixup_value = 0;
		bool has_fixup = false;

		if (offset > payload_size ||
		    payload_size - (size_t)offset < sizeof(object_type) ||
		    offset % sizeof(uint32_t) != 0)
			return -EINVAL;
		memcpy(&object_type, payload + (size_t)offset,
		       sizeof(object_type));
		if (object_type != BINDER_TYPE_PTR)
			continue;
		if (payload_size - (size_t)offset < sizeof(object))
			return -EINVAL;
		memcpy(&object, payload + (size_t)offset, sizeof(object));
		if ((object.flags & ~BINDER_BUFFER_FLAG_HAS_PARENT) != 0)
			return -EINVAL;
		if ((object.flags & BINDER_BUFFER_FLAG_HAS_PARENT) != 0) {
			struct binder_buffer_object parent;
			uint32_t parent_type;
			size_t parent_index;
			size_t ancestor_index;
			size_t min_offset = 0;
			uint64_t parent_object_offset;

			if (!have_last_bbo || object.parent >= i ||
			    object.parent >= offsets_count)
				return -EINVAL;
			parent_index = (size_t)object.parent;
			ancestor_index = last_bbo_index;
			while (ancestor_index != parent_index) {
				struct binder_buffer_object ancestor;
				uint32_t ancestor_type;
				uint64_t ancestor_offset;

				if (ancestor_index >= i ||
				    ancestor_index >= offsets_count)
					return -EINVAL;
				ancestor_offset = offsets[ancestor_index];
				if (ancestor_offset > payload_size ||
				    payload_size - (size_t)ancestor_offset <
					    sizeof(ancestor_type) ||
				    ancestor_offset % sizeof(uint32_t) != 0)
					return -EINVAL;
				memcpy(&ancestor_type,
				       payload + (size_t)ancestor_offset,
				       sizeof(ancestor_type));
				if (ancestor_type != BINDER_TYPE_PTR ||
				    payload_size - (size_t)ancestor_offset <
					    sizeof(ancestor))
					return -EINVAL;
				memcpy(&ancestor, payload + (size_t)ancestor_offset,
				       sizeof(ancestor));
				if ((ancestor.flags & BINDER_BUFFER_FLAG_HAS_PARENT) == 0 ||
				    (ancestor.flags & ~BINDER_BUFFER_FLAG_HAS_PARENT) != 0 ||
				    ancestor.parent >= ancestor_index ||
				    ancestor.parent_offset >
					    UINT64_MAX - sizeof(uint64_t))
					return -EINVAL;
				min_offset = (size_t)ancestor.parent_offset +
					sizeof(uint64_t);
				ancestor_index = (size_t)ancestor.parent;
			}
			if (object.parent_offset < min_offset)
				return -EINVAL;

			parent_object_offset = offsets[parent_index];
			if (parent_object_offset > payload_size ||
			    payload_size - (size_t)parent_object_offset <
				    sizeof(parent_type) ||
			    parent_object_offset % sizeof(uint32_t) != 0)
				return -EINVAL;
			memcpy(&parent_type, payload + (size_t)parent_object_offset,
			       sizeof(parent_type));
			if (parent_type != BINDER_TYPE_PTR ||
			    payload_size - (size_t)parent_object_offset <
				    sizeof(parent))
				return -EINVAL;
			memcpy(&parent, payload + (size_t)parent_object_offset,
			       sizeof(parent));
			if ((parent.flags & ~BINDER_BUFFER_FLAG_HAS_PARENT) != 0 ||
			    parent.buffer > copied ||
			    parent.length > copied - parent.buffer ||
			    parent.length < sizeof(uint64_t) ||
			    object.parent_offset > parent.length - sizeof(uint64_t))
				return -EINVAL;
			fixup_offset = (size_t)parent.buffer +
				(size_t)object.parent_offset;
			if (fixup_offset > copied - sizeof(uint64_t))
				return -EINVAL;
			fixup_value = copied;
			has_fixup = true;
		}
		if (copied > buffers_size ||
		    object.length > buffers_size - copied)
			return -EINVAL;
		length = (size_t)object.length;
		aligned_length = align_binder_size(length);
		if (aligned_length > buffers_size - copied)
			return -EINVAL;
		source = object.buffer;
		if (length != 0 &&
		    (source == 0 || read_data(tracee, payload + payload_size + copied,
					      source, length) < 0))
			return -EFAULT;
		object.buffer = copied;
		memcpy(payload + (size_t)offset, &object, sizeof(object));
		if (has_fixup)
			memcpy(payload + payload_size + fixup_offset, &fixup_value,
			       sizeof(fixup_value));
		copied += aligned_length;
		last_bbo_index = i;
		have_last_bbo = true;
	}
	*extra_size = buffers_size;
	return 0;
}

static int translate_objects(BinderEndpoint *sender, BinderEndpoint *recipient,
		enum BinderDomain domain, uint8_t *payload, size_t payload_size,
		uint64_t *offsets,
		size_t offsets_size, bool scatter_gather, size_t extra_size,
		bool allow_fda_reply)
{
	size_t i;
	for (i = 0; i < offsets_size / sizeof(uint64_t); i++) {
		uint64_t offset = offsets[i];
		uint32_t object_type;

		if (offset > payload_size ||
		    payload_size - (size_t)offset < sizeof(object_type) ||
		    offset % sizeof(uint32_t) != 0)
			return -EINVAL;
		memcpy(&object_type, payload + (size_t)offset,
		       sizeof(object_type));
		if (domain == BINDER_DOMAIN_BINDER &&
		    sender == binder_broker.context_manager[domain] &&
		    sender->tracee != NULL && recipient->tracee != NULL &&
		    payload_size == 52 &&
		    offsets_size == sizeof(uint64_t) && offset == 20) {
			static unsigned int diagnostic_count;

			if (diagnostic_count < 100) {
				struct flat_binder_object object = {};
				if (payload_size - (size_t)offset >= sizeof(object))
					memcpy(&object, payload + (size_t)offset,
					       sizeof(object));
				fprintf(stderr,
					"[DEBUG-CM-OBJ-r153] sender_vpid=%d recipient_vpid=%d offset=%llu payload=%zu offsets=%zu sg=%d extra=%zu type=%#x flags=%#x union_lo=%#x cookie=%#llx\n",
					(int)sender->tracee->vpid,
					(int)recipient->tracee->vpid,
					(unsigned long long)offset, payload_size,
					offsets_size, scatter_gather, extra_size,
					object_type, object.flags, object.b.handle,
					(unsigned long long)object.cookie);
				diagnostic_count++;
			}
		}
		if (domain == BINDER_DOMAIN_BINDER &&
		    sender->tracee != NULL && sender->tracee->vpid == 11 &&
		    recipient->tracee != NULL && recipient->tracee->vpid == 186) {
			static unsigned int diagnostic_count;

			if (diagnostic_count < 20) {
				fprintf(stderr,
					"[DEBUG-BWR-OBJECT-c9a1] sender_vpid=%d recipient_vpid=%d index=%zu offset=%llu payload=%zu type=%#x remaining=%zu\n",
					(int)sender->tracee->vpid,
					(int)recipient->tracee->vpid, i,
					(unsigned long long)offset, payload_size, object_type,
					payload_size - (size_t)offset);
				diagnostic_count++;
			}
		}
		switch (object_type) {
		case BINDER_TYPE_BINDER:
		case BINDER_TYPE_WEAK_BINDER: {
			struct flat_binder_object object;
			bool transaction_security_context;
			int handle;

			if (payload_size - (size_t)offset < sizeof(object))
				return -EINVAL;
			memcpy(&object, payload + (size_t)offset, sizeof(object));
			transaction_security_context =
				(object.flags & FLAT_BINDER_FLAG_TXN_SECURITY_CTX) != 0;
			handle = handle_for(recipient, domain, sender, object.b.binder,
				object.cookie, sender->generation,
				object_type == BINDER_TYPE_WEAK_BINDER,
				transaction_security_context);
			if (handle < 0)
				return -ENOSPC;
			object.hdr_type = object_type == BINDER_TYPE_BINDER
				? BINDER_TYPE_HANDLE : BINDER_TYPE_WEAK_HANDLE;
			object.b.handle = (uint32_t)handle;
			object.cookie = 0;
			memcpy(payload + (size_t)offset, &object, sizeof(object));
			break;
		}
		case BINDER_TYPE_HANDLE:
		case BINDER_TYPE_WEAK_HANDLE: {
			struct flat_binder_object object;
			BinderEndpoint *owner;
			binder_uintptr_t node = 0;
			binder_uintptr_t cookie = 0;
			uint64_t owner_generation = 0;
			bool transaction_security_context = false;
			int handle;
			static unsigned int diagnostic_count;
			static unsigned int dead_handle_diagnostic_count;

			if (payload_size - (size_t)offset < sizeof(object))
				return -EINVAL;
			memcpy(&object, payload + (size_t)offset, sizeof(object));
			if (object.b.handle >= 256)
				return -EINVAL;
			if (object.b.handle == 0) {
				if (domain < 0 || domain >= BINDER_DOMAIN_COUNT)
					return -EINVAL;
				owner = binder_broker.context_manager[domain];
				if (owner != NULL) {
					owner_generation = owner->generation;
					node = owner->context_node;
					cookie = owner->context_cookie;
					transaction_security_context =
						owner->context_security_context;
				}
			}
			else {
				BinderHandle *source_handle;

				if (domain < 0 || domain >= BINDER_DOMAIN_COUNT)
					return -EINVAL;
				source_handle =
					&sender->handles[domain][object.b.handle];
				owner = source_handle->endpoint;
				owner_generation = source_handle->owner_generation;
				node = source_handle->node;
				cookie = source_handle->cookie;
				transaction_security_context =
					source_handle->transaction_security_context;
			}
			if (owner == NULL) {
				if (object.b.handle != 0 && sender != NULL &&
				    domain == BINDER_DOMAIN_BINDER &&
				    sender == binder_broker.context_manager[domain] &&
				    payload_size == 52 &&
				    offsets_size == sizeof(uint64_t) && offset == 20 &&
				    dead_handle_diagnostic_count < 100) {
					const BinderHandle *missing =
						&sender->handles[domain][object.b.handle];

					fprintf(stderr,
						"[DEBUG-DEAD-HANDLE-r154] sender_vpid=%d recipient_vpid=%d handle=%u strong_refs=%u weak_refs=%u death_notification=%d death_pending=%d node=%#llx cookie=%#llx secctx=%d\n",
						sender->tracee == NULL ? -1 :
							(int)sender->tracee->vpid,
						recipient->tracee == NULL ? -1 :
							(int)recipient->tracee->vpid,
						object.b.handle, missing->strong_refs,
						missing->weak_refs,
						missing->death_notification,
						missing->death_pending,
						(unsigned long long)missing->node,
						(unsigned long long)missing->cookie,
						missing->transaction_security_context);
					dead_handle_diagnostic_count++;
				}
				if (owner_generation == 0)
					return -EINVAL;
			}
			if (domain == BINDER_DOMAIN_BINDER &&
			    diagnostic_count < 500) {
				fprintf(stderr,
					"[DEBUG-BINDER-OBJ-f18d] phase=received sender_vpid=%d recipient_vpid=%d source_handle=%u owner_vpid=%d node=%#llx cookie=%#llx secctx=%d\n",
					sender->tracee == NULL ? -1 :
						(int)sender->tracee->vpid,
					recipient->tracee == NULL ? -1 :
						(int)recipient->tracee->vpid,
					object.b.handle,
					owner == NULL || owner->tracee == NULL ? -1 :
						(int)owner->tracee->vpid,
					(unsigned long long)node,
					(unsigned long long)cookie,
					transaction_security_context);
				diagnostic_count++;
			}
			if (owner == recipient) {
				object.flags &= ~FLAT_BINDER_FLAG_TXN_SECURITY_CTX;
				if (transaction_security_context)
					object.flags |= FLAT_BINDER_FLAG_TXN_SECURITY_CTX;
				object.hdr_type = object_type == BINDER_TYPE_HANDLE
					? BINDER_TYPE_BINDER
					: BINDER_TYPE_WEAK_BINDER;
				object.b.binder = node;
				object.cookie = cookie;
				memcpy(payload + (size_t)offset, &object,
				       sizeof(object));
				break;
			}
			if (object.b.handle != 0) {
				handle = handle_for(recipient, domain, owner, node, cookie,
					owner_generation,
					object_type == BINDER_TYPE_WEAK_HANDLE,
					transaction_security_context);
				if (handle < 0)
					return -ENOSPC;
				if (domain == BINDER_DOMAIN_BINDER &&
				    diagnostic_count < 500) {
					fprintf(stderr,
						"[DEBUG-BINDER-OBJ-f18d] phase=translated source_handle=%u recipient_vpid=%d result_handle=%d owner_vpid=%d node=%#llx cookie=%#llx\n",
						object.b.handle,
						recipient->tracee == NULL ? -1 :
							(int)recipient->tracee->vpid,
						handle,
						owner == NULL || owner->tracee == NULL ? -1 :
							(int)owner->tracee->vpid,
						(unsigned long long)node,
						(unsigned long long)cookie);
					diagnostic_count++;
				}
				object.b.handle = (uint32_t)handle;
				object.cookie = 0;
				memcpy(payload + (size_t)offset, &object,
				       sizeof(object));
			}
			break;
		}
		case BINDER_TYPE_FD: {
			struct flat_binder_object object;

			if (payload_size - (size_t)offset < sizeof(object))
				return -EINVAL;
			memcpy(&object, payload + (size_t)offset, sizeof(object));
			if (object.b.handle > INT32_MAX)
				return -EBADF;
			break;
		}
		case BINDER_TYPE_FDA:
			if (!allow_fda_reply) {
				static unsigned int diagnostic_count;

				if (diagnostic_count < 32) {
					fprintf(stderr,
						"[DEBUG-BINDER-FDA-REJECT-c9a1] sender_vpid=%d recipient_vpid=%d domain=%d offset=%llu payload=%zu offsets=%zu sg=%d extra=%zu\n",
						sender->tracee == NULL ? -1 :
							(int)sender->tracee->vpid,
						recipient->tracee == NULL ? -1 :
							(int)recipient->tracee->vpid,
						(int)domain, (unsigned long long)offset,
						payload_size, offsets_size, scatter_gather,
						extra_size);
					diagnostic_count++;
				}
				return -EINVAL;
			}
			break;
		case BINDER_TYPE_PTR: {
			struct binder_buffer_object buffer;

			if (payload_size - (size_t)offset < sizeof(buffer))
				return -EINVAL;
			memcpy(&buffer, payload + (size_t)offset, sizeof(buffer));
			if (!scatter_gather ||
			    (buffer.flags & ~BINDER_BUFFER_FLAG_HAS_PARENT) != 0 ||
			    ((buffer.flags & BINDER_BUFFER_FLAG_HAS_PARENT) != 0 &&
			     buffer.parent >= i) ||
			    buffer.buffer > extra_size ||
			    buffer.length > extra_size - buffer.buffer)
				return -EINVAL;
			break;
		}
		default:
			return -EINVAL;
		}
	}
	return 0;
}

static int validate_reply_fd_array(const uint8_t *payload,
		size_t payload_size, size_t extra_size,
		const uint64_t *offsets, size_t offsets_size, bool scatter_gather,
		bool *has_fda, int *source_fd, size_t *slot_offset)
{
	size_t count = offsets_size / sizeof(uint64_t);
	size_t fda_count = 0;
	size_t i;

	*has_fda = false;
	*source_fd = -1;
	*slot_offset = 0;
	if (!scatter_gather)
		return 0;
	for (i = 0; i < count; i++) {
		struct binder_fd_array_object fda;
		struct binder_buffer_object parent;
		uint32_t type;
		uint64_t offset = offsets[i];
		uint64_t parent_object_offset;
		uint64_t slot;

		if (offset > payload_size ||
		    payload_size - (size_t)offset < sizeof(type) ||
		    offset % sizeof(uint32_t) != 0)
			return -EINVAL;
		memcpy(&type, payload + (size_t)offset, sizeof(type));
		if (type != BINDER_TYPE_FDA)
			continue;
		if (++fda_count != 1 ||
		    payload_size - (size_t)offset < sizeof(fda))
			return -EINVAL;
		memcpy(&fda, payload + (size_t)offset, sizeof(fda));
		if (fda.num_fds != 1 || fda.parent >= i || fda.parent >= count)
			return -EINVAL;
		parent_object_offset = offsets[fda.parent];
		if (parent_object_offset > payload_size ||
		    payload_size - (size_t)parent_object_offset < sizeof(parent))
			return -EINVAL;
		memcpy(&parent, payload + (size_t)parent_object_offset,
		       sizeof(parent));
		if (parent.hdr_type != BINDER_TYPE_PTR ||
		    (parent.flags & ~BINDER_BUFFER_FLAG_HAS_PARENT) != 0 ||
		    parent.buffer > extra_size ||
		    parent.length > extra_size - parent.buffer ||
		    parent.length < sizeof(int32_t) ||
		    fda.parent_offset > parent.length - sizeof(int32_t) ||
		    fda.parent_offset > UINT64_MAX - parent.buffer)
			return -EINVAL;
		slot = parent.buffer + fda.parent_offset;
		if (slot > extra_size || extra_size - (size_t)slot < sizeof(int32_t) ||
		    slot % _Alignof(int32_t) != 0)
			return -EINVAL;
		memcpy(source_fd, payload + payload_size + (size_t)slot,
		       sizeof(*source_fd));
		if (*source_fd < 0)
			return -EBADF;
		*has_fda = true;
		*slot_offset = (size_t)slot;
	}
	return 0;
}

static int validate_direct_fd_objects(const uint8_t *payload,
		size_t payload_size, const uint64_t *offsets, size_t offsets_size,
		BinderFdTransfer **transfers, size_t *transfer_count)
{
	size_t count = offsets_size / sizeof(uint64_t);
	size_t i;
	int status = 0;

	*transfers = NULL;
	*transfer_count = 0;
	for (i = 0; i < count; i++) {
		struct flat_binder_object object;
		uint32_t type;
		uint64_t offset = offsets[i];
		BinderFdTransfer *new_transfers;

		if (offset > payload_size ||
		    payload_size - (size_t)offset < sizeof(type) ||
		    offset % sizeof(uint32_t) != 0) {
			status = -EINVAL;
			goto fail;
		}
		memcpy(&type, payload + (size_t)offset, sizeof(type));
		if (type != BINDER_TYPE_FD)
			continue;
		if (payload_size - (size_t)offset < sizeof(object)) {
			status = -EINVAL;
			goto fail;
		}
		if (*transfer_count == MAX_BINDER_FDS) {
			status = -E2BIG;
			goto fail;
		}
		memcpy(&object, payload + (size_t)offset, sizeof(object));
		if (object.b.handle > INT32_MAX) {
			status = -EBADF;
			goto fail;
		}
		new_transfers = realloc(*transfers,
			(*transfer_count + 1) * sizeof(**transfers));
		if (new_transfers == NULL) {
			status = -ENOMEM;
			goto fail;
		}
		*transfers = new_transfers;
		memset(&new_transfers[*transfer_count], 0,
			sizeof(new_transfers[*transfer_count]));
		new_transfers[*transfer_count].source_fd = (int)object.b.handle;
		new_transfers[*transfer_count].staged_fd = -1;
		new_transfers[*transfer_count].domain = BINDER_DOMAIN_NONE;
		new_transfers[*transfer_count].slot_offset =
			(size_t)offset + offsetof(struct flat_binder_object, b);
		(*transfer_count)++;
	}
	return 0;

fail:
	free(*transfers);
	*transfers = NULL;
	*transfer_count = 0;
	return status;
}

static int capture_tracee_fd(BinderConfig *sender, int source_fd)
{
	pid_t host_pid;
	int pid_fd;
	int staged_fd;

	if (sender == NULL || sender->tracee == NULL || source_fd < 0)
		return -EBADF;
	host_pid = tracee_host_pid(sender->tracee);
	pid_fd = (int)syscall(SYS_pidfd_open, host_pid, 0);
	if (pid_fd < 0) {
		return -errno;
	}
	staged_fd = (int)syscall(SYS_pidfd_getfd, pid_fd, source_fd, 0);
	if (staged_fd < 0) {
		int status = -errno;
		close(pid_fd);
		return status;
	}
	close(pid_fd);
	return staged_fd;
}

static void close_fd_transfers(BinderFdTransfer *transfers, size_t count)
{
	size_t i;

	for (i = 0; i < count; i++)
		if (transfers[i].staged_fd >= 0)
			close(transfers[i].staged_fd);
	free(transfers);
}

static int capture_fd_transfers(BinderConfig *sender,
		BinderFdTransfer *transfers, size_t count)
{
	size_t i;

	for (i = 0; i < count; i++) {
		BinderFd *source_binder_fd;
		int staged_fd = capture_tracee_fd(sender, transfers[i].source_fd);

		if (staged_fd < 0) {
			close_fd_transfers(transfers, count);
			return staged_fd;
		}
		transfers[i].staged_fd = staged_fd;
		source_binder_fd = find_fd(sender, transfers[i].source_fd);
		if (source_binder_fd != NULL)
			transfers[i].domain = source_binder_fd->domain;
	}
	return 0;
}

static int fill_fda_courier_address(uint64_t transaction_id,
		struct sockaddr_un *address, socklen_t *address_length)
{
	char name[sizeof(address->sun_path) - 1];
	int length;

	memset(address, 0, sizeof(*address));
	address->sun_family = AF_UNIX;
	length = snprintf(name, sizeof(name), "prfd-%lx-%llx",
		(unsigned long)getpid(), (unsigned long long)transaction_id);
	if (length < 0 || (size_t)length >= sizeof(name))
		return -ENAMETOOLONG;
	address->sun_path[0] = '\0';
	memcpy(address->sun_path + 1, name, (size_t)length);
	*address_length = (socklen_t)(offsetof(struct sockaddr_un, sun_path) +
		1 + (size_t)length);
	return 0;
}

static int make_fda_courier_listener(uint64_t transaction_id,
		struct sockaddr_un *address, socklen_t *address_length)
{
	int fd;
	int status = fill_fda_courier_address(transaction_id, address,
		address_length);

	if (status < 0)
		return status;
	fd = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
	if (fd < 0)
		return -errno;
	if (bind(fd, (struct sockaddr *)address, *address_length) < 0 ||
	    listen(fd, 1) < 0) {
		status = -errno;
		close(fd);
		return status;
	}
	return fd;
}

static int courier_send_fds(int listener_fd, const int *staged_fds,
		size_t fd_count, pid_t expected_peer_pid)
{
	struct {
		struct cmsghdr align;
		unsigned char data[CMSG_SPACE(sizeof(int) * MAX_BINDER_FDS)];
	} control = {};
	struct msghdr message = {
		.msg_control = control.data,
		.msg_controllen = sizeof(control.data),
	};
	struct cmsghdr *header;
	int client_fd;
	ssize_t sent;
	int status;

	if (expected_peer_pid <= 0 || fd_count == 0 ||
	    fd_count > MAX_BINDER_FDS)
		return -EINVAL;

	client_fd = accept4(listener_fd, NULL, NULL, SOCK_CLOEXEC);
	if (client_fd < 0)
		return -errno;
	status = binder_fda_verify_peer_pid(client_fd, expected_peer_pid);
	if (status < 0) {
		close(client_fd);
		return status;
	}
	header = CMSG_FIRSTHDR(&message);
	if (header == NULL) {
		close(client_fd);
		return -EINVAL;
	}
	header->cmsg_len = CMSG_LEN(fd_count * sizeof(int));
	header->cmsg_level = SOL_SOCKET;
	header->cmsg_type = SCM_RIGHTS;
	memcpy(CMSG_DATA(header), staged_fds, fd_count * sizeof(int));
	message.msg_controllen = CMSG_SPACE(fd_count * sizeof(int));
	sent = sendmsg(client_fd, &message, MSG_NOSIGNAL);
	status = sent == 0 ? 0 :
		(sent < 0 ? -errno : -EIO);
	close(client_fd);
	return status;
}

static void close_transaction_fda(BinderTransaction *item)
{
	size_t i;

	for (i = 0; i < item->fd_transfer_count; i++)
		if (item->fd_transfers[i].staged_fd >= 0)
			close(item->fd_transfers[i].staged_fd);
	free(item->fd_transfers);
	item->fd_transfers = NULL;
	item->fd_transfer_count = 0;
	if (item->courier_listener >= 0)
		close(item->courier_listener);
	item->courier_listener = -1;
}

static void free_transaction_buffers(BinderTransaction *item)
{
	free(item->payload);
	free(item->offsets);
	free(item->references);
	item->payload = NULL;
	item->offsets = NULL;
	item->references = NULL;
	item->reference_count = 0;
	item->references_released = 0;
}

static int enqueue_transaction(BinderEndpoint *target,
		const struct binder_transaction_data *transaction,
		const void *payload, size_t payload_size, size_t extra_size,
		const uint64_t *offsets, size_t offsets_size, bool scatter_gather,
		uint32_t command, bool security_context, BinderConfig *sender,
		BinderConfig *target_thread, enum BinderDomain domain,
		uint64_t transaction_id, BinderConfig *reply_sender,
		uint64_t reply_frame_id, bool fda_reply,
		BinderFdTransfer *fd_transfers, size_t fd_transfer_count)
{
	BinderTransaction *item;
	int status;
	if (target == NULL || sender == NULL || sender->endpoint == NULL ||
	    target->queue_count == MAX_BINDER_TRANSACTIONS ||
	    extra_size > MAX_BINDER_PAYLOAD ||
	    payload_size > MAX_BINDER_PAYLOAD - extra_size ||
	    offsets_size > MAX_BINDER_PAYLOAD ||
	    offsets_size % sizeof(uint64_t) != 0 ||
	    offsets_size / sizeof(uint64_t) > MAX_BINDER_OFFSETS ||
	    fd_transfer_count > MAX_BINDER_FDS ||
	    (fd_transfer_count != 0 && fd_transfers == NULL)) {
		close_fd_transfers(fd_transfers, fd_transfer_count);
		return -ENOSPC;
	}
	item = &target->queue[target->queue_count];
	memset(item, 0, sizeof(*item));
	item->command = command;
	item->transaction = *transaction;
	item->domain = domain;
	item->payload_size = payload_size;
	item->extra_size = extra_size;
	item->offsets_size = offsets_size;
	item->scatter_gather = scatter_gather;
	item->security_context = command == BR_TRANSACTION && security_context;
	item->id = transaction_id;
	item->reply_sender = reply_sender;
	item->reply_frame_id = reply_frame_id;
	item->fda_reply = fda_reply;
	item->fd_transfers = fd_transfers;
	item->fd_transfer_count = fd_transfer_count;
	item->courier_listener = -1;
	item->sender = command == BR_TRANSACTION ? sender : NULL;
	item->target_thread = target_thread;
	if (payload_size + extra_size != 0) {
		item->payload = malloc(payload_size + extra_size);
		if (item->payload == NULL) {
			close_transaction_fda(item);
			return -ENOMEM;
		}
		memcpy(item->payload, payload, payload_size + extra_size);
	}
	if (offsets_size != 0) {
		item->offsets = malloc(offsets_size);
		if (item->offsets == NULL) {
			free_transaction_buffers(item);
			close_transaction_fda(item);
			return -ENOMEM;
		}
		memcpy(item->offsets, offsets, offsets_size);
	}
	status = translate_objects(sender->endpoint, target, domain, item->payload,
		payload_size,
		item->offsets, offsets_size, scatter_gather, extra_size,
		fda_reply);
	if (status < 0) {
		static unsigned int diagnostic_count;

		if (payload_size == 128 && offsets_size == sizeof(uint64_t) &&
		    offsets != NULL && offsets[0] == 100) {
			static unsigned int object_diagnostic_count;

			if (object_diagnostic_count < 20) {
				struct flat_binder_object object = {};
				uint32_t type = 0;
				size_t byte_index;

				memcpy(&type, item->payload + 100, sizeof(type));
				if (payload_size - 100 >= sizeof(object))
					memcpy(&object, item->payload + 100,
					       sizeof(object));
				fprintf(stderr,
					"[DEBUG-TRANSLATE-OBJECT-8e31] status=%d domain=%d command=%#x sender_vpid=%d target_vpid=%d code=%#x offset=%llu type=%#x flags=%#x handle=%u binder=%#llx cookie=%#llx bytes=",
					status, (int)domain, command,
					sender->tracee == NULL ? -1 :
						(int)sender->tracee->vpid,
					target->tracee == NULL ? -1 :
						(int)target->tracee->vpid,
					transaction->code,
					(unsigned long long)offsets[0], type,
					object.flags, object.b.handle,
					(unsigned long long)object.b.binder,
					(unsigned long long)object.cookie);
				for (byte_index = 96; byte_index < payload_size; byte_index++)
					fprintf(stderr, "%02x", item->payload[byte_index]);
				fputc('\n', stderr);
				object_diagnostic_count++;
			}
		}
		if (diagnostic_count < 20) {
			fprintf(stderr,
				"[DEBUG-BWR-CAUSE-c9a1] stage=translate-objects status=%d command=%#x txid=%llu sender_vpid=%d target_vpid=%d data=%zu offsets=%zu first_offset=%llu\n",
				status, command, (unsigned long long)transaction_id,
				sender->tracee == NULL ? -1 : (int)sender->tracee->vpid,
				target->tracee == NULL ? -1 : (int)target->tracee->vpid,
				payload_size, offsets_size,
				offsets_size < sizeof(*item->offsets) ? 0 :
					(unsigned long long)item->offsets[0]);
			diagnostic_count++;
		}
		if (domain == BINDER_DOMAIN_HWBINDER && transaction->code == 3)
			fprintf(stderr,
				"[DEBUG-HIDL-GT-a17e-ENQUEUE-FAIL] command=%#x status=%d sender_vpid=%d target_vpid=%d data=%zu offsets=%zu extra=%zu sg=%d\n",
				command, status,
				sender->tracee == NULL ? -1 : (int)sender->tracee->vpid,
				target->tracee == NULL ? -1 : (int)target->tracee->vpid,
				payload_size, offsets_size, extra_size, scatter_gather);
		free_transaction_buffers(item);
		return status;
	}
	status = prepare_transaction_references(target, item);
	if (status < 0) {
		static unsigned int diagnostic_count;

		if (diagnostic_count < 20) {
			fprintf(stderr,
				"[DEBUG-BWR-CAUSE-c9a1] stage=prepare-references status=%d command=%#x txid=%llu sender_vpid=%d target_vpid=%d\n",
				status, command, (unsigned long long)transaction_id,
				sender->tracee == NULL ? -1 : (int)sender->tracee->vpid,
				target->tracee == NULL ? -1 : (int)target->tracee->vpid);
			diagnostic_count++;
		}
		free_transaction_buffers(item);
		close_transaction_fda(item);
		return status;
	}
	if ((command == BR_TRANSACTION && target->context_manager &&
	     (transaction->code == 3 || transaction->code == 4 ||
	      transaction->code == 0x10)) ||
	    (command == BR_REPLY && sender->endpoint->context_manager)) {
		static unsigned int request_diagnostic_count;
		static unsigned int reply_diagnostic_count;
		unsigned int *diagnostic_count = command == BR_REPLY
			? &reply_diagnostic_count : &request_diagnostic_count;
		uint32_t preview_size = (uint32_t)(payload_size + extra_size);
		size_t j;

		if (preview_size > 512)
			preview_size = 512;
		if (*diagnostic_count < 1000) {
			fprintf(stderr,
				"[DEBUG-CM-PAYLOAD-r162] command=%#x txid=%llu frame=%llu domain=%d sender_vpid=%d target_vpid=%d code=%#x flags=%#x data=%zu offsets=%zu extra=%zu sg=%d bytes=",
				command, (unsigned long long)transaction_id,
				(unsigned long long)reply_frame_id, (int)domain,
				sender->tracee == NULL ? -1 : (int)sender->tracee->vpid,
				target->tracee == NULL ? -1 : (int)target->tracee->vpid,
				transaction->code, transaction->flags, payload_size,
				offsets_size, extra_size, scatter_gather);
			for (j = 0; j < preview_size; j++)
				fprintf(stderr, "%02x", item->payload[j]);
			fprintf(stderr, " object_offsets=");
			for (j = 0; j < offsets_size / sizeof(uint64_t); j++)
				fprintf(stderr, "%s%llu", j == 0 ? "" : ",",
					(unsigned long long)item->offsets[j]);
			fputc('\n', stderr);
			(*diagnostic_count)++;
		}
	}
	if (domain == BINDER_DOMAIN_BINDER &&
	    (target->context_manager || command == BR_REPLY)) {
		static unsigned int diagnostic_count;

		if (diagnostic_count < 1500) {
			fprintf(stderr,
				"[DEBUG-CM-q3f1-QUEUE] command=%#x txid=%llu frame=%llu sender_vpid=%d target_vpid=%d target_thread_vpid=%d code=%#x flags=%#x data=%zu offsets=%zu extra=%zu sg=%d secctx=%d\n",
				command, (unsigned long long)transaction_id,
				(unsigned long long)reply_frame_id,
				sender->tracee == NULL ? -1 : (int)sender->tracee->vpid,
				target->tracee == NULL ? -1 : (int)target->tracee->vpid,
				target_thread == NULL || target_thread->tracee == NULL
					? -1 : (int)target_thread->tracee->vpid,
				transaction->code, transaction->flags, payload_size,
				offsets_size, extra_size, scatter_gather,
				command == BR_TRANSACTION && security_context);
			diagnostic_count++;
		}
	}
	if (domain == BINDER_DOMAIN_HWBINDER && command == BR_REPLY) {
		static unsigned int diagnostic_count;
		uint32_t response_words[4] = {};
		size_t copy_size = payload_size < sizeof(response_words)
			? payload_size : sizeof(response_words);

		if (copy_size != 0)
			memcpy(response_words, item->payload, copy_size);
		if (diagnostic_count < 200) {
			fprintf(stderr,
				"[DEBUG-HIDL-RPLY-b926-ENQUEUE] txid=%llu frame=%llu sender_vpid=%d target_vpid=%d code=%#x flags=%#x data=%zu offsets=%zu extra=%zu sg=%d data0=%08x data1=%08x data2=%08x data3=%08x\n",
				(unsigned long long)transaction_id,
				(unsigned long long)reply_frame_id,
				sender->tracee == NULL ? -1 : (int)sender->tracee->vpid,
			target->tracee == NULL ? -1 : (int)target->tracee->vpid,
			transaction->code, transaction->flags, payload_size,
			offsets_size, extra_size, scatter_gather,
			response_words[0], response_words[1],
			response_words[2], response_words[3]);
			diagnostic_count++;
		}
	}
	if (domain == BINDER_DOMAIN_HWBINDER && transaction->code == 3) {
		static unsigned int diagnostic_count;

		if (diagnostic_count < 500) {
			fprintf(stderr,
				"[DEBUG-HIDL-GT-a17e-ENQUEUE] command=%#x txid=%llu sender_vpid=%d target_vpid=%d data=%zu offsets=%zu extra=%zu sg=%d secctx=%d\n",
				command, (unsigned long long)transaction_id,
				sender->tracee == NULL ? -1 : (int)sender->tracee->vpid,
				target->tracee == NULL ? -1 : (int)target->tracee->vpid,
				payload_size, offsets_size, extra_size, scatter_gather,
				security_context);
			diagnostic_count++;
		}
	}
	if (domain == BINDER_DOMAIN_HWBINDER &&
	    (command == BR_TRANSACTION || command == BR_REPLY)) {
		static unsigned int diagnostic_count;
		size_t preview_size = payload_size < 96 ? payload_size : 96;
		size_t offset_count = offsets_size / sizeof(uint64_t);
		size_t preview_offsets = offset_count < 8 ? offset_count : 8;
		size_t j;

		if (diagnostic_count < 1200) {
			fprintf(stderr,
				"[DEBUG-HWBINDER-ALL-d8f2] command=%#x txid=%llu frame=%llu sender_vpid=%d target_vpid=%d target_thread_vpid=%d code=%#x flags=%#x data=%zu offsets=%zu extra=%zu bytes=",
				command, (unsigned long long)transaction_id,
				(unsigned long long)reply_frame_id,
				sender->tracee == NULL ? -1 : (int)sender->tracee->vpid,
				target->tracee == NULL ? -1 : (int)target->tracee->vpid,
				target_thread == NULL || target_thread->tracee == NULL
					? -1 : (int)target_thread->tracee->vpid,
				transaction->code, transaction->flags, payload_size,
				offsets_size, extra_size);
			for (j = 0; j < preview_size; j++)
				fprintf(stderr, "%02x", item->payload[j]);
			fprintf(stderr, " object_offsets=");
			for (j = 0; j < preview_offsets; j++)
				fprintf(stderr, "%s%llu", j == 0 ? "" : ",",
					(unsigned long long)item->offsets[j]);
			fprintf(stderr, "\n");
			diagnostic_count++;
		}
	}
	if (domain == BINDER_DOMAIN_BINDER &&
	    (transaction->code == 0x5f4e5446 ||
	     (command == BR_REPLY && payload_size <= 128))) {
		static unsigned int diagnostic_count;
		size_t preview_size = payload_size < 96 ? payload_size : 96;
		size_t offset_count = offsets_size / sizeof(uint64_t);
		size_t preview_offsets = offset_count < 8 ? offset_count : 8;
		size_t j;

		if (diagnostic_count < 1000) {
			fprintf(stderr,
				"[DEBUG-BINDER-IFACE-c147] command=%#x txid=%llu frame=%llu sender_vpid=%d target_vpid=%d code=%#x flags=%#x data=%zu offsets=%zu bytes=",
				command, (unsigned long long)transaction_id,
				(unsigned long long)reply_frame_id,
				sender->tracee == NULL ? -1 : (int)sender->tracee->vpid,
				target->tracee == NULL ? -1 : (int)target->tracee->vpid,
				transaction->code, transaction->flags, payload_size,
				offsets_size);
			for (j = 0; j < preview_size; j++)
				fprintf(stderr, "%02x", item->payload[j]);
			fprintf(stderr, " object_offsets=");
			for (j = 0; j < preview_offsets; j++)
				fprintf(stderr, "%s%llu", j == 0 ? "" : ",",
					(unsigned long long)item->offsets[j]);
			fprintf(stderr, "\n");
			diagnostic_count++;
		}
	}
	if (fda_reply) {
		int empty_slot = -1;
		size_t i;

		for (i = 0; i < fd_transfer_count; i++)
			if (fd_transfers[i].slot_in_extra)
				memcpy(item->payload + payload_size +
					fd_transfers[i].slot_offset, &empty_slot,
					sizeof(empty_slot));
	}
	target->queue_count++;
	notify_endpoint(target, domain);
	return 0;
}

static BinderBuffer *find_buffer(BinderEndpoint *endpoint, word_t address)
{
	size_t i;

	for (i = 0; i < MAX_BINDER_BUFFERS; i++)
		if (endpoint->buffers[i].active &&
		    endpoint->buffers[i].address == address)
			return &endpoint->buffers[i];
	return NULL;
}

static int release_buffer_references(BinderEndpoint *endpoint,
		BinderBuffer *buffer)
{
	while (buffer->references_released < buffer->reference_count) {
		BinderBufferReference *reference =
			&buffer->references[buffer->references_released];
		int status = update_handle_reference(endpoint, buffer->domain,
			reference->handle, reference->strong, false);

		if (status < 0)
			return status;
		buffer->references_released++;
	}
	free(buffer->references);
	buffer->references = NULL;
	buffer->reference_count = 0;
	buffer->references_released = 0;
	return 0;
}

static int register_buffer(BinderEndpoint *endpoint,
		enum BinderDomain domain, word_t address, size_t size)
{
	size_t i;
	for (i = 0; i < MAX_BINDER_BUFFERS; i++)
		if (!endpoint->buffers[i].active) {
			BinderBuffer *buffer = &endpoint->buffers[i];

			memset(buffer, 0, sizeof(*buffer));
			buffer->active = true;
			buffer->address = address;
			buffer->size = size;
			buffer->domain = domain;
			return 0;
		}
	return -ENOSPC;
}

static int log_buffer_allocation_failure(BinderEndpoint *endpoint,
		enum BinderDomain domain, size_t size, const char *reason,
		word_t candidate, word_t map_end)
{
	static unsigned int diagnostic_count;
	size_t i;

	if (diagnostic_count < 100) {
		BinderMapping *mapping = &endpoint->mappings[domain];

		fprintf(stderr,
			"[BINDER_ALLOC_FAIL] pid=%ld domain=%d reason=%s request=%zu map=%#llx/%zu candidate=%#llx end=%#llx buffers=",
			(long)endpoint->host_pid, (int)domain, reason, size,
			(unsigned long long)mapping->address, mapping->size,
			(unsigned long long)candidate,
			(unsigned long long)map_end);
		for (i = 0; i < MAX_BINDER_BUFFERS; i++) {
			const BinderBuffer *buffer = &endpoint->buffers[i];

			if (buffer->active)
				fprintf(stderr, "%s%zu:%d:%#llx/%zu",
					i == 0 ? "" : ";", i, (int)buffer->domain,
					(unsigned long long)buffer->address, buffer->size);
		}
		fputc('\n', stderr);
		diagnostic_count++;
	}
	return -ENOSPC;
}

static int free_buffer(BinderEndpoint *endpoint, word_t address)
{
	size_t i;
	for (i = 0; i < MAX_BINDER_BUFFERS; i++)
		if (endpoint->buffers[i].active &&
		    endpoint->buffers[i].address == address) {
			int status = release_buffer_references(endpoint,
				&endpoint->buffers[i]);

			if (status < 0)
				return status;
			memset(&endpoint->buffers[i], 0, sizeof(endpoint->buffers[i]));
			return 0;
		}
	return -ENOENT;
}

static int release_transaction_references(BinderEndpoint *recipient,
		BinderTransaction *item)
{
	while (item->references_released < item->reference_count) {
		BinderBufferReference *reference =
			&item->references[item->references_released];
		int status = update_handle_reference(recipient, item->domain,
			reference->handle, reference->strong, false);

		if (status < 0)
			return status;
		item->references_released++;
	}
	free(item->references);
	item->references = NULL;
	item->reference_count = 0;
	item->references_released = 0;
	return 0;
}

static int prepare_transaction_references(BinderEndpoint *recipient,
		BinderTransaction *item)
{
	BinderBufferReference *references;
	size_t offsets_count = item->offsets_size / sizeof(uint64_t);
	size_t i;
	int status = -EINVAL;

	if (item->references != NULL || item->reference_count != 0 ||
	    item->references_released != 0)
		return -EINVAL;
	if (offsets_count == 0)
		return 0;
	references = calloc(offsets_count, sizeof(*references));
	if (references == NULL)
		return -ENOMEM;
	item->references = references;
	for (i = 0; i < offsets_count; i++) {
		struct flat_binder_object object;
		uint64_t offset = item->offsets[i];
		uint32_t type;

		if (offset > item->payload_size ||
		    item->payload_size - (size_t)offset < sizeof(type) ||
		    offset % sizeof(uint32_t) != 0)
			goto fail;
		memcpy(&type, item->payload + (size_t)offset, sizeof(type));
		if (type != BINDER_TYPE_HANDLE &&
		    type != BINDER_TYPE_WEAK_HANDLE)
			continue;
		if (item->payload_size - (size_t)offset < sizeof(object))
			goto fail;
		memcpy(&object, item->payload + (size_t)offset, sizeof(object));
		if (object.b.handle >= 256)
			goto fail;
		references[item->reference_count].handle = object.b.handle;
		references[item->reference_count].strong =
			type == BINDER_TYPE_HANDLE;
		status = update_handle_reference(recipient, item->domain,
			references[item->reference_count].handle,
			references[item->reference_count].strong, true);
		if (status < 0)
			goto fail;
		item->reference_count++;
	}
	if (item->reference_count == 0) {
		free(item->references);
		item->references = NULL;
	}
	return 0;

fail:
	(void)release_transaction_references(recipient, item);
	return status;
}

static int transfer_buffer_references(BinderBuffer *buffer,
		BinderTransaction *item)
{
	if (buffer->domain != item->domain || buffer->references != NULL ||
	    buffer->reference_count != 0 ||
	    (item->reference_count != 0 && item->references == NULL))
		return -EINVAL;
	buffer->references = item->references;
	buffer->reference_count = item->reference_count;
	buffer->references_released = item->references_released;
	item->references = NULL;
	item->reference_count = 0;
	item->references_released = 0;
	return 0;
}

static int allocate_buffer(BinderEndpoint *endpoint,
		enum BinderDomain domain, size_t size, word_t *address)
{
	BinderMapping *mapping;
	word_t map_end;
	word_t candidate;
	size_t attempt;

	if (domain < 0 || domain >= BINDER_DOMAIN_COUNT || size == 0)
		return -EINVAL;
	mapping = &endpoint->mappings[domain];
	if (mapping->address == 0 || mapping->size == 0 ||
	    mapping->address > UINT64_MAX - mapping->size)
		return log_buffer_allocation_failure(endpoint, domain, size,
			"invalid-mapping", mapping->address,
			mapping->address + mapping->size);
	map_end = mapping->address + mapping->size;
	candidate = mapping->address;
	for (attempt = 0; attempt <= MAX_BINDER_BUFFERS; attempt++) {
		word_t allocation_end;
		word_t next_candidate;
		size_t i;

		if (candidate > UINT64_MAX - (sizeof(uint64_t) - 1))
			return -EOVERFLOW;
		candidate = (candidate + sizeof(uint64_t) - 1) &
			~(word_t)(sizeof(uint64_t) - 1);
		next_candidate = candidate;
		if (candidate > map_end || size > map_end - candidate)
			return log_buffer_allocation_failure(endpoint, domain, size,
				"range-exhausted", candidate, map_end);
		allocation_end = candidate + size;
		for (i = 0; i < MAX_BINDER_BUFFERS; i++) {
			BinderBuffer *buffer = &endpoint->buffers[i];
			word_t buffer_end;

			if (!buffer->active)
				continue;
			if (buffer->address > UINT64_MAX - buffer->size)
				return -EOVERFLOW;
			buffer_end = buffer->address + buffer->size;
			if (candidate < buffer_end && buffer->address < allocation_end &&
			    buffer_end > next_candidate)
				next_candidate = buffer_end;
		}
		if (next_candidate == candidate) {
			int status = register_buffer(endpoint, domain, candidate, size);
			if (status < 0)
				(void)log_buffer_allocation_failure(endpoint, domain,
					size, "register-failed", candidate, map_end);
			if (status < 0)
				return status;
			*address = candidate;
			return 0;
		}
		candidate = next_candidate;
	}
	return log_buffer_allocation_failure(endpoint, domain, size,
		"attempt-limit", candidate, map_end);
}

static bool thread_can_accept_inbound_transaction(
		const BinderConfig *thread)
{
	const BinderTransactionFrame *frame;

	if (thread->transaction_depth == 0)
		return true;
	frame = &thread->transaction_stack[thread->transaction_depth - 1];
	return frame->type == BINDER_TRANSACTION_OUTBOUND;
}

static size_t deliverable_transaction(const BinderEndpoint *endpoint,
		const BinderConfig *thread, enum BinderDomain domain)
{
	size_t i;

	for (i = 0; i < endpoint->queue_count; i++)
		if (endpoint->queue[i].domain == domain &&
		    !endpoint->queue[i].delivery_pending &&
		    (endpoint->queue[i].target_thread == NULL ||
		    endpoint->queue[i].target_thread == thread) &&
		    (endpoint->queue[i].command != BR_TRANSACTION ||
		    thread_can_accept_inbound_transaction(thread)) &&
		    (endpoint->queue[i].command != BR_REPLY ||
		     reply_frames_match(endpoint->queue[i].reply_sender, thread,
			endpoint->queue[i].domain,
			endpoint->queue[i].reply_frame_id)))
			return i;
	return endpoint->queue_count;
}

static int dequeue_transaction(BinderEndpoint *endpoint, size_t index)
{
	int status;

	if (index >= endpoint->queue_count)
		return -EINVAL;
	status = release_transaction_references(endpoint,
		&endpoint->queue[index]);
	if (status < 0)
		return status;
	close_transaction_fda(&endpoint->queue[index]);
	free_transaction_buffers(&endpoint->queue[index]);
	if (index + 1 < endpoint->queue_count)
		memmove(&endpoint->queue[index], &endpoint->queue[index + 1],
			(endpoint->queue_count - index - 1) *
			sizeof(endpoint->queue[0]));
	endpoint->queue_count--;
	memset(&endpoint->queue[endpoint->queue_count], 0,
		sizeof(endpoint->queue[0]));
	endpoint->queue[endpoint->queue_count].courier_listener = -1;
	return 0;
}

static size_t transaction_index_by_id(const BinderEndpoint *endpoint,
		uint64_t transaction_id)
{
	size_t i;

	for (i = 0; i < endpoint->queue_count; i++)
		if (endpoint->queue[i].id == transaction_id)
			return i;
	return endpoint->queue_count;
}

static void cancel_fda_transaction(BinderEndpoint *endpoint,
		uint64_t transaction_id)
{
	size_t index = transaction_index_by_id(endpoint, transaction_id);

	if (index < endpoint->queue_count) {
		enum BinderDomain domain = endpoint->queue[index].domain;
		if (dequeue_transaction(endpoint, index) < 0) {
			fprintf(stderr,
				"[BINDER_REF_RELEASE_FAIL] cancelled transaction cleanup\n");
			return;
		}
		if (!endpoint_has_pending(endpoint, domain))
			clear_endpoint_eventfd(endpoint, domain);
	}
}

static void forget_fd(BinderConfig *c, int fd)
{
	BinderEndpoint *endpoint = c->endpoint;
	size_t i;
	static unsigned int diagnostic_count;

	if (endpoint == NULL) {
		BinderFd *binder_fd = find_fd(c, fd);
		if (binder_fd != NULL) {
			if (diagnostic_count < 2000) {
				fprintf(stderr,
					"[DEBUG-BINDER-FD-CLOSE-r143] actor_vpid=%d owner_vpid=%d fd=%d domain=%d endpoint=null\n",
					c->tracee == NULL ? -1 : (int)c->tracee->vpid,
					c->tracee == NULL ? -1 : (int)c->tracee->vpid,
					fd, (int)binder_fd->domain);
				diagnostic_count++;
			}
			memset(binder_fd, 0, sizeof(*binder_fd));
		}
		return;
	}
	/* close() changes the shared CLONE_THREAD file table, so discard the
	 * per-thread bookkeeping entry from every config on this endpoint. */
	for (i = 0; i < endpoint->thread_count; i++) {
		BinderFd *binder_fd = find_fd(endpoint->threads[i], fd);

		if (binder_fd != NULL) {
			if (diagnostic_count < 2000) {
				fprintf(stderr,
					"[DEBUG-BINDER-FD-CLOSE-r143] actor_vpid=%d owner_vpid=%d fd=%d domain=%d threads=%zu\n",
					c->tracee == NULL ? -1 : (int)c->tracee->vpid,
					endpoint->threads[i]->tracee == NULL ? -1 :
						(int)endpoint->threads[i]->tracee->vpid,
					fd, (int)binder_fd->domain,
					endpoint->thread_count);
				diagnostic_count++;
			}
			memset(binder_fd, 0, sizeof(*binder_fd));
		}
	}
}
static void result(Tracee *t, long value) { poke_reg(t, SYSARG_RESULT, (word_t)value); }
static int queue_word(BinderFd *f, uint32_t word)
{
	if (f->read_count >= MAX_BINDER_REPLY_WORDS) return -ENOSPC;
	f->read_words[f->read_count++] = word; return 0;
}
static int deliver_transaction(Tracee *target_tracee, BinderEndpoint *target,
		BinderTransaction *item, word_t read_buffer, size_t read_size,
		size_t *used, word_t *delivery_buffer)
{
	struct binder_transaction_data transaction = item->transaction;
	struct binder_transaction_data_secctx transaction_secctx = {};
	uint8_t payload[MAX_BINDER_PAYLOAD];
	/* Guest Binder metadata only; host credentials remain unchanged. */
	static const char guest_security_context[] = "u:r:su:s0";
	static const uint8_t zero_padding[sizeof(uint64_t)] = {};
	bool include_security_context = item->command == BR_TRANSACTION &&
		item->security_context;
	uint32_t response_command = include_security_context
		? BR_TRANSACTION_SEC_CTX : item->command;
	const void *transaction_response = &transaction;
	size_t transaction_response_size = sizeof(transaction);
	word_t data_address = 0;
	word_t offsets_address = 0;
	word_t extra_address;
	word_t security_context_address = 0;
	size_t payload_space = align_binder_size(item->payload_size);
	size_t offsets_space = item->scatter_gather
		? align_binder_size(item->offsets_size) : item->offsets_size;
	size_t security_context_size = include_security_context
		? sizeof(guest_security_context) : 0;
	size_t allocation_size = payload_space + offsets_space + item->extra_size +
		security_context_size;
	size_t read_total = sizeof(uint32_t) + (include_security_context
		? sizeof(transaction_secctx) : sizeof(transaction));
	bool allocated_buffer = false;
	bool inline_buffer = false;
	size_t i;

	*delivery_buffer = 0;
	if (item->domain == BINDER_DOMAIN_BINDER &&
	    (target->context_manager || item->command == BR_REPLY)) {
		static unsigned int diagnostic_count;

		if (diagnostic_count < 1500) {
			fprintf(stderr,
				"[DEBUG-CM-q3f1-DELIVER] command=%#x txid=%llu frame=%llu sender_vpid=%d target_vpid=%d code=%#x flags=%#x data=%zu offsets=%zu extra=%zu sg=%d secctx=%d\n",
				item->command, (unsigned long long)item->id,
				(unsigned long long)item->reply_frame_id,
				transaction.sender_pid, (int)target_tracee->vpid,
				transaction.code, transaction.flags,
				item->payload_size, item->offsets_size,
				item->extra_size, item->scatter_gather,
				include_security_context);
			diagnostic_count++;
		}
	}
	if (item->domain == BINDER_DOMAIN_HWBINDER && transaction.code == 3) {
		static unsigned int diagnostic_count;

		if (diagnostic_count < 500) {
			fprintf(stderr,
				"[DEBUG-HIDL-GT-a17e-DELIVER] command=%#x sender_pid=%d target_vpid=%d flags=%#x data=%zu offsets=%zu extra=%zu sg=%d secctx=%d\n",
				item->command, transaction.sender_pid,
				(int)target_tracee->vpid, transaction.flags,
				item->payload_size, item->offsets_size, item->extra_size,
				item->scatter_gather, include_security_context);
			diagnostic_count++;
		}
	}
	if (item->domain == BINDER_DOMAIN_HWBINDER &&
	    item->command == BR_REPLY) {
		static unsigned int diagnostic_count;
		uint32_t response_words[4] = {};
		size_t copy_size = item->payload_size < sizeof(response_words)
			? item->payload_size : sizeof(response_words);

		if (copy_size != 0)
			memcpy(response_words, item->payload, copy_size);
		if (diagnostic_count < 200) {
			fprintf(stderr,
				"[DEBUG-HIDL-RPLY-b926-DELIVER] txid=%llu frame=%llu sender_vpid=%d target_thread_vpid=%d code=%#x flags=%#x data=%zu offsets=%zu extra=%zu sg=%d data0=%08x data1=%08x data2=%08x data3=%08x\n",
				(unsigned long long)item->id,
				(unsigned long long)item->reply_frame_id,
				transaction.sender_pid, (int)target_tracee->vpid,
				transaction.code, transaction.flags,
				item->payload_size, item->offsets_size,
				item->extra_size, item->scatter_gather,
				response_words[0], response_words[1],
				response_words[2], response_words[3]);
			diagnostic_count++;
		}
	}
	if (item->domain == BINDER_DOMAIN_HWBINDER &&
	    item->command == BR_TRANSACTION &&
	    (transaction.flags & BINDER_TF_ONE_WAY) != 0) {
		static unsigned int diagnostic_count;

		if (diagnostic_count < 200) {
			fprintf(stderr,
				"[DEBUG-HWCB-68f1-IN] receiver_vpid=%d sender_vpid=%d code=%#x flags=%#x size=%llu\n",
				(int)target_tracee->vpid, transaction.sender_pid,
				transaction.code, transaction.flags,
				(unsigned long long)transaction.data_size);
			diagnostic_count++;
		}
	}
	if (item->command != BR_TRANSACTION && item->command != BR_REPLY) {
		if (item->command == BR_DEAD_BINDER ||
		    item->command == BR_CLEAR_DEATH_NOTIFICATION_DONE) {
			size_t work_size = sizeof(item->command) +
				sizeof(item->transaction.cookie);

			if (read_size < work_size ||
			    read_buffer > UINT64_MAX - work_size)
				return -ENOSPC;
			if (write_data(target_tracee, read_buffer,
					&item->command, sizeof(item->command)) < 0 ||
			    write_data(target_tracee,
					read_buffer + sizeof(item->command),
					&item->transaction.cookie,
					sizeof(item->transaction.cookie)) < 0)
				return -EFAULT;
			*used = work_size;
			return 0;
		}
		struct binder_ptr_cookie ptr_cookie = {
			.ptr = transaction.target,
			.cookie = transaction.cookie,
		};
		size_t work_size = sizeof(item->command) + sizeof(ptr_cookie);

		if ((item->command != BR_INCREFS &&
		     item->command != BR_ACQUIRE &&
		     item->command != BR_RELEASE &&
		     item->command != BR_DECREFS) || read_size < work_size ||
		    read_buffer > UINT64_MAX - work_size)
			return -ENOSPC;
		if (write_data(target_tracee, read_buffer, &item->command,
				sizeof(item->command)) < 0 ||
		    write_data(target_tracee, read_buffer + sizeof(item->command),
				&ptr_cookie, sizeof(ptr_cookie)) < 0)
			return -EFAULT;
		*used = work_size;
		return 0;
	}
	if (read_size < read_total)
		return -ENOSPC;
	if (allocation_size == 0)
		allocation_size = sizeof(uint64_t);
	if (allocation_size != 0) {
		if (item->domain < 0 || item->domain >= BINDER_DOMAIN_COUNT)
			return -EINVAL;
		if (target->mappings[item->domain].size != 0) {
			int status = allocate_buffer(target, item->domain,
				allocation_size, &data_address);
			if (status < 0)
				return status == -ENOSPC ? -ENOMEM : status;
		} else {
			if (allocation_size > SIZE_MAX - read_total ||
			    read_size < read_total + allocation_size ||
			    read_buffer > UINT64_MAX -
				(read_total + allocation_size))
				return -ENOMEM;
			data_address = read_buffer + read_total;
			if (register_buffer(target, item->domain, data_address,
					allocation_size) < 0)
				return -ENOMEM;
			inline_buffer = true;
		}
		allocated_buffer = true;
	}
	if (item->payload_size + item->extra_size != 0)
		memcpy(payload, item->payload,
		       item->payload_size + item->extra_size);
	if (item->payload_size != 0 || allocation_size != 0) {
		transaction.data_buffer = data_address;
	}
	if (item->offsets_size != 0) {
		offsets_address = data_address + payload_space;
		transaction.offsets_buffer = offsets_address;
	}
	extra_address = data_address + payload_space + offsets_space;
	if (include_security_context) {
		security_context_address = extra_address + item->extra_size;
		transaction_secctx.transaction_data = transaction;
		transaction_secctx.secctx = security_context_address;
		transaction_response = &transaction_secctx;
		transaction_response_size = sizeof(transaction_secctx);
	}
	if (item->fd_transfer_count != 0) {
		int32_t invalid_fd = -1;

		for (i = 0; i < item->fd_transfer_count; i++) {
			BinderFdTransfer *transfer = &item->fd_transfers[i];
			word_t slot_base;
			uint8_t *slot_payload;
			size_t slot_limit;

			if (transfer->slot_in_extra) {
				slot_base = extra_address;
				slot_payload = payload + item->payload_size;
				slot_limit = item->extra_size;
			} else {
				slot_base = data_address;
				slot_payload = payload;
				slot_limit = item->payload_size;
			}
			if (transfer->slot_offset > slot_limit ||
			    slot_limit - transfer->slot_offset < sizeof(invalid_fd) ||
			    slot_base > UINT64_MAX - transfer->slot_offset) {
				if (allocated_buffer)
					(void)free_buffer(target, data_address);
				return -EINVAL;
			}
			memcpy(slot_payload + transfer->slot_offset, &invalid_fd,
				sizeof(invalid_fd));
			transfer->recipient_slot_address = slot_base +
				transfer->slot_offset;
		}
	}
	if (item->scatter_gather) {
		for (i = 0; i < item->offsets_size / sizeof(uint64_t); i++) {
			struct binder_buffer_object buffer;
			uint32_t object_type;
			uint64_t offset = item->offsets[i];

			if (offset > item->payload_size ||
			    item->payload_size - (size_t)offset < sizeof(object_type) ||
			    offset % sizeof(uint32_t) != 0)
				return -EINVAL;
			memcpy(&object_type, payload + (size_t)offset,
			       sizeof(object_type));
			if (object_type == BINDER_TYPE_PTR) {
				if (item->payload_size - (size_t)offset < sizeof(buffer))
					return -EINVAL;
				memcpy(&buffer, payload + (size_t)offset,
				       sizeof(buffer));
				if ((buffer.flags & ~BINDER_BUFFER_FLAG_HAS_PARENT) != 0 ||
				    buffer.buffer > item->extra_size ||
				    buffer.length > item->extra_size - buffer.buffer ||
				    buffer.buffer > UINT64_MAX - extra_address)
					return -EOVERFLOW;
				if ((buffer.flags & BINDER_BUFFER_FLAG_HAS_PARENT) != 0) {
					struct binder_buffer_object parent;
					uint32_t parent_type;
					uint64_t parent_object_offset;
					uint64_t parent_relative;
					size_t fixup_offset;
					uint64_t child_address = extra_address +
						buffer.buffer;

					if (buffer.parent >= i ||
					    buffer.parent >= item->offsets_size /
						    sizeof(uint64_t))
						return -EINVAL;
					parent_object_offset =
						item->offsets[buffer.parent];
					if (parent_object_offset > item->payload_size ||
					    item->payload_size -
						    (size_t)parent_object_offset <
						    sizeof(parent_type))
						return -EINVAL;
					memcpy(&parent_type,
					       payload + (size_t)parent_object_offset,
					       sizeof(parent_type));
					if (parent_type != BINDER_TYPE_PTR ||
					    item->payload_size -
						    (size_t)parent_object_offset <
						    sizeof(parent))
						return -EINVAL;
					memcpy(&parent,
					       payload + (size_t)parent_object_offset,
					       sizeof(parent));
					if ((parent.flags &
					     ~BINDER_BUFFER_FLAG_HAS_PARENT) != 0 ||
					    parent.buffer < extra_address)
						return -EINVAL;
					parent_relative = parent.buffer - extra_address;
					if (parent_relative > item->extra_size ||
					    parent.length > item->extra_size -
						    parent_relative ||
					    parent.length < sizeof(uint64_t) ||
					    buffer.parent_offset > parent.length -
						    sizeof(uint64_t))
						return -EINVAL;
					fixup_offset = (size_t)parent_relative +
						(size_t)buffer.parent_offset;
					if (item->extra_size < sizeof(child_address) ||
					    fixup_offset > item->extra_size -
						    sizeof(child_address))
						return -EINVAL;
					memcpy(payload + item->payload_size + fixup_offset,
					       &child_address, sizeof(child_address));
				}
				buffer.buffer += extra_address;
				memcpy(payload + (size_t)offset, &buffer, sizeof(buffer));
			}
		}
	}
	if (write_data(target_tracee, read_buffer, &response_command,
			sizeof(response_command)) < 0 ||
	    write_data(target_tracee, read_buffer + sizeof(item->command),
			transaction_response, transaction_response_size) < 0 ||
	    (item->payload_size != 0 && write_data(target_tracee, data_address,
			payload, item->payload_size) < 0) ||
	    (payload_space > item->payload_size &&
	     write_data(target_tracee, data_address + item->payload_size,
		zero_padding, payload_space - item->payload_size) < 0) ||
	    (item->offsets_size != 0 && write_data(target_tracee, offsets_address,
			item->offsets, item->offsets_size) < 0) ||
	    (offsets_space > item->offsets_size &&
	     write_data(target_tracee, offsets_address + item->offsets_size,
		zero_padding, offsets_space - item->offsets_size) < 0) ||
	    (item->extra_size != 0 && write_data(target_tracee, extra_address,
			payload + item->payload_size, item->extra_size) < 0) ||
	    (include_security_context && write_data(target_tracee,
			security_context_address, guest_security_context,
			security_context_size) < 0)) {
		if (allocated_buffer)
			(void)free_buffer(target, data_address);
		return -EFAULT;
	}
	if (allocated_buffer) {
		BinderBuffer *buffer = find_buffer(target, data_address);
		int status;

		if (buffer == NULL)
			return -EINVAL;
		status = transfer_buffer_references(buffer, item);
		if (status < 0) {
			(void)free_buffer(target, data_address);
			return status;
		}
	}
	if (allocated_buffer)
		*delivery_buffer = data_address;
	*used = inline_buffer ? read_total + allocation_size : read_total;
	return 0;
}

static int start_fda_delivery(Tracee *tracee, BinderConfig *config,
		BinderTransaction *item, word_t bwr_arg,
		const struct binder_write_read *bwr, size_t read_consumed,
		word_t delivery_buffer)
{
	struct BinderFdaCourierScratch scratch = {};
	struct sockaddr_un address;
	socklen_t address_length;
	uintptr_t scratch_address;
	int status;
	size_t scratch_size;

	if (config->fda_chain_stage != BINDER_FDA_CHAIN_IDLE ||
	    item->fd_transfer_count == 0 ||
	    item->fd_transfer_count > MAX_BINDER_FDS ||
	    item->target_thread != config)
		return -EINVAL;
	if (tracee_has_external_files_table_sharing(tracee))
		return -EOPNOTSUPP;
	if (item->courier_listener < 0) {
		item->courier_listener = make_fda_courier_listener(item->id,
			&address, &address_length);
		if (item->courier_listener < 0)
			return item->courier_listener;
	}
	status = fill_fda_courier_address(item->id, &address, &address_length);
	if (status < 0)
		return status;
	if ((size_t)address_length > sizeof(scratch.data.address))
		return -ENAMETOOLONG;
	scratch_size = offsetof(struct BinderFdaCourierReceiveScratch, control) +
		CMSG_SPACE(item->fd_transfer_count * sizeof(int));
	status = binder_fda_scratch_address((uintptr_t)bwr->read_buffer,
		(size_t)bwr->read_size, read_consumed, scratch_size,
		_Alignof(struct BinderFdaCourierScratch), &scratch_address);
	if (status < 0)
		return status;
	config->fda_scratch = (word_t)scratch_address;
	config->fda_scratch_size = scratch_size;
	memcpy(scratch.data.address, &address, (size_t)address_length);
	if (write_data(tracee, config->fda_scratch, &scratch,
			scratch_size) < 0)
		return -EFAULT;
	config->fda_transaction_id = item->id;
	config->fda_bwr_arg = bwr_arg;
	config->fda_bwr = *bwr;
	config->fda_bwr.read_consumed = 0;
	config->fda_delivery_buffer = delivery_buffer;
	config->fda_read_consumed = read_consumed;
	config->fda_courier_fd = -1;
	config->fda_recipient_fd_count = 0;
	config->fda_recipient_fd_close_index = 0;
	config->fda_chain_result = 0;
	config->fda_chain_stage = BINDER_FDA_CHAIN_SOCKET;
	status = register_chained_syscall(tracee, PR_socket, AF_UNIX,
		SOCK_SEQPACKET | SOCK_CLOEXEC, 0, 0, 0, 0);
	if (status < 0) {
		config->fda_chain_stage = BINDER_FDA_CHAIN_IDLE;
		config->fda_transaction_id = 0;
		return status;
	}
	item->delivery_pending = true;
	return 0;
}

static int rollback_fda_delivery(Tracee *tracee, BinderConfig *config,
		int error)
{
	BinderEndpoint *endpoint = config->endpoint;
	size_t index = endpoint == NULL ? 0 : transaction_index_by_id(endpoint,
		config->fda_transaction_id);

	/* Best-effort chained cleanup for descriptors already installed in the
	 * recipient.  Keep the failure result until both closes finish. */
	if (config->fda_recipient_fd_close_index <
	    config->fda_recipient_fd_count) {
		int status = register_chained_syscall(tracee, PR_close,
			config->fda_recipient_fds[
				config->fda_recipient_fd_close_index],
			0, 0, 0, 0, 0);
		if (status == 0) {
			config->fda_chain_result = error < 0 ? error : -EIO;
			config->fda_chain_stage = BINDER_FDA_CHAIN_CLOSE_RECIPIENT;
			return 0;
		}
	}
	if (config->fda_courier_fd >= 0) {
		int status = register_chained_syscall(tracee, PR_close,
			config->fda_courier_fd, 0, 0, 0, 0, 0);
		if (status == 0) {
			config->fda_chain_result = error < 0 ? error : -EIO;
			config->fda_chain_stage = BINDER_FDA_CHAIN_CLOSE_SOCKET;
			return 0;
		}
	}
	if (endpoint != NULL && config->fda_delivery_buffer != 0)
		(void)free_buffer(endpoint, config->fda_delivery_buffer);
	if (index < (endpoint == NULL ? 0 : endpoint->queue_count)) {
		enum BinderDomain domain = endpoint->queue[index].domain;
		int status = dequeue_transaction(endpoint, index);

		if (status < 0)
			return status;
		if (!endpoint_has_pending(endpoint, domain))
			clear_endpoint_eventfd(endpoint, domain);
	}
	config->fda_bwr.read_consumed = 0;
	if (config->fda_bwr_arg != 0)
		(void)write_data(tracee, config->fda_bwr_arg, &config->fda_bwr,
			sizeof(config->fda_bwr));
	config->fda_chain_stage = BINDER_FDA_CHAIN_IDLE;
	config->fda_transaction_id = 0;
	config->fda_delivery_buffer = 0;
	config->fda_scratch_size = 0;
	config->fda_courier_fd = -1;
	config->fda_recipient_fd_count = 0;
	config->fda_recipient_fd_close_index = 0;
	force_chain_final_result(tracee, error < 0 ? error : -EIO);
	return 0;
}

static int commit_fda_delivery(Tracee *tracee, BinderConfig *config)
{
	BinderEndpoint *endpoint = config->endpoint;
	size_t index;
	BinderTransaction *item;
	int status;
	size_t i;

	if (endpoint == NULL || config->fda_recipient_fd_count == 0 ||
	    config->fda_recipient_fd_count > MAX_BINDER_FDS)
		return -EINVAL;
	index = transaction_index_by_id(endpoint, config->fda_transaction_id);
	if (index == endpoint->queue_count)
		return -ECANCELED;
	item = &endpoint->queue[index];
	if (!item->delivery_pending ||
	    item->fd_transfer_count != config->fda_recipient_fd_count ||
	    item->fd_transfer_count == 0 ||
	    item->target_thread != config ||
	    (item->fda_reply &&
	     !reply_frames_match(item->reply_sender, config, item->domain,
		item->reply_frame_id)))
		return -EINVAL;
	if (tracee_has_external_files_table_sharing(tracee))
		return -EOPNOTSUPP;
	for (i = 0; i < item->fd_transfer_count; i++) {
		int32_t recipient_fd = config->fda_recipient_fds[i];
		BinderFdTransfer *transfer = &item->fd_transfers[i];

		if (recipient_fd < 0 || transfer->recipient_slot_address == 0 ||
		    write_data(tracee, transfer->recipient_slot_address,
			&recipient_fd, sizeof(recipient_fd)) < 0) {
			int32_t empty_slot = -1;
			size_t j;

			for (j = 0; j < i; j++)
				(void)write_data(tracee,
					item->fd_transfers[j].recipient_slot_address,
					&empty_slot, sizeof(empty_slot));
			return -EFAULT;
		}
	}
	config->fda_bwr.read_consumed = config->fda_read_consumed;
	if (write_data(tracee, config->fda_bwr_arg, &config->fda_bwr,
			sizeof(config->fda_bwr)) < 0)
		goto reset_slots;
	status = 0;
	if (item->fda_reply) {
		if (item->reply_sender != NULL)
			status = pop_transaction_frame(item->reply_sender,
				BINDER_TRANSACTION_INBOUND, item->domain,
				item->reply_frame_id);
		if (status < 0)
			goto reset_slots;
		status = pop_transaction_frame(config,
			BINDER_TRANSACTION_OUTBOUND, item->domain,
			item->reply_frame_id);
		if (status < 0)
			goto reset_slots;
	} else if (item->command == BR_TRANSACTION &&
		   (item->transaction.flags & BINDER_TF_ONE_WAY) == 0) {
		status = push_transaction_frame(config, BINDER_TRANSACTION_INBOUND,
			item->domain, item->transaction.flags, item->id);
		if (status < 0)
			goto reset_slots;
		config->last_sender = item->sender;
		config->last_sender_domain = item->domain;
	}
	{
		enum BinderDomain domain = item->domain;

		for (i = 0; i < item->fd_transfer_count; i++) {
			enum BinderDomain fd_domain =
				item->fd_transfers[i].domain;

			if (fd_domain >= 0 && fd_domain < BINDER_DOMAIN_COUNT)
				remember_fd(config, config->fda_recipient_fds[i],
					fd_domain);
		}
		status = dequeue_transaction(endpoint, index);
		if (status < 0)
			return status;
		if (!endpoint_has_pending(endpoint, domain))
			clear_endpoint_eventfd(endpoint, domain);
	}
	config->fda_chain_stage = BINDER_FDA_CHAIN_IDLE;
	config->fda_transaction_id = 0;
	config->fda_delivery_buffer = 0;
	config->fda_scratch_size = 0;
	config->fda_courier_fd = -1;
	config->fda_recipient_fd_count = 0;
	config->fda_recipient_fd_close_index = 0;
	force_chain_final_result(tracee, 0);
	return 0;

reset_slots:
	{
		int32_t empty_slot = -1;

		for (i = 0; i < item->fd_transfer_count; i++)
			(void)write_data(tracee,
				item->fd_transfers[i].recipient_slot_address,
				&empty_slot, sizeof(empty_slot));
	}
	return status;
}

static int schedule_fda_close(Tracee *tracee, BinderConfig *config,
		int fd, enum BinderFdaChainStage stage)
{
	int status = register_chained_syscall(tracee, PR_close, fd, 0, 0, 0, 0, 0);

	if (status < 0)
		return rollback_fda_delivery(tracee, config, status);
	config->fda_chain_stage = stage;
	return 0;
}

static int binder_fda_chained_exit(Tracee *tracee, BinderConfig *config)
{
	word_t syscall_result = peek_reg(tracee, CURRENT, SYSARG_RESULT);
	int result = (int)(long)syscall_result;
	int status;
	BinderEndpoint *endpoint = config->endpoint;
	size_t index;
	BinderTransaction *item;

	switch (config->fda_chain_stage) {
	case BINDER_FDA_CHAIN_IDLE:
		return 0;
	case BINDER_FDA_CHAIN_SOCKET:
		if (result < 0)
			return rollback_fda_delivery(tracee, config, result);
		config->fda_courier_fd = result;
		{
			struct sockaddr_un address;
			socklen_t address_length;
			int status = fill_fda_courier_address(
				config->fda_transaction_id, &address,
				&address_length);
			if (status < 0)
				return schedule_fda_close(tracee, config,
					config->fda_courier_fd,
					BINDER_FDA_CHAIN_CLOSE_SOCKET);
			status = register_chained_syscall(tracee, PR_connect,
				config->fda_courier_fd,
				config->fda_scratch,
				address_length, 0, 0, 0);
			if (status < 0) {
				config->fda_chain_result = status;
				return schedule_fda_close(tracee, config,
					config->fda_courier_fd,
					BINDER_FDA_CHAIN_CLOSE_SOCKET);
			}
			config->fda_chain_stage = BINDER_FDA_CHAIN_CONNECT;
		}
		return 0;
	case BINDER_FDA_CHAIN_CONNECT:
		if (result < 0) {
			config->fda_chain_result = result;
			return schedule_fda_close(tracee, config,
				config->fda_courier_fd,
				BINDER_FDA_CHAIN_CLOSE_SOCKET);
		}
		index = endpoint == NULL ? 0 : transaction_index_by_id(endpoint,
			config->fda_transaction_id);
		if (index == (endpoint == NULL ? 0 : endpoint->queue_count)) {
			config->fda_chain_result = -ECANCELED;
			return schedule_fda_close(tracee, config,
				config->fda_courier_fd,
				BINDER_FDA_CHAIN_CLOSE_SOCKET);
		}
		item = &endpoint->queue[index];
		{
			struct BinderFdaCourierReceiveScratch scratch = {};
			pid_t expected_peer_pid;
			int status;
			int staged_fds[MAX_BINDER_FDS];
			size_t i;

			scratch.message.msg_control = (void *)(config->fda_scratch +
				offsetof(struct BinderFdaCourierReceiveScratch,
					control));
			scratch.message.msg_controllen =
				config->fda_scratch_size -
				offsetof(struct BinderFdaCourierReceiveScratch,
					control);
			if (write_data(tracee, config->fda_scratch, &scratch,
					config->fda_scratch_size) < 0) {
				config->fda_chain_result = -EFAULT;
				return schedule_fda_close(tracee, config,
					config->fda_courier_fd,
					BINDER_FDA_CHAIN_CLOSE_SOCKET);
			}

			if (item->target_thread == NULL ||
			    item->target_thread->tracee == NULL ||
			    tracee_host_tgid(item->target_thread->tracee,
					&expected_peer_pid) < 0) {
				status = -ESRCH;
			}
			else {
				for (i = 0; i < item->fd_transfer_count; i++)
					staged_fds[i] =
						item->fd_transfers[i].staged_fd;
				status = courier_send_fds(item->courier_listener,
					staged_fds, item->fd_transfer_count,
					expected_peer_pid);
			}
			if (status < 0) {
				config->fda_chain_result = status;
				return schedule_fda_close(tracee, config,
					config->fda_courier_fd,
					BINDER_FDA_CHAIN_CLOSE_SOCKET);
			}
			status = register_chained_syscall(tracee, PR_recvmsg,
				config->fda_courier_fd, config->fda_scratch,
				MSG_CMSG_CLOEXEC, 0, 0, 0);
			if (status < 0) {
				config->fda_chain_result = status;
				return schedule_fda_close(tracee, config,
					config->fda_courier_fd,
					BINDER_FDA_CHAIN_CLOSE_SOCKET);
			}
			config->fda_chain_stage = BINDER_FDA_CHAIN_RECVMSG;
		}
		return 0;
	case BINDER_FDA_CHAIN_RECVMSG: {
		struct BinderFdaCourierReceiveScratch scratch;
		struct cmsghdr header = {};
		int32_t received_fds[MAX_BINDER_FDS] = {};
		size_t expected_count = 0;
		size_t control_size = config->fda_scratch_size -
			offsetof(struct BinderFdaCourierReceiveScratch, control);
		bool valid_message = false;
		bool header_read = false;
		word_t fd_address = config->fda_scratch +
			offsetof(struct BinderFdaCourierReceiveScratch, control) +
			CMSG_ALIGN(sizeof(header));
		int error = result < 0 ? result : -EBADMSG;
		size_t i;

		memset(&scratch, 0, sizeof(scratch));
		if (read_data(tracee, &scratch, config->fda_scratch,
				config->fda_scratch_size) == 0 &&
		    read_data(tracee, &header, config->fda_scratch +
			offsetof(struct BinderFdaCourierReceiveScratch, control),
			sizeof(header)) == 0) {
			header_read = true;
		}
		if (endpoint != NULL) {
			index = transaction_index_by_id(endpoint,
				config->fda_transaction_id);
			if (index < endpoint->queue_count)
				expected_count =
					endpoint->queue[index].fd_transfer_count;
		}
		if (header_read && header.cmsg_level == SOL_SOCKET &&
		    header.cmsg_type == SCM_RIGHTS &&
		    header.cmsg_len >= CMSG_LEN(sizeof(int)) &&
		    header.cmsg_len <= CMSG_LEN(MAX_BINDER_FDS * sizeof(int)) &&
		    header.cmsg_len - CMSG_LEN(0) <= control_size -
			CMSG_ALIGN(sizeof(header))) {
			size_t available = (size_t)(header.cmsg_len - CMSG_LEN(0));
			size_t count = available / sizeof(int);

			if (count <= MAX_BINDER_FDS &&
			    read_data(tracee, received_fds, fd_address,
				count * sizeof(received_fds[0])) == 0) {
				for (i = 0; i < count; i++)
					if (received_fds[i] >= 0)
						config->fda_recipient_fds[
							config->fda_recipient_fd_count++] =
							received_fds[i];
				valid_message = count == expected_count &&
					header.cmsg_len == CMSG_LEN(
						expected_count * sizeof(int)) &&
					scratch.message.msg_controllen == CMSG_SPACE(
						expected_count * sizeof(int)) &&
					!(scratch.message.msg_flags & MSG_CTRUNC) &&
					config->fda_recipient_fd_count == expected_count;
			}
		}
		if (result < 0 || !valid_message) {
			config->fda_chain_result = error;
			return rollback_fda_delivery(tracee, config, error);
		}
		return schedule_fda_close(tracee, config,
			config->fda_courier_fd, BINDER_FDA_CHAIN_CLOSE_SOCKET);
	}
	case BINDER_FDA_CHAIN_CLOSE_RECIPIENT:
		if (result < 0)
			config->fda_chain_result = -EIO;
		config->fda_recipient_fd_close_index++;
		if (config->fda_recipient_fd_close_index <
		    config->fda_recipient_fd_count)
			return schedule_fda_close(tracee, config,
				config->fda_recipient_fds[
					config->fda_recipient_fd_close_index],
				BINDER_FDA_CHAIN_CLOSE_RECIPIENT);
		if (config->fda_courier_fd >= 0)
			return schedule_fda_close(tracee, config,
				config->fda_courier_fd,
				BINDER_FDA_CHAIN_CLOSE_SOCKET);
		return rollback_fda_delivery(tracee, config,
			config->fda_chain_result < 0 ? config->fda_chain_result : -EIO);
	case BINDER_FDA_CHAIN_CLOSE_SOCKET:
		config->fda_courier_fd = -1;
		if (result < 0) {
			config->fda_chain_result = -EIO;
			return rollback_fda_delivery(tracee, config, -EIO);
		}
		if (config->fda_chain_result < 0)
			return rollback_fda_delivery(tracee, config,
				config->fda_chain_result);
		status = commit_fda_delivery(tracee, config);
		if (status < 0) {
			config->fda_chain_result = status;
			return rollback_fda_delivery(tracee, config, status);
		}
		return 0;
	}
	return rollback_fda_delivery(tracee, config, -EINVAL);
}

static int binder_process_write_read(Tracee *t, BinderFd *f,
		BinderConfig *c, word_t arg)
{
	struct binder_write_read bwr;
	struct binder_transaction_data transaction;
	BinderEndpoint *self = c->endpoint;
	enum BinderDomain domain = f->domain;
	uint8_t payload[MAX_BINDER_PAYLOAD];
	uint64_t offsets[MAX_BINDER_OFFSETS];
	uint32_t command;
	word_t pos;
	bool deferred_output = false;
	static unsigned int diagnostic_count;
	if (self == NULL || read_data(t, &bwr, arg, sizeof(bwr)) < 0)
		return -EFAULT;
	if (bwr.write_size > 1024 * 1024 || bwr.read_size > 1024 * 1024)
		return -EINVAL;
	/* Drain pending read commands before accepting more writes.  If a
	 * transaction is also delivered below, read_consumed becomes nonzero and
	 * the normal tail path intentionally leaves these commands queued.  Let
	 * userspace consume them first so the bounded queue cannot wedge at full. */
	if (f->read_count != 0 && bwr.read_buffer != 0 &&
	    bwr.read_size >= sizeof(uint32_t)) {
		size_t word_count = bwr.read_size / sizeof(uint32_t);
		size_t count = f->read_count < word_count
			? f->read_count : word_count;
		size_t bytes = count * sizeof(uint32_t);

		bwr.write_consumed = 0;
		bwr.read_consumed = 0;
		if (write_data(t, bwr.read_buffer, f->read_words, bytes) < 0)
			return -EFAULT;
		if (count < f->read_count)
			memmove(f->read_words, f->read_words + count,
				(f->read_count - count) * sizeof(f->read_words[0]));
		f->read_count -= count;
		bwr.read_consumed = bytes;
		if (write_data(t, arg, &bwr, sizeof(bwr)) < 0)
			return -EFAULT;
		return 0;
	}
	/* A read-only request should go directly to queued transaction delivery. */
	if (bwr.write_size == 0)
		goto read_queue;
	pos = bwr.write_buffer;
	while (bwr.write_consumed + sizeof(command) <= bwr.write_size) {
		if (read_data(t, &command, pos, sizeof(command)) < 0)
			return -EFAULT;
		pos += sizeof(command);
		bwr.write_consumed += sizeof(command);
		if (diagnostic_count < 1000) {
			fprintf(stderr,
				"[BINDER_CMD] tid=%ld fd=%d command=%08x consumed=%zu write=%zu\n",
				(long)t->pid, f->fd, command,
				(size_t)bwr.write_consumed, (size_t)bwr.write_size);
			diagnostic_count++;
		}
		switch (command) {
		case BC_TRANSACTION:
		case BC_REPLY:
		case BC_TRANSACTION_SG:
		case BC_REPLY_SG: {
			bool is_reply = command == BC_REPLY || command == BC_REPLY_SG;
			bool is_sg = command == BC_TRANSACTION_SG || command == BC_REPLY_SG;
			bool debug_sg_transaction = false;
			bool is_one_way;
			size_t buffers_size = 0;
			size_t extra_size = 0;
			int status;

			if (f->read_count >= MAX_BINDER_REPLY_WORDS)
				return -ENOSPC;
			if (is_sg) {
				struct binder_transaction_data_sg sg;

				if (bwr.write_consumed + sizeof(sg) > bwr.write_size ||
				    read_data(t, &sg, pos, sizeof(sg)) < 0)
					return -EINVAL;
				pos += sizeof(sg);
				bwr.write_consumed += sizeof(sg);
				if (sg.buffers_size > MAX_BINDER_PAYLOAD)
					return -E2BIG;
				buffers_size = (size_t)sg.buffers_size;
				transaction = sg.transaction_data;
			}
			else {
				if (bwr.write_consumed + sizeof(transaction) > bwr.write_size ||
				    read_data(t, &transaction, pos, sizeof(transaction)) < 0)
					return -EINVAL;
				pos += sizeof(transaction);
				bwr.write_consumed += sizeof(transaction);
			}
			if (transaction.data_size > MAX_BINDER_PAYLOAD ||
			    transaction.offsets_size > MAX_BINDER_PAYLOAD ||
			    transaction.offsets_size % sizeof(uint64_t) != 0 ||
			    transaction.offsets_size / sizeof(uint64_t) > MAX_BINDER_OFFSETS)
				return -E2BIG;
			if (transaction.data_size != 0 &&
			    read_data(t, payload, transaction.data_buffer,
				transaction.data_size) < 0)
				return -EFAULT;
			if (transaction.offsets_size != 0 &&
			    read_data(t, offsets, transaction.offsets_buffer,
				transaction.offsets_size) < 0)
				return -EFAULT;
			if (t->vpid == 11 && transaction.data_size == 128 &&
			    transaction.offsets_size == sizeof(uint64_t) &&
			    offsets[0] == 100) {
				static unsigned int diagnostic_count;

				if (diagnostic_count < 20) {
					uint8_t tagged[128] = {};
					uint8_t untagged[128] = {};
					uint8_t tgid_bytes[128] = {};
					struct iovec local = { .iov_base = tagged,
						.iov_len = sizeof(tagged) };
					struct iovec remote = {
						.iov_base = (void *)(uintptr_t)
							transaction.data_buffer,
						.iov_len = sizeof(tagged) };
					long tagged_result;
					long untagged_result;
					long tgid_result;
					long ptrace_words[4] = {};
					int ptrace_errors[4] = {};
					pid_t tgid = tracee_host_pid(t);
					size_t byte_index;

					tagged_result = process_vm_readv(t->pid, &local, 1,
						&remote, 1, 0);
					local.iov_base = untagged;
					remote.iov_base = (void *)(uintptr_t)
						(transaction.data_buffer &
						 UINT64_C(0x00ffffffffffffff));
					untagged_result = process_vm_readv(t->pid, &local, 1,
						&remote, 1, 0);
					local.iov_base = tgid_bytes;
					tgid_result = process_vm_readv(tgid, &local, 1,
						&remote, 1, 0);
					for (byte_index = 0; byte_index < 4; byte_index++) {
						errno = 0;
						ptrace_words[byte_index] = ptrace(PTRACE_PEEKDATA,
							t->pid, (void *)(uintptr_t)
							((transaction.data_buffer &
							 UINT64_C(0x00ffffffffffffff)) + 96 +
							 byte_index * sizeof(long)), NULL);
						ptrace_errors[byte_index] = errno;
					}
					fprintf(stderr,
						"[DEBUG-BINDER-MEM-91d2] tid=%ld tgid=%d data=%#llx tagged=%ld untagged=%ld tgid_read=%ld ptrace_errno=%d,%d,%d,%d ptrace_words=%016lx,%016lx,%016lx,%016lx copied=",
						(long)t->pid, (int)tgid,
						(unsigned long long)transaction.data_buffer,
						tagged_result, untagged_result, tgid_result,
						ptrace_errors[0], ptrace_errors[1],
						ptrace_errors[2], ptrace_errors[3],
						ptrace_words[0], ptrace_words[1],
						ptrace_words[2], ptrace_words[3]);
					for (byte_index = 96; byte_index < 128; byte_index++)
						fprintf(stderr, "%02x", payload[byte_index]);
					fprintf(stderr, " tagged_bytes=");
					for (byte_index = 96; byte_index < 128; byte_index++)
						fprintf(stderr, "%02x", tagged[byte_index]);
					fprintf(stderr, " untagged_bytes=");
					for (byte_index = 96; byte_index < 128; byte_index++)
						fprintf(stderr, "%02x", untagged[byte_index]);
					fprintf(stderr, " tgid_bytes=");
					for (byte_index = 96; byte_index < 128; byte_index++)
						fprintf(stderr, "%02x", tgid_bytes[byte_index]);
					fputc('\n', stderr);
					diagnostic_count++;
				}
			}
			if (domain == BINDER_DOMAIN_BINDER && t->vpid == 11 &&
			    transaction.target == 24) {
				static unsigned int diagnostic_count;

				if (diagnostic_count < 20) {
					uint32_t object_type = 0;
					if (transaction.offsets_size >= sizeof(uint64_t) &&
					    offsets[0] <= transaction.data_size &&
					    transaction.data_size - offsets[0] >=
						    sizeof(object_type))
						memcpy(&object_type, payload + offsets[0],
						       sizeof(object_type));
					fprintf(stderr,
						"[DEBUG-BWR-CAUSE-c9a1] stage=transaction-input vpid=%d target=%llu code=%#x flags=%#x data=%llu offsets=%llu first_offset=%llu first_type=%#x\n",
						(int)t->vpid,
						(unsigned long long)transaction.target,
						transaction.code, transaction.flags,
						(unsigned long long)transaction.data_size,
						(unsigned long long)transaction.offsets_size,
						(unsigned long long)(transaction.offsets_size <
							sizeof(uint64_t) ? 0 : offsets[0]),
						object_type);
					diagnostic_count++;
				}
			}
			debug_sg_transaction = is_sg && transaction.target == 4 &&
				transaction.code == 1 && transaction.flags == 0x11 &&
				transaction.data_size == 212 &&
				transaction.offsets_size == 32 && buffers_size == 88;
			if (debug_sg_transaction) {
				static unsigned int debug_address_count;

				if (debug_address_count < 4) {
					fprintf(stderr,
						"[DEBUG-SG-ADDR-6d32] tid=%ld data_buffer=%#llx offsets_buffer=%#llx\n",
						(long)t->pid,
						(unsigned long long)transaction.data_buffer,
						(unsigned long long)transaction.offsets_buffer);
					debug_address_count++;
				}
			}
			if (debug_sg_transaction) {
				static unsigned int debug_count;

				if (debug_count < 32) {
					size_t debug_i;

					fprintf(stderr,
						"[DEBUG-SG-SHAPE-c9a1] tid=%ld vpid=%d domain=%d target=%llu code=%#x flags=%#x data=%llu offsets=%llu buffers=%zu objects=",
						(long)t->pid, (int)t->vpid, (int)domain,
						(unsigned long long)transaction.target,
						transaction.code, transaction.flags,
						(unsigned long long)transaction.data_size,
						(unsigned long long)transaction.offsets_size,
						buffers_size);
					for (debug_i = 0; debug_i < transaction.offsets_size /
						     sizeof(uint64_t); debug_i++) {
						uint64_t offset = offsets[debug_i];
						uint32_t type = 0;

						if (offset > transaction.data_size ||
						    transaction.data_size - offset <
							    sizeof(type)) {
							fprintf(stderr, "%s%llu:invalid",
								debug_i == 0 ? "" : ",",
								(unsigned long long)offset);
							continue;
						}
						memcpy(&type, payload + (size_t)offset,
						       sizeof(type));
						fprintf(stderr, "%s%llu:%08x",
							debug_i == 0 ? "" : ",",
							(unsigned long long)offset, type);
						if (type == BINDER_TYPE_PTR &&
						    transaction.data_size - offset >=
							    sizeof(struct binder_buffer_object)) {
							struct binder_buffer_object object;

							memcpy(&object, payload + (size_t)offset,
							       sizeof(object));
							fprintf(stderr,
								"(flags=%#x,len=%llu,parent=%llu,parent_offset=%llu)",
								object.flags,
								(unsigned long long)object.length,
								(unsigned long long)object.parent,
								(unsigned long long)object.parent_offset);
						} else if (type == BINDER_TYPE_FDA &&
							transaction.data_size - offset >=
							    sizeof(struct binder_fd_array_object)) {
							struct binder_fd_array_object object;

							memcpy(&object, payload + (size_t)offset,
							       sizeof(object));
							fprintf(stderr,
								"(num_fds=%llu,parent=%llu,parent_offset=%llu)",
								(unsigned long long)object.num_fds,
								(unsigned long long)object.parent,
								(unsigned long long)object.parent_offset);
						}
					}
					fputc('\n', stderr);
					debug_count++;
				}
			}
			if (domain == BINDER_DOMAIN_BINDER && t->vpid == 11 &&
			    transaction.target == 23) {
				static unsigned int debug_count;
				size_t debug_size = transaction.data_size < 96
					? (size_t)transaction.data_size : 96;
				size_t debug_i;

				if (debug_count < 16) {
					fprintf(stderr,
						"[DEBUG-APEX-HANDLE-23] tid=%ld code=%#x flags=%#x data=%llu offsets=%llu data_buffer=%#llx offsets_buffer=%#llx bytes=",
						(long)t->pid, transaction.code,
						transaction.flags,
						(unsigned long long)transaction.data_size,
						(unsigned long long)transaction.offsets_size,
						(unsigned long long)transaction.data_buffer,
						(unsigned long long)transaction.offsets_buffer);
					for (debug_i = 0; debug_i < debug_size; debug_i++)
						fprintf(stderr, "%02x", payload[debug_i]);
					fprintf(stderr, " object_offsets=");
					for (debug_i = 0;
					     debug_i < transaction.offsets_size /
							     sizeof(uint64_t);
					     debug_i++)
						fprintf(stderr, "%s%llu",
							debug_i == 0 ? "" : ",",
							(unsigned long long)offsets[debug_i]);
					fputc('\n', stderr);
					debug_count++;
				}
			}
			if (is_sg) {
				status = copy_scatter_gather_buffers(t, payload,
					(size_t)transaction.data_size, offsets,
					(size_t)transaction.offsets_size, buffers_size,
					&extra_size);
				if (status < 0) {
					if (debug_sg_transaction)
						fprintf(stderr,
							"[DEBUG-SG-FAIL-c9a1] stage=copy status=%d\n",
							status);
					return status;
				}
			}
			transaction.sender_pid = (int32_t)t->vpid;
			transaction.sender_euid = 0;
			is_one_way = (transaction.flags & BINDER_TF_ONE_WAY) != 0;
			if (domain == BINDER_DOMAIN_HWBINDER && transaction.code == 3) {
				static unsigned int diagnostic_count;

				if (diagnostic_count < 500) {
					fprintf(stderr,
						"[DEBUG-HIDL-GT-a17e-CMD] tid=%ld vpid=%d fd=%d operation=%s target=%#llx flags=%#x data=%llu offsets=%llu extra=%zu sg=%d depth=%zu last_sender_vpid=%d\n",
						(long)t->pid, (int)t->vpid, f->fd,
						is_reply ? "reply" : "transaction",
						(unsigned long long)transaction.target,
						transaction.flags,
						(unsigned long long)transaction.data_size,
						(unsigned long long)transaction.offsets_size,
						extra_size, is_sg, c->transaction_depth,
						c->last_sender == NULL ||
							c->last_sender->tracee == NULL ? -1 :
							(int)c->last_sender->tracee->vpid);
					diagnostic_count++;
				}
			}
			if (is_reply) {
				BinderConfig *reply_target = c->last_sender;
				BinderTransactionFrame *frame;
				bool has_fda;
				BinderFdTransfer *fd_transfers = NULL;
				size_t fd_transfer_count = 0;
				int source_fd;
				size_t fda_slot_offset;
				uint64_t transaction_id;
				uint64_t reply_frame_id;
				static unsigned int reply_reject_diagnostic_count;

				if (((reply_target == NULL &&
				      c->last_sender_domain == BINDER_DOMAIN_NONE) ||
				     (reply_target != NULL &&
				      reply_target->endpoint == NULL)) &&
				    transaction_frame_matches(c,
					BINDER_TRANSACTION_INBOUND, domain, 0)) {
					frame = &c->transaction_stack[c->transaction_depth - 1];
					reply_frame_id = frame->transaction_id;
					/* A caller may close after delivery. Consume the reply
					 * and complete the write as a dead transaction. */
					status = pop_transaction_frame(c,
						BINDER_TRANSACTION_INBOUND, domain,
						reply_frame_id);
					if (status < 0)
						return status;
					if (queue_word(f, BR_TRANSACTION_COMPLETE) < 0)
						return -ENOSPC;
					continue;
				}
				if (reply_target == NULL || reply_target->endpoint == NULL ||
				    c->last_sender_domain != domain ||
				    !transaction_frame_matches(c,
					BINDER_TRANSACTION_INBOUND, domain, 0)) {
					if (reply_reject_diagnostic_count < 100) {
						const BinderTransactionFrame *previous =
							c->transaction_depth < 2 ? NULL :
							&c->transaction_stack[
								c->transaction_depth - 2];
						const BinderTransactionFrame *top =
							c->transaction_depth == 0 ? NULL :
							&c->transaction_stack[c->transaction_depth - 1];
						long sender_pid = reply_target == NULL ||
							reply_target->tracee == NULL ? -1 :
							(long) reply_target->tracee->pid;

						fprintf(stderr,
							"[BINDER_REPLY_REJECT] tid=%ld fd=%d domain=%d sender_pid=%ld last_domain=%d depth=%zu previous_type=%d previous_domain=%d previous_id=%llu previous_flags=%#x top_type=%d top_domain=%d top_id=%llu top_flags=%#x code=%#x flags=%#x target=%llu\n",
							(long)t->pid, f->fd, (int)domain,
							sender_pid, (int)c->last_sender_domain,
							c->transaction_depth,
							previous == NULL ? -1 : (int)previous->type,
							previous == NULL ? -1 : (int)previous->domain,
							(unsigned long long)(previous == NULL ? 0 :
								previous->transaction_id),
							previous == NULL ? 0 : previous->request_flags,
							top == NULL ? -1 : (int)top->type,
							top == NULL ? -1 : (int)top->domain,
							(unsigned long long)(top == NULL ? 0 :
								top->transaction_id),
							top == NULL ? 0 : top->request_flags,
							transaction.code, transaction.flags,
							(unsigned long long)transaction.target);
						reply_reject_diagnostic_count++;
					}
					return -EINVAL;
				}
				frame = &c->transaction_stack[c->transaction_depth - 1];
				reply_frame_id = frame->transaction_id;
				status = validate_reply_fd_array(payload,
					(size_t)transaction.data_size, extra_size, offsets,
					(size_t)transaction.offsets_size, is_sg, &has_fda,
					&source_fd, &fda_slot_offset);
				if (status < 0) {
					fprintf(stderr,
						"[DEBUG-BWR-CAUSE-c9a1] stage=validate-reply-fda status=%d vpid=%d data=%llu offsets=%llu\n",
						status, (int)t->vpid,
						(unsigned long long)transaction.data_size,
						(unsigned long long)transaction.offsets_size);
					return status;
				}
				status = validate_direct_fd_objects(payload,
					(size_t)transaction.data_size, offsets,
					(size_t)transaction.offsets_size, &fd_transfers,
					&fd_transfer_count);
				if (status < 0) {
					fprintf(stderr,
						"[DEBUG-BWR-CAUSE-c9a1] stage=validate-reply-direct-fd status=%d vpid=%d data=%llu offsets=%llu\n",
						status, (int)t->vpid,
						(unsigned long long)transaction.data_size,
						(unsigned long long)transaction.offsets_size);
					return status;
				}
				if (has_fda && fd_transfer_count != 0) {
					close_fd_transfers(fd_transfers,
						fd_transfer_count);
					return -EOPNOTSUPP;
				}
				if (has_fda) {
					fd_transfers = calloc(1, sizeof(*fd_transfers));
					if (fd_transfers == NULL)
						return -ENOMEM;
					fd_transfer_count = 1;
					fd_transfers[0].source_fd = source_fd;
					fd_transfers[0].staged_fd = -1;
					fd_transfers[0].domain = BINDER_DOMAIN_NONE;
					fd_transfers[0].slot_in_extra = true;
					fd_transfers[0].slot_offset = fda_slot_offset;
				}
				if (fd_transfer_count != 0 &&
				    (frame->request_flags & BINDER_TF_ACCEPT_FDS) == 0) {
					close_fd_transfers(fd_transfers,
						fd_transfer_count);
					return -EPERM;
				}
				if (fd_transfer_count != 0 &&
				    (get_abi(t) != ABI_DEFAULT ||
				     sizeof_word(t) != sizeof(uint64_t))) {
					close_fd_transfers(fd_transfers,
						fd_transfer_count);
					return -EOPNOTSUPP;
				}
				if (fd_transfer_count != 0) {
					status = capture_fd_transfers(c, fd_transfers,
						fd_transfer_count);
					if (status < 0)
						return status;
				}
				transaction_id = new_transaction_id();
				status = enqueue_transaction(reply_target->endpoint,
					&transaction, payload, transaction.data_size, extra_size,
					offsets, transaction.offsets_size, is_sg, BR_REPLY,
					false, c,
					reply_target, domain, transaction_id,
					fd_transfer_count != 0 ? c : NULL,
					reply_frame_id, fd_transfer_count != 0,
					fd_transfers, fd_transfer_count);
				if (status < 0) {
					if (reply_reject_diagnostic_count < 100) {
						fprintf(stderr,
							"[BINDER_REPLY_ENQUEUE_FAIL] tid=%ld fd=%d status=%d sender_pid=%ld target_pid=%ld domain=%d frame_id=%llu code=%#x flags=%#x\n",
							(long)t->pid, f->fd, status,
							reply_target->tracee == NULL ? -1L :
								(long)reply_target->tracee->pid,
							reply_target->endpoint->tracee == NULL ? -1L :
								(long)reply_target->endpoint->tracee->pid,
							(int)domain,
							(unsigned long long)frame->transaction_id,
							transaction.code, transaction.flags);
						reply_reject_diagnostic_count++;
					}
					return status;
				}
				if (fd_transfer_count == 0) {
					/* Normal replies commit when queued; their caller's
					 * outbound frame is the delivery key.  Pop the responder's
					 * inbound frame so it can accept later requests. */
					status = pop_transaction_frame(c,
						BINDER_TRANSACTION_INBOUND, domain,
						reply_frame_id);
					if (status < 0) {
						fprintf(stderr,
							"[DEBUG-BWR-CAUSE-c9a1] stage=pop-reply-inbound status=%d vpid=%d domain=%d frame=%llu depth=%zu\n",
							status, (int)t->vpid, (int)domain,
							(unsigned long long)reply_frame_id,
							c->transaction_depth);
						return status;
					}
				}
			} else {
				binder_uintptr_t target_node = 0;
				binder_uintptr_t target_cookie = 0;
				BinderEndpoint *target = target_for(self, domain,
					(uint32_t)transaction.target, &target_node,
					&target_cookie);
				bool security_context;
				bool frame_pushed = false;
				BinderFdTransfer *fd_transfers = NULL;
				size_t fd_transfer_count = 0;
				uint64_t transaction_id = new_transaction_id();
				if (domain == BINDER_DOMAIN_BINDER && t->vpid == 11 &&
				    transaction.target == 23) {
					fprintf(stderr,
						"[DEBUG-APEX-HANDLE-23-TARGET] endpoint=%p target_vpid=%d node=%#llx cookie=%#llx\n",
						(void *)target,
						target == NULL || target->tracee == NULL ? -1 :
							(int)target->tracee->vpid,
						(unsigned long long)target_node,
						(unsigned long long)target_cookie);
				}

				if (target == NULL) {
					status = queue_word(f,
						target_failure_command(self, domain,
							transaction.target));
					if (status < 0)
						return status;
					continue;
				}
				if (domain == BINDER_DOMAIN_BINDER &&
				    transaction.code == 0x5f4e5446) {
					static unsigned int diagnostic_count;

					if (diagnostic_count < 100) {
						fprintf(stderr,
							"[DEBUG-BINDER-ROUTE-f18d] txid=%llu sender_vpid=%d handle=%u target_vpid=%d node=%#llx cookie=%#llx flags=%#x\n",
							(unsigned long long)transaction_id,
							(int)t->vpid,
							(uint32_t)transaction.target,
							target->tracee == NULL ? -1 :
								(int)target->tracee->vpid,
							(unsigned long long)target_node,
							(unsigned long long)target_cookie,
							transaction.flags);
						diagnostic_count++;
					}
				}
				security_context = transaction.target == 0
					? target->context_security_context
					: self->handles[domain][
						(uint32_t)transaction.target]
						.transaction_security_context;
				status = validate_direct_fd_objects(payload,
					(size_t)transaction.data_size, offsets,
					(size_t)transaction.offsets_size, &fd_transfers,
					&fd_transfer_count);
				if (status < 0) {
					static unsigned int diagnostic_count;

					if (diagnostic_count < 20) {
						fprintf(stderr,
							"[DEBUG-BWR-CAUSE-c9a1] stage=validate-transaction-direct-fd status=%d vpid=%d target=%llu data=%llu offsets=%llu first_offset=%llu\n",
							status, (int)t->vpid,
							(unsigned long long)transaction.target,
							(unsigned long long)transaction.data_size,
							(unsigned long long)transaction.offsets_size,
							(unsigned long long)(transaction.offsets_size <
								sizeof(uint64_t) ? 0 : offsets[0]));
						diagnostic_count++;
					}
					if (debug_sg_transaction)
						fprintf(stderr,
							"[DEBUG-SG-FAIL-c9a1] stage=validate-fd status=%d\n",
							status);
					return status;
				}
				if (fd_transfer_count != 0 &&
				    (get_abi(t) != ABI_DEFAULT ||
				     sizeof_word(t) != sizeof(uint64_t))) {
					close_fd_transfers(fd_transfers,
						fd_transfer_count);
					return -EOPNOTSUPP;
				}
				if (fd_transfer_count != 0) {
					status = capture_fd_transfers(c, fd_transfers,
						fd_transfer_count);
					if (status < 0)
						return status;
				}
				if (domain == BINDER_DOMAIN_HWBINDER && is_one_way) {
					static unsigned int diagnostic_count;

					if (diagnostic_count < 200) {
						fprintf(stderr,
							"[DEBUG-HWCB-68f1-OUT] sender_vpid=%d receiver_vpid=%d handle=%u code=%#x flags=%#x size=%llu\n",
							(int)t->vpid,
							target->tracee == NULL ? -1 :
								(int)target->tracee->vpid,
							(uint32_t)transaction.target,
							transaction.code, transaction.flags,
							(unsigned long long)transaction.data_size);
						diagnostic_count++;
					}
				}
				if (!is_one_way) {
					status = push_transaction_frame(c,
						BINDER_TRANSACTION_OUTBOUND, domain,
						transaction.flags, transaction_id);
					if (status < 0) {
						close_fd_transfers(fd_transfers,
							fd_transfer_count);
						return status;
					}
					frame_pushed = true;
				}
				transaction.target = target_node;
				transaction.cookie = target_cookie;
				status = enqueue_transaction(target, &transaction, payload,
					transaction.data_size, extra_size, offsets,
					transaction.offsets_size, is_sg, BR_TRANSACTION,
					security_context, c,
					NULL, domain, transaction_id, NULL, 0, false,
					fd_transfers, fd_transfer_count);
				if (status < 0) {
					if (debug_sg_transaction)
						fprintf(stderr,
							"[DEBUG-SG-FAIL-c9a1] stage=enqueue status=%d target_vpid=%d\n",
							status, target->tracee == NULL ? -1 :
								(int)target->tracee->vpid);

					if (domain == BINDER_DOMAIN_BINDER &&
					    t->vpid == 11 && transaction.target == 23)
						fprintf(stderr,
							"[DEBUG-APEX-HANDLE-23-ENQUEUE-FAIL] status=%d target_vpid=%d code=%#x flags=%#x data=%llu offsets=%llu\n",
							status,
							target->tracee == NULL ? -1 :
								(int)target->tracee->vpid,
							transaction.code, transaction.flags,
							(unsigned long long)transaction.data_size,
							(unsigned long long)transaction.offsets_size);
					if (frame_pushed)
						(void)pop_transaction_frame(c,
							BINDER_TRANSACTION_OUTBOUND, domain,
							transaction_id);
					return status;
				}
			if (queue_word(f, BR_TRANSACTION_COMPLETE) < 0)
				return -ENOSPC;
			break;
		}
		/* Replies share this case block but must not reach BC_FREE_BUFFER. */
		break;
		case BC_FREE_BUFFER: {
			binder_uintptr_t buffer;
			static unsigned int free_diagnostic_count;
			static unsigned int cause_diagnostic_count;
			int read_status;
			int free_status = 0;
			size_t i;

			if (bwr.write_consumed + sizeof(buffer) > bwr.write_size)
				return -EINVAL;
			read_status = read_data(t, &buffer, pos, sizeof(buffer));
			if (read_status == 0)
				free_status = free_buffer(self, buffer);
			if (free_diagnostic_count < 20) {
				fprintf(stderr,
					"[BINDER_FREE] tid=%ld fd=%d consumed=%zu write=%zu read=%d ptr=%016llx map=%016llx/%zu free=%d buffers=",
					(long)t->pid, f->fd, (size_t)bwr.write_consumed,
					(size_t)bwr.write_size, read_status,
					(unsigned long long)(read_status == 0 ? buffer : 0),
					(unsigned long long)self->mappings[domain].address,
					self->mappings[domain].size, free_status);
				for (i = 0; i < 4; i++)
					fprintf(stderr, "%s%016llx", i == 0 ? "" : ",",
						(unsigned long long)(self->buffers[i].active
							? self->buffers[i].address : 0));
				fputc('\n', stderr);
				free_diagnostic_count++;
			}
			if (read_status < 0 ||
			    (free_status < 0 && free_status != -ENOENT)) {
				size_t active_count = 0;
				bool address_active = false;

				for (i = 0; i < MAX_BINDER_BUFFERS; i++)
					if (self->buffers[i].active) {
						active_count++;
						if (self->buffers[i].address == buffer &&
						    self->buffers[i].domain == domain)
							address_active = true;
					}
				if (cause_diagnostic_count < 20) {
					fprintf(stderr,
						"[DEBUG-BWR-CAUSE-c9a1] stage=free-buffer read=%d free=%d vpid=%d domain=%d address=%#llx active=%d active_count=%zu\n",
						read_status, free_status, (int)t->vpid,
						(int)domain,
						(unsigned long long)(read_status == 0 ? buffer : 0),
						address_active, active_count);
					cause_diagnostic_count++;
				}
				return -EINVAL;
			}
			pos += sizeof(buffer);
			bwr.write_consumed += sizeof(buffer);
			break;
		}
		case BC_INCREFS:
		case BC_ACQUIRE:
		case BC_RELEASE:
		case BC_DECREFS: {
			uint32_t handle;
			bool strong = command == BC_ACQUIRE || command == BC_RELEASE;
			bool increment = command == BC_INCREFS || command == BC_ACQUIRE;

			if (bwr.write_consumed + sizeof(handle) > bwr.write_size ||
			    read_data(t, &handle, pos, sizeof(handle)) < 0)
				return -EINVAL;
			/* The kernel reports invalid or stale reference changes to
			 * diagnostics, but consumes the command and keeps processing the
			 * write batch.  In particular, late BC_RELEASE/BC_DECREFS after
			 * handle teardown must not turn a valid batch into -EINVAL. */
			(void)update_handle_reference(self, domain, handle, strong,
				increment);
			pos += sizeof(handle);
			bwr.write_consumed += sizeof(handle);
			break;
		}
		case BC_INCREFS_DONE:
		case BC_ACQUIRE_DONE: {
			struct binder_ptr_cookie ptr_cookie;

			if (bwr.write_consumed + sizeof(ptr_cookie) > bwr.write_size ||
			    read_data(t, &ptr_cookie, pos, sizeof(ptr_cookie)) < 0)
				return -EINVAL;
			/* The notification recipient has already updated its own
			 * Binder object; the broker only needs to consume the ack. */
			pos += sizeof(ptr_cookie);
			bwr.write_consumed += sizeof(ptr_cookie);
			break;
		}
		case BC_REQUEST_DEATH_NOTIFICATION:
		case BC_CLEAR_DEATH_NOTIFICATION: {
			struct binder_handle_cookie notification;
			BinderHandle *reference;

			if (bwr.write_consumed + sizeof(notification) >
			    bwr.write_size ||
			    read_data(t, &notification, pos,
				      sizeof(notification)) < 0)
				return -EINVAL;
			reference = reference_for_handle(self, domain,
				notification.handle);
			if (command == BC_REQUEST_DEATH_NOTIFICATION &&
			    domain == BINDER_DOMAIN_HWBINDER) {
				static unsigned int diagnostic_count;

				if (diagnostic_count < 200) {
					int owner_vpid = reference != NULL &&
						reference->endpoint != NULL &&
						reference->endpoint->tracee != NULL ?
						(int)reference->endpoint->tracee->vpid : -1;

					fprintf(stderr,
						"[DEBUG-HWCB-68f1-DEATH] requester_vpid=%d handle=%u reference=%d owner_vpid=%d active=%d pending=%d cookie=%#llx\n",
						(int)t->vpid, notification.handle,
						reference != NULL, owner_vpid,
						reference != NULL &&
							reference->death_notification,
						reference != NULL && reference->death_pending,
						(unsigned long long)notification.cookie);
					diagnostic_count++;
				}
			}
			if (command == BC_REQUEST_DEATH_NOTIFICATION) {
				if (reference != NULL &&
				    !reference->death_notification) {
					reference->death_notification = true;
					reference->death_cookie = notification.cookie;
				}
			} else if (reference != NULL &&
				   reference->death_notification &&
				   reference->death_cookie == notification.cookie) {
				int status = enqueue_death_work(self, domain,
					BR_CLEAR_DEATH_NOTIFICATION_DONE,
					notification.cookie, c);
				if (status < 0)
					return status;
				reference->death_notification = false;
				reference->death_cookie = 0;
			}
			pos += sizeof(notification);
			bwr.write_consumed += sizeof(notification);
			break;
		}
		case BC_DEAD_BINDER_DONE: {
			binder_uintptr_t cookie;
			size_t i;

			if (bwr.write_consumed + sizeof(cookie) > bwr.write_size ||
			    read_data(t, &cookie, pos, sizeof(cookie)) < 0)
				return -EINVAL;
			if (domain >= 0 && domain < BINDER_DOMAIN_COUNT) {
				for (i = 0; i < 256; i++) {
					BinderHandle *reference =
						&self->handles[domain][i];

					if (reference->death_pending &&
					    reference->death_cookie == cookie) {
						reference->death_pending = false;
						reference->death_cookie = 0;
						if (reference->strong_refs == 0 &&
						    reference->weak_refs == 0)
							memset(reference, 0,
								sizeof(*reference));
						break;
					}
				}
			}
			pos += sizeof(cookie);
			bwr.write_consumed += sizeof(cookie);
			break;
		}
		case BC_ENTER_LOOPER:
		case BC_REGISTER_LOOPER:
		case BC_EXIT_LOOPER:
			break;
		default:
			if (diagnostic_count < 1100)
				fprintf(stderr,
					"[DEBUG-BWR-UNKNOWN-c9a1] tid=%ld command=%08x consumed=%zu write=%zu\n",
					(long)t->pid, command, (size_t)bwr.write_consumed,
					(size_t)bwr.write_size);
			return -EINVAL;
		}
	}
	read_queue:
	{
		size_t queue_index = deliverable_transaction(self, c, domain);
		static unsigned int read_diagnostic_count;

		if (domain == BINDER_DOMAIN_BINDER && self->queue_count != 0 &&
		    t->vpid <= 2 &&
		    read_diagnostic_count < 100) {
			BinderTransaction *queued = &self->queue[0];

			fprintf(stderr,
				"[DEBUG-BWR-READ-5d72] vpid=%d domain=%d queue=%zu index=%zu read_count=%zu read_size=%llu read_buffer=%#llx first_domain=%d first_pending=%d first_target=%d first_command=%#x first_code=%#x\n",
				(int)t->vpid, (int)domain, self->queue_count, queue_index,
				f->read_count, (unsigned long long)bwr.read_size,
				(unsigned long long)bwr.read_buffer,
				(int)queued->domain, queued->delivery_pending,
				queued->target_thread == NULL ||
				queued->target_thread->tracee == NULL ? -1 :
					(int)queued->target_thread->tracee->vpid,
				queued->command, queued->transaction.code);
			read_diagnostic_count++;
		}
		if (queue_index != self->queue_count && bwr.read_buffer != 0) {
			size_t used = 0;
			word_t delivery_buffer = 0;
			BinderTransaction *item = &self->queue[queue_index];
			bool push_inbound = item->command == BR_TRANSACTION &&
				(item->transaction.flags & BINDER_TF_ONE_WAY) == 0;
			bool pop_outbound = item->command == BR_REPLY;

			if (push_inbound && !transaction_stack_has_room(c))
				return -EOVERFLOW;
			if (pop_outbound && !reply_frames_match(item->reply_sender, c,
					item->domain, item->reply_frame_id)) {
				fprintf(stderr,
					"[DEBUG-BWR-CAUSE-c9a1] stage=reply-frame-delivery vpid=%d id=%llu frame=%llu depth=%zu top_type=%d top_domain=%d top_id=%llu\n",
					(int)t->vpid, (unsigned long long)item->id,
					(unsigned long long)item->reply_frame_id,
					c->transaction_depth,
					c->transaction_depth == 0 ? -1 :
						(int)c->transaction_stack[c->transaction_depth - 1].type,
					c->transaction_depth == 0 ? -1 :
						(int)c->transaction_stack[c->transaction_depth - 1].domain,
					c->transaction_depth == 0 ? 0 :
						(unsigned long long)c->transaction_stack[
							c->transaction_depth - 1].transaction_id);
				return -EINVAL;
			}
			int status = deliver_transaction(t, self, item,
				bwr.read_buffer, bwr.read_size, &used,
				&delivery_buffer);
			if (status < 0 && status != -ENOSPC)
				fprintf(stderr,
					"[DEBUG-BWR-CAUSE-c9a1] stage=deliver-transaction status=%d vpid=%d command=%#x id=%llu frame=%llu read_size=%llu payload=%zu offsets=%zu\n",
					status, (int)t->vpid, item->command,
					(unsigned long long)item->id,
					(unsigned long long)item->reply_frame_id,
					(unsigned long long)bwr.read_size,
					item->payload_size, item->offsets_size);
			if (status == 0) {
				enum BinderDomain item_domain = item->domain;
				uint64_t queued_id = item->id;
				if (item->fd_transfer_count != 0) {
					if (item->target_thread == NULL)
						item->target_thread = c;
					status = start_fda_delivery(t, c, item, arg, &bwr,
						used, delivery_buffer);
					if (status < 0) {
						(void)free_buffer(self, delivery_buffer);
						cancel_fda_transaction(self, queued_id);
						return status;
					}
					deferred_output = true;
				} else {
					bwr.read_consumed = used;
					if (push_inbound) {
						status = push_transaction_frame(c,
							BINDER_TRANSACTION_INBOUND,
						item_domain,
						item->transaction.flags, item->id);
						if (status < 0)
							return status;
						c->last_sender = item->sender;
						c->last_sender_domain = item_domain;
					} else if (pop_outbound) {
					status = 0;
					if (item->reply_sender != NULL)
						status = pop_transaction_frame(
							item->reply_sender,
							BINDER_TRANSACTION_INBOUND,
							item_domain, item->reply_frame_id);
					if (status < 0)
						return status;
					status = pop_transaction_frame(c,
						BINDER_TRANSACTION_OUTBOUND, item_domain,
						item->reply_frame_id);
					if (status < 0)
						return status;
				}
				status = dequeue_transaction(self, queue_index);
				if (status < 0)
					return status;
				if (!endpoint_has_pending(self, item_domain))
					clear_endpoint_eventfd(self, item_domain);
				}
			}
			else if (status != -ENOSPC) {
				if (status == -ENOMEM) {
					size_t active_buffers = 0;
					size_t payload_space = item->scatter_gather
						? align_binder_size(item->payload_size)
						: item->payload_size;
					size_t offsets_space = item->scatter_gather
						? align_binder_size(item->offsets_size)
						: item->offsets_size;
					size_t allocation_size = payload_space +
						offsets_space + item->extra_size;
					size_t i;

					for (i = 0; i < MAX_BINDER_BUFFERS; i++)
						if (self->buffers[i].active)
							active_buffers++;
					if (allocation_size == 0)
						allocation_size = sizeof(uint64_t);
					fprintf(stderr,
						"[BINDER_DELIVERY_ENOMEM] target_pid=%ld sender_pid=%ld domain=%d command=%#x id=%llu read_size=%llu payload=%zu offsets=%zu extra=%zu sg=%d allocation=%zu map=%#llx/%zu active_buffers=%zu",
						(long)self->host_pid,
						item->reply_sender == NULL ||
							item->reply_sender->tracee == NULL ? -1L :
							(long)item->reply_sender->tracee->pid,
						(int)item->domain, item->command,
						(unsigned long long)item->id,
						(unsigned long long)bwr.read_size,
						item->payload_size, item->offsets_size,
						item->extra_size, item->scatter_gather,
						allocation_size,
						(unsigned long long)self->mappings[item->domain].address,
						self->mappings[item->domain].size, active_buffers);
					for (i = 0; i < MAX_BINDER_BUFFERS; i++) {
						const BinderBuffer *buffer = &self->buffers[i];

						if (buffer->active)
							fprintf(stderr,
								" buffer%zu=%d:%#llx/%zu",
								i, (int)buffer->domain,
								(unsigned long long)buffer->address,
								buffer->size);
					}
					fputc('\n', stderr);
				}
				return status;
			}
		}
	}
	}
	if (!deferred_output && f->read_count != 0 && bwr.read_buffer != 0 &&
	    bwr.read_consumed == 0) {
		size_t n = f->read_count * sizeof(uint32_t);
		if (n > bwr.read_size) n = bwr.read_size;
		if (write_data(t, bwr.read_buffer, f->read_words, n) < 0)
			return -EFAULT;
		bwr.read_consumed = n;
		f->read_count = 0;
	}
	if (!deferred_output && write_data(t, arg, &bwr, sizeof(bwr)) < 0)
		return -EFAULT;
	return 0;
}

static bool prepare_binder_read_wait(Tracee *t, BinderFd *f,
		BinderConfig *c, word_t arg)
{
	struct binder_write_read bwr;
	BinderEndpoint *self = c->endpoint;

	if (self == NULL ||
	    deliverable_transaction(self, c, f->domain) != self->queue_count ||
	    f->read_count != 0 ||
	    read_data(t, &bwr, arg, sizeof(bwr)) < 0 || bwr.write_size != 0 ||
	    bwr.read_buffer == 0 || bwr.read_size < sizeof(struct pollfd))
		return false;

	{
		struct pollfd wait_fd = {
			.fd = f->fd,
			.events = POLLIN,
		};
		if (write_data(t, bwr.read_buffer, &wait_fd, sizeof(wait_fd)) < 0)
			return false;
	}

	if (detranslate_sysnum(get_abi(t), PR_poll) != SYSCALL_AVOIDER) {
		set_sysnum(t, PR_poll);
		poke_reg(t, SYSARG_1, bwr.read_buffer);
		poke_reg(t, SYSARG_2, 1);
		poke_reg(t, SYSARG_3, (word_t)-1);
		return true;
	}

	/* AArch64 has no poll(2) syscall.  Use ppoll(2) with the pollfd
	 * stored in the caller's output buffer. */
	if (get_abi(t) != ABI_DEFAULT || sizeof_word(t) != sizeof(word_t))
		return false;
	set_sysnum(t, PR_ppoll);
	poke_reg(t, SYSARG_1, bwr.read_buffer);
	poke_reg(t, SYSARG_2, 1);
	poke_reg(t, SYSARG_3, 0);
	poke_reg(t, SYSARG_4, 0);
	poke_reg(t, SYSARG_5, 0);
	return true;
}

int binder_callback(Extension *e, ExtensionEvent event, intptr_t data1, intptr_t data2)
{
	BinderConfig *c; Tracee *t = TRACEE(e); Sysnum s;
	switch (event) {
	case INITIALIZATION:
		e->config = talloc_zero(e, BinderConfig); if (!e->config) return -1;
		c = talloc_get_type_abort(e->config, BinderConfig);
		c->tracee = t;
		if (register_thread_config(endpoint_for(t), c) < 0)
			return -1;
		e->filtered_sysnums = filtered_sysnums; return 0;
	case INHERIT_PARENT:
		return 1;
	case INHERIT_CHILD: {
		Extension *parent = (Extension *)data1;
		BinderConfig *pc = talloc_get_type_abort(parent->config, BinderConfig);
		word_t clone_flags = (word_t)data2;
		e->config = talloc_zero(e, BinderConfig); if (!e->config) return -1;
		c = talloc_get_type_abort(e->config, BinderConfig);
		memcpy(c, pc, sizeof(*pc));
		c->tracee = t;
		c->last_sender = NULL;
		c->last_sender_domain = BINDER_DOMAIN_NONE;
		/* Binder transaction frames belong to one thread and must not be
		 * inherited by a clone or forked process. */
		c->transaction_depth = 0;
		memset(c->transaction_stack, 0, sizeof(c->transaction_stack));
		c->fda_chain_stage = BINDER_FDA_CHAIN_IDLE;
		c->fda_transaction_id = 0;
		c->fda_courier_fd = -1;
		c->fda_recipient_fd_count = 0;
		c->fda_recipient_fd_close_index = 0;
		c->fda_delivery_buffer = 0;
		if ((clone_flags & CLONE_THREAD) != 0) {
			if (pc->endpoint == NULL)
				return -1;
			if (register_thread_config(pc->endpoint, c) < 0)
				return -1;
			/* Syscall-local state must not leak between threads. */
			c->last_binder_path = false;
			c->uevent_socket_pending = false;
			c->ioctl_pending = false;
			c->mmap_pending = false;
			for (size_t i = 0; i < MAX_BINDER_FDS; i++)
				c->fds[i].read_count = 0;
		}
		else {
			if (register_thread_config(endpoint_for(t), c) < 0)
				return -1;
		}
		e->filtered_sysnums = filtered_sysnums; return 0;
	}
	case GUEST_PATH:
		c = talloc_get_type_abort(e->config, BinderConfig);
		c->last_domain = binder_domain((const char *)data2);
		c->last_binder_path = c->last_domain != BINDER_DOMAIN_NONE;
		if (strstr((const char *)data2, "binder") != NULL) {
			static unsigned int diagnostic_count;

			if (diagnostic_count < 2000) {
				fprintf(stderr,
					"[DEBUG-BINDER-PATH-r42e] vpid=%d path=%s domain=%d\n",
					(int)t->vpid, (const char *)data2,
					(int)c->last_domain);
				diagnostic_count++;
			}
		}
		if (c->last_binder_path) {
			const char *path = (const char *)data2;
			const char *slash = strrchr((const char *)data2, '/');
			const char *name = slash == NULL ? (const char *)data2 : slash + 1;
			bool binderfs_path = strncmp(path, "/dev/binderfs/", 14) == 0;
			bool legacy_device = strcmp(path, "/dev/binder") == 0 ||
				strcmp(path, "/dev/hwbinder") == 0 ||
				strcmp(path, "/dev/vndbinder") == 0;
			/* Legacy Binder nodes are always provided by the broker.
			 * BinderFS nodes remain unavailable until BINDER_CTL_ADD
			 * allocates the corresponding device. */
			if (strcmp(name, "binder-control") == 0 ||
			    legacy_device ||
			    (binderfs_path && c->last_domain >= 0 &&
			     binderfs_allocated[c->last_domain])) {
				strcpy((char *)data1, "/dev/null");
			}
			else
				strcpy((char *)data1, "/dev/shm/procroot-binder-missing");
			return 1;
		}
		return 0;
	case SYSCALL_CHAINED_EXIT:
		c = talloc_get_type_abort(e->config, BinderConfig);
		return binder_fda_chained_exit(t, c);
	case SYSCALL_ENTER_START:
		c = talloc_get_type_abort(e->config, BinderConfig); s = get_sysnum(t, ORIGINAL);

		/* shutdown(2) half-closes a socket; only reboot affects the host. */
		if (s == PR_reboot)
			return -EPERM;
		/* ueventd's kernel netlink stream is a host-global interface.  A
		 * guest listener sees unrelated host events and can spin forever;
		 * Binder mode supplies a device namespace without exposing it. */
		if (s == PR_socket &&
		    peek_reg(t, CURRENT, SYSARG_1) == AF_NETLINK &&
		    peek_reg(t, CURRENT, SYSARG_3) == NETLINK_KOBJECT_UEVENT)
			c->uevent_socket_pending = true;
		if (s == PR_bind &&
		    is_uevent_socket(c, (int)peek_reg(t, CURRENT, SYSARG_1))) {
			word_t address_ptr = peek_reg(t, CURRENT, SYSARG_2);
			word_t address_size = peek_reg(t, CURRENT, SYSARG_3);
			struct sockaddr_nl address;

			if (address_ptr != 0 && address_size >= sizeof(address) &&
			    read_data(t, &address, address_ptr, sizeof(address)) == 0 &&
			    address.nl_family == AF_NETLINK && address.nl_groups != 0) {
				/* Never subscribe a guest ueventd to host-global
				 * kernel broadcasts.  Bind it without multicast groups. */
				address.nl_groups = 0;
				if (write_data(t, address_ptr, &address, sizeof(address)) < 0)
					return -EFAULT;
			}
		}
		if (s == PR_mmap || s == PR_mmap2) {
			int fd = (int)peek_reg(t, CURRENT, SYSARG_5);
			BinderFd *f = find_fd(c, fd);
			if (f != NULL) {
				word_t flags = peek_reg(t, CURRENT, SYSARG_4);
				c->mmap_pending = true;
				c->pending_mmap_domain = f->domain;
				c->pending_mmap_size =
					(size_t)peek_reg(t, CURRENT, SYSARG_2);
				poke_reg(t, SYSARG_5, (word_t)-1);
				poke_reg(t, SYSARG_4, flags | MAP_ANONYMOUS);
			}
		}
		if (s == PR_ioctl || s == PR_x32_ioctl) {
			int fd = (int)peek_reg(t, CURRENT, SYSARG_1);
			unsigned long req = (unsigned long)peek_reg(t, CURRENT, SYSARG_2);
			word_t arg = peek_reg(t, CURRENT, SYSARG_3);
			BinderFd *f = find_fd(c, fd);
			if (((req >> 8) & 0xff) == BINDER_IOCTL_TYPE || IS_BINDER_CTL(req)) {
				if (f == NULL) {
					static unsigned int diagnostic_count;

					if (diagnostic_count < 2000) {
						fprintf(stderr,
							"[DEBUG-BINDER-FD-FALLBACK-r143] vpid=%d fd=%d request=%#lx default_domain=%d endpoint=%p threads=%zu\n",
							(int)t->vpid, fd, req,
							(int)BINDER_DOMAIN_BINDER,
							(void *)c->endpoint,
							c->endpoint == NULL ? 0 :
								c->endpoint->thread_count);
						diagnostic_count++;
					}
					if (c->endpoint != NULL) {
						for (size_t i = 0;
						     i < c->endpoint->thread_count; i++) {
							BinderConfig *peer = c->endpoint->threads[i];
							BinderFd *peer_fd = peer == NULL ? NULL :
								find_fd(peer, fd);
							if (peer_fd != NULL)
								fprintf(stderr,
									"[DEBUG-BINDER-FD-PEER-r143] requester_vpid=%d peer_vpid=%d fd=%d domain=%d endpoint=%p\n",
									(int)t->vpid,
									peer->tracee == NULL ? -1 :
										(int)peer->tracee->vpid,
									fd, (int)peer_fd->domain,
									(void *)c->endpoint);
						}
					}
					remember_fd(c, fd, BINDER_DOMAIN_BINDER);
					f = find_fd(c, fd);
				}
				c->ioctl_pending = true; c->pending_fd = fd;
				c->pending_request = req; c->pending_arg = arg;
				if (req != BINDER_WRITE_READ || f == NULL ||
				    !prepare_binder_read_wait(t, f, c, arg))
					set_sysnum(t, PR_getpid);
			}
		}
		if (s == PR_close) forget_fd(c, (int)peek_reg(t, CURRENT, SYSARG_1));
		return 0;
	case SYSCALL_ENTER_END:
		c = talloc_get_type_abort(e->config, BinderConfig);
		s = get_sysnum(t, ORIGINAL);
		if (c->last_binder_path)
			(void)replace_binder_open_with_eventfd(t, s);
		return 0;
	case SYSCALL_EXIT_START:
		c = talloc_get_type_abort(e->config, BinderConfig); s = get_sysnum(t, ORIGINAL);
		if ((s == PR_ioctl || s == PR_x32_ioctl) && !c->ioctl_pending) {
			int fd = (int)peek_reg(t, CURRENT, SYSARG_1);
			unsigned long req = (unsigned long)peek_reg(t, CURRENT, SYSARG_2);
			BinderFd *f = find_fd(c, fd);
			if (((req >> 8) & 0xff) == BINDER_IOCTL_TYPE || IS_BINDER_CTL(req)) {
				if (f == NULL) {
					remember_fd(c, fd, BINDER_DOMAIN_BINDER);
					f = find_fd(c, fd);
				}
			c->ioctl_pending = true;
			c->pending_fd = fd;
			c->pending_request = req;
			}
		}
		return 0;
	case SYSCALL_EXIT_END:
		c = talloc_get_type_abort(e->config, BinderConfig); s = get_sysnum(t, ORIGINAL);
		if (s == PR_socket && c->uevent_socket_pending) {
			long fd = (long)peek_reg(t, CURRENT, SYSARG_RESULT);
			if (fd >= 0)
				remember_uevent_socket(c, (int)fd);
			c->uevent_socket_pending = false;
		}
		if ((s == PR_ioctl || s == PR_x32_ioctl) && !c->ioctl_pending) {
			int fd = (int) peek_reg(t, CURRENT, SYSARG_1);
			unsigned long req = peek_reg(t, CURRENT, SYSARG_2);
			if (find_fd(c, fd) || IS_BINDER_CTL(req)) {
				c->ioctl_pending = true;
				c->pending_fd = fd;
				c->pending_request = req;
				c->pending_arg = peek_reg(t, CURRENT, SYSARG_3);
			}
		}
		if ((s == PR_open || s == PR_openat || s == PR_openat2) && c->last_binder_path) {
			long opened_fd = (long)peek_reg(t, CURRENT, SYSARG_RESULT);
			if (opened_fd >= 0) {
				static unsigned int diagnostic_count;
				remember_fd(c, (int)opened_fd, c->last_domain);
				if (diagnostic_count < 2000) {
					fprintf(stderr,
						"[DEBUG-BINDER-OPEN-r42e] vpid=%d fd=%ld domain=%d\n",
						(int)t->vpid, opened_fd, (int)c->last_domain);
					diagnostic_count++;
				}
			}
			c->last_binder_path = false;
		}
		if ((s == PR_mmap || s == PR_mmap2) && c->mmap_pending) {
			word_t address = peek_reg(t, CURRENT, SYSARG_RESULT);
			enum BinderDomain domain = c->pending_mmap_domain;

			if ((long)address >= 0 && c->endpoint != NULL &&
			    domain >= 0 && domain < BINDER_DOMAIN_COUNT) {
				c->endpoint->mappings[domain].address = address;
				c->endpoint->mappings[domain].size = c->pending_mmap_size;
			}
			c->mmap_pending = false;
		}
		if ((s == PR_mknod || s == PR_mknodat) && c->last_binder_path) {
			if ((long)peek_reg(t, CURRENT, SYSARG_RESULT) < 0)
				result(t, 0);
			c->last_binder_path = false;
		}
		/* The enter handler replaces Binder ioctl with getpid so the host
		 * never executes the ioctl.  Therefore ORIGINAL is no longer an
		 * ioctl at exit; the pending flag is the authoritative marker. */
		if (c->ioctl_pending) {

			BinderFd *f = find_fd(c, c->pending_fd); long r = 0; word_t arg = c->pending_arg;
			static unsigned int ioctl_error_diagnostic_count;
			if (!f) r = -EBADF;
			else if (IS_BINDER_CTL(c->pending_request)) {
				struct procroot_binderfs_device device;
				if (read_data(t, &device, arg, sizeof(device)) < 0)
					r = -EFAULT;
				else if (device.name[0] == '\0' ||
					strnlen(device.name, sizeof(device.name)) == sizeof(device.name))
					r = -EINVAL;
				else {
					/* BinderFS nodes are represented by the userspace Binder
					 * broker, not host device nodes.  Return harmless stable
					 * numbers so binder_alloc can create its guest names. */
					device.major = 511;
					device.minor = binderfs_next_minor++;
					if (strcmp(device.name, "binder") == 0)
						binderfs_allocated[BINDER_DOMAIN_BINDER] = true;
					else if (strcmp(device.name, "hwbinder") == 0)
						binderfs_allocated[BINDER_DOMAIN_HWBINDER] = true;
					else if (strcmp(device.name, "vndbinder") == 0)
						binderfs_allocated[BINDER_DOMAIN_VNDBINDER] = true;
					if (write_data(t, arg, &device, sizeof(device)) < 0)
						r = -EFAULT;
				}
			}
			else if (c->pending_request == BINDER_VERSION) {
				struct binder_version v = { BINDER_CURRENT_PROTOCOL_VERSION };
				int wr = write_data(t, arg, &v, sizeof(v));
				if (wr < 0) r = -EFAULT;
			}
			else if (c->pending_request == BINDER_SET_MAX_THREADS) { uint32_t n; if (read_data(t, &n, arg, sizeof(n)) < 0) r = -EFAULT; else f->max_threads = n; }
			else if (c->pending_request == BINDER_SET_CONTEXT_MGR ||
				 c->pending_request == BINDER_SET_CONTEXT_MGR_EXT) {
				BinderEndpoint *endpoint = c->endpoint;
				enum BinderDomain domain = f->domain;
				bool extended =
					c->pending_request == BINDER_SET_CONTEXT_MGR_EXT;
				struct binder_context_mgr_ext manager = {};

				if (extended &&
				    read_data(t, &manager, arg, sizeof(manager)) < 0)
					r = -EFAULT;
				else if (extended &&
					 manager.obj.hdr_type != BINDER_TYPE_BINDER &&
					 manager.obj.hdr_type != BINDER_TYPE_WEAK_BINDER)
					r = -EINVAL;
				else if (domain < 0 || domain >= BINDER_DOMAIN_COUNT)
					r = -ENODEV;
				else if (binder_broker.context_manager[domain] != NULL &&
				    binder_broker.context_manager[domain] != endpoint)
					r = -EBUSY;
				else {
					binder_broker.context_manager[domain] = endpoint;
					if (endpoint != NULL) {
						endpoint->context_manager = true;
						endpoint->context_security_context = extended &&
							(manager.obj.flags &
							 FLAT_BINDER_FLAG_TXN_SECURITY_CTX) != 0;
						endpoint->context_node = extended
							? manager.obj.b.binder : 0;
						endpoint->context_cookie = extended
							? manager.obj.cookie : 0;
					}
					if (domain == BINDER_DOMAIN_BINDER)
						fprintf(stderr,
							"[DEBUG-CM-q3f1-REGISTER] vpid=%d domain=%d extended=%d secctx=%d flags=%#x\n",
							c->tracee == NULL ? -1 :
								(int)c->tracee->vpid,
							(int)domain, extended,
							endpoint != NULL &&
								endpoint->context_security_context,
							extended ? manager.obj.flags : 0);
				}
			}
			else if (c->pending_request == BINDER_WRITE_READ)
				r = binder_process_write_read(t, f, c, arg);
			else if (c->pending_request == BINDER_THREAD_EXIT) { }
			else r = -ENOTTY;
			if (r < 0 && c->pending_request == BINDER_WRITE_READ &&
			    ioctl_error_diagnostic_count < 200) {
				struct binder_write_read failed_bwr = {};
				uint32_t failed_words[64] = {};
				size_t failed_word_count = 0;
				int bwr_status = read_data(t, &failed_bwr, arg,
						sizeof(failed_bwr));
				if (bwr_status == 0 && failed_bwr.write_buffer != 0) {
					failed_word_count = failed_bwr.write_size /
						sizeof(failed_words[0]);
					if (failed_word_count >
					    sizeof(failed_words) / sizeof(failed_words[0]))
						failed_word_count = sizeof(failed_words) /
							sizeof(failed_words[0]);
					if (failed_word_count != 0 &&
					    read_data(t, failed_words,
						failed_bwr.write_buffer,
						failed_word_count * sizeof(failed_words[0])) < 0)
						failed_word_count = 0;
				}

				fprintf(stderr,
					"[BINDER_IOCTL_ERROR] tid=%ld fd=%d request=%lx arg=%lx result=%ld bwr_status=%d write=%llu read=%llu write_consumed=%llu read_consumed=%llu words=%08x,%08x,%08x,%08x,%08x,%08x,%08x,%08x\n",
					(long)t->pid, f->fd,
					c->pending_request, (unsigned long)arg, r,
					bwr_status,
					(unsigned long long)failed_bwr.write_size,
					(unsigned long long)failed_bwr.read_size,
					(unsigned long long)failed_bwr.write_consumed,
					(unsigned long long)failed_bwr.read_consumed,
					failed_words[0], failed_words[1],
					failed_words[2], failed_words[3],
					failed_words[4], failed_words[5],
					failed_words[6], failed_words[7]);
				fprintf(stderr,
					"[DEBUG-BWR-DETAIL-c9a1] tid=%ld result=%ld write_bytes=%llu words=",
					(long)t->pid, r,
					(unsigned long long)failed_bwr.write_size);
				for (size_t i = 0; i < failed_word_count; i++)
					fprintf(stderr, "%s%08x", i == 0 ? "" : ",",
						failed_words[i]);
				fputc('\n', stderr);
				ioctl_error_diagnostic_count++;
			}
			result(t, r); c->ioctl_pending = false;
		}
		return 0;
	case NEW_STATUS:
		c = talloc_get_type_abort(e->config, BinderConfig);
		if ((WIFEXITED((int)data1) || WIFSIGNALED((int)data1)) &&
		    c->endpoint != NULL) {
			BinderEndpoint *endpoint = c->endpoint;
			unregister_thread_config(endpoint, c);
			if (endpoint->references == 0)
				release_endpoint(endpoint);
		}
		return 0;
	default: return 0;
	}
}
