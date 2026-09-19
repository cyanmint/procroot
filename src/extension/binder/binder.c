/* Userspace Binder UAPI compatibility layer.
 *
 * The extension owns the Binder process state in the tracer and handles the
 * non-blocking Binder control ABI without requiring a Binder kernel module.
 * Transaction routing is deliberately isolated behind binder_process_write_read;
 * this keeps the UAPI parser independent from the future broker transport.
 */
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <talloc.h>

#include "extension/extension.h"
#include "syscall/syscall.h"
#include "syscall/sysnum.h"
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
struct binder_context_mgr_ext { struct flat_binder_object obj; };
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
#define BC_REGISTER_LOOPER _IO('c', 11)
#define BC_ENTER_LOOPER _IO('c', 12)
#define BC_EXIT_LOOPER _IO('c', 13)
#define BR_TRANSACTION _IOR('r', 2, struct binder_transaction_data)
#define BR_REPLY _IOR('r', 3, struct binder_transaction_data)
#define BR_TRANSACTION_COMPLETE _IO('r', 6)
#define BR_NOOP _IO('r', 12)
#define BR_FAILED_REPLY _IO('r', 17)
#define BR_DEAD_REPLY _IO('r', 5)
#define BINDER_VERSION _IOWR(BINDER_IOCTL_TYPE, 9, struct binder_version)
#define BINDER_SET_MAX_THREADS _IOW(BINDER_IOCTL_TYPE, 5, uint32_t)
#define BINDER_SET_CONTEXT_MGR _IOW(BINDER_IOCTL_TYPE, 7, uint32_t)
#define BINDER_SET_CONTEXT_MGR_EXT _IOW(BINDER_IOCTL_TYPE, 13, struct binder_context_mgr_ext)
#define BINDER_THREAD_EXIT _IOW(BINDER_IOCTL_TYPE, 8, uint32_t)
#define BINDER_WRITE_READ _IOWR(BINDER_IOCTL_TYPE, 1, struct binder_write_read)
#define MAX_BINDER_FDS 64
#define MAX_BINDER_QUEUE 64
#define MAX_BINDER_REPLY_WORDS 256
#define MAX_BINDER_ENDPOINTS 128
#define MAX_BINDER_TRANSACTIONS 32
#define MAX_BINDER_PAYLOAD 65536
#define MAX_BINDER_OFFSETS (MAX_BINDER_PAYLOAD / sizeof(uint64_t))
#define BINDER_TYPE_BINDER 0x85
#define BINDER_TYPE_WEAK_BINDER 0x80
#define BINDER_TYPE_HANDLE 0x86
#define BINDER_TYPE_WEAK_HANDLE 0x81
#define BINDER_TYPE_FD 0x87

enum BinderDomain {
	BINDER_DOMAIN_BINDER = 0,
	BINDER_DOMAIN_HWBINDER,
	BINDER_DOMAIN_VNDBINDER,
	BINDER_DOMAIN_COUNT,
	BINDER_DOMAIN_NONE = -1,
};

typedef struct BinderEndpoint BinderEndpoint;
typedef struct {
	int fd;
	bool active;
	enum BinderDomain domain;
	bool context_manager;
	uint32_t max_threads;
	uint32_t read_words[MAX_BINDER_REPLY_WORDS];
	size_t read_count;
} BinderFd;
typedef struct {
	uint32_t command;
	struct binder_transaction_data transaction;
	size_t payload_size;
	size_t offsets_size;
	uint8_t payload[MAX_BINDER_PAYLOAD];
	uint64_t offsets[MAX_BINDER_OFFSETS];
	BinderEndpoint *sender;
} BinderTransaction;
struct BinderEndpoint {
	Tracee *tracee;
	bool context_manager;
	BinderTransaction queue[MAX_BINDER_TRANSACTIONS];
	size_t queue_count;
	BinderEndpoint *last_sender;
	BinderEndpoint *handles[256];
};
typedef struct {
	bool last_binder_path;
	enum BinderDomain last_domain;
	bool ioctl_pending;
	int pending_fd;
	unsigned long pending_request;
	BinderFd fds[MAX_BINDER_FDS];
} BinderConfig;
static struct {
	BinderEndpoint endpoints[MAX_BINDER_ENDPOINTS];
	size_t count;
	BinderEndpoint *context_manager[BINDER_DOMAIN_COUNT];
} binder_broker;

static FilteredSysnum filtered_sysnums[] = {
	{ PR_open, FILTER_SYSEXIT }, { PR_openat, FILTER_SYSEXIT },
	{ PR_openat2, FILTER_SYSEXIT }, { PR_ioctl, FILTER_SYSEXIT },
	{ PR_mmap, FILTER_SYSEXIT }, { PR_mmap2, FILTER_SYSEXIT },
	{ PR_mknod, FILTER_SYSEXIT }, { PR_mknodat, FILTER_SYSEXIT },
	{ PR_close, 0 }, FILTERED_SYSNUM_END,
};
static enum BinderDomain binder_domain(const char *p)
{
	if (strcmp(p, "/dev/hwbinder") == 0)
		return BINDER_DOMAIN_HWBINDER;
	if (strcmp(p, "/dev/vndbinder") == 0)
		return BINDER_DOMAIN_VNDBINDER;
	if (strcmp(p, "/dev/binder") == 0 || strcmp(p, "/dev/binder-control") == 0 ||
	    strncmp(p, "/dev/binderfs/", 14) == 0)
		return BINDER_DOMAIN_BINDER;
	return BINDER_DOMAIN_NONE;
}
static BinderFd *find_fd(BinderConfig *c, int fd)
{
	int i; for (i = 0; i < MAX_BINDER_FDS; i++)
		if (c->fds[i].active && c->fds[i].fd == fd) return &c->fds[i];
	return NULL;
}
static void remember_fd(BinderConfig *c, int fd, enum BinderDomain domain)
{
	int i; if (fd < 0 || find_fd(c, fd)) return;
	for (i = 0; i < MAX_BINDER_FDS; i++) if (!c->fds[i].active) {
		c->fds[i].active = true; c->fds[i].fd = fd; c->fds[i].domain = domain; return;
	}
}
static BinderEndpoint *endpoint_for(Tracee *tracee)
{
	size_t i;
	for (i = 0; i < binder_broker.count; i++)
		if (binder_broker.endpoints[i].tracee == tracee)
			return &binder_broker.endpoints[i];
	if (binder_broker.count == MAX_BINDER_ENDPOINTS)
		return NULL;
	memset(&binder_broker.endpoints[binder_broker.count], 0,
	       sizeof(binder_broker.endpoints[0]));
	binder_broker.endpoints[binder_broker.count].tracee = tracee;
	return &binder_broker.endpoints[binder_broker.count++];
}

static BinderEndpoint *target_for(BinderEndpoint *sender,
		enum BinderDomain domain, uint32_t handle)
{
	if (domain < 0 || domain >= BINDER_DOMAIN_COUNT)
		return NULL;
	if (handle == 0)
		return binder_broker.context_manager[domain];
	if (sender != NULL && handle < 256 && sender->handles[handle] != NULL)
		return sender->handles[handle];
	return binder_broker.context_manager[domain];
}

static int handle_for(BinderEndpoint *recipient, BinderEndpoint *owner,
		uint64_t node, bool weak)
{
	uint32_t i;
	(void)node;
	(void)weak;
	for (i = 1; i < 256; i++)
		if (recipient->handles[i] == owner)
			return (int)i;
	for (i = 1; i < 256; i++)
		if (recipient->handles[i] == NULL) {
			recipient->handles[i] = owner;
			return (int)i;
		}
	return -1;
}

static int translate_objects(BinderEndpoint *sender, BinderEndpoint *recipient,
		uint8_t *payload, size_t payload_size, uint64_t *offsets,
		size_t offsets_size)
{
	size_t i;
	for (i = 0; i < offsets_size / sizeof(uint64_t); i++) {
		uint64_t offset = offsets[i];
		struct flat_binder_object *object;
		int handle;
		if (offset > payload_size || payload_size - offset < sizeof(*object) ||
		    offset % sizeof(uint64_t) != 0)
			return -EINVAL;
		object = (struct flat_binder_object *)(payload + offset);
		switch (object->hdr_type) {
		case BINDER_TYPE_BINDER:
		case BINDER_TYPE_WEAK_BINDER:
			handle = handle_for(recipient, sender, object->b.binder,
				object->hdr_type == BINDER_TYPE_WEAK_BINDER);
			if (handle < 0)
				return -ENOSPC;
			object->hdr_type = object->hdr_type == BINDER_TYPE_BINDER
				? BINDER_TYPE_HANDLE : BINDER_TYPE_WEAK_HANDLE;
			object->b.handle = (uint32_t)handle;
			object->cookie = 0;
			break;
		case BINDER_TYPE_HANDLE:
		case BINDER_TYPE_WEAK_HANDLE:
			if (object->b.handle == 0 || object->b.handle >= 256 ||
			    sender->handles[object->b.handle] == NULL)
				return -EINVAL;
			break;
		case BINDER_TYPE_FD:
			return -ENOTSUP;
		default:
			return -EINVAL;
		}
	}
	return 0;
}

static int enqueue_transaction(BinderEndpoint *target,
		const struct binder_transaction_data *transaction,
		const void *payload, size_t payload_size, const uint64_t *offsets,
		size_t offsets_size, uint32_t command, BinderEndpoint *sender)
{
	BinderTransaction *item;
	int status;
	if (target == NULL || sender == NULL ||
	    target->queue_count == MAX_BINDER_TRANSACTIONS ||
	    payload_size > MAX_BINDER_PAYLOAD ||
	    offsets_size > MAX_BINDER_PAYLOAD ||
	    offsets_size % sizeof(uint64_t) != 0 ||
	    offsets_size / sizeof(uint64_t) > MAX_BINDER_OFFSETS)
		return -ENOSPC;
	item = &target->queue[target->queue_count];
	memset(item, 0, sizeof(*item));
	item->command = command;
	item->transaction = *transaction;
	item->payload_size = payload_size;
	item->offsets_size = offsets_size;
	item->sender = sender;
	if (payload_size != 0)
		memcpy(item->payload, payload, payload_size);
	if (offsets_size != 0)
		memcpy(item->offsets, offsets, offsets_size);
	status = translate_objects(sender, target, item->payload, payload_size,
		item->offsets, offsets_size);
	if (status < 0)
		return status;
	target->queue_count++;
	return 0;
}

static void dequeue_transaction(BinderEndpoint *endpoint)
{
	if (endpoint->queue_count > 1)
		memmove(&endpoint->queue[0], &endpoint->queue[1],
			(endpoint->queue_count - 1) * sizeof(endpoint->queue[0]));
	if (endpoint->queue_count != 0)
		endpoint->queue_count--;
}

static void forget_fd(BinderConfig *c, int fd)
{
	BinderFd *f = find_fd(c, fd); if (f) memset(f, 0, sizeof(*f));
}
static void result(Tracee *t, long value) { poke_reg(t, SYSARG_RESULT, (word_t)value); }
static int queue_word(BinderFd *f, uint32_t word)
{
	if (f->read_count >= MAX_BINDER_REPLY_WORDS) return -ENOSPC;
	f->read_words[f->read_count++] = word; return 0;
}
static int deliver_transaction(Tracee *target_tracee, BinderTransaction *item,
		word_t read_buffer, size_t read_size, size_t *used)
{
	struct binder_transaction_data transaction = item->transaction;
	word_t data_address = 0;
	word_t offsets_address = 0;
	size_t total = sizeof(uint32_t) + sizeof(transaction) + item->payload_size +
		item->offsets_size;
	if (read_size < total)
		return -ENOSPC;
	if (item->payload_size != 0) {
		data_address = read_buffer + sizeof(uint32_t) + sizeof(transaction);
		transaction.data_buffer = data_address;
	}
	if (item->offsets_size != 0) {
		offsets_address = read_buffer + sizeof(uint32_t) + sizeof(transaction) +
			item->payload_size;
		transaction.offsets_buffer = offsets_address;
	}
	if (write_data(target_tracee, read_buffer, &item->command,
			sizeof(item->command)) < 0 ||
	    write_data(target_tracee, read_buffer + sizeof(item->command),
			&transaction, sizeof(transaction)) < 0 ||
	    (item->payload_size != 0 && write_data(target_tracee, data_address,
			item->payload, item->payload_size) < 0) ||
	    (item->offsets_size != 0 && write_data(target_tracee, offsets_address,
			item->offsets, item->offsets_size) < 0))
		return -EFAULT;
	*used = total;
	return 0;
}

static int binder_process_write_read(Tracee *t, BinderFd *f, word_t arg)
{
	struct binder_write_read bwr;
	struct binder_transaction_data transaction;
	BinderEndpoint *self = endpoint_for(t);
	enum BinderDomain domain = f->domain;
	uint8_t payload[MAX_BINDER_PAYLOAD];
	uint64_t offsets[MAX_BINDER_OFFSETS];
	uint32_t command;
	word_t pos;
	if (self == NULL || read_data(t, &bwr, arg, sizeof(bwr)) < 0)
		return -EFAULT;
	if (bwr.write_size > 1024 * 1024 || bwr.read_size > 1024 * 1024)
		return -EINVAL;
	pos = bwr.write_buffer;
	while (bwr.write_consumed + sizeof(command) <= bwr.write_size) {
		if (read_data(t, &command, pos, sizeof(command)) < 0)
			return -EFAULT;
		pos += sizeof(command);
		bwr.write_consumed += sizeof(command);
		switch (command) {
		case BC_TRANSACTION:
		case BC_REPLY:
			if (bwr.write_consumed + sizeof(transaction) > bwr.write_size ||
			    read_data(t, &transaction, pos, sizeof(transaction)) < 0)
				return -EINVAL;
			pos += sizeof(transaction);
			bwr.write_consumed += sizeof(transaction);
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
			transaction.sender_pid = (int32_t)t->vpid;
			transaction.sender_euid = 0;
			if (command == BC_REPLY && self->last_sender != NULL) {
				BinderEndpoint *reply_target = self->last_sender;
				if (enqueue_transaction(reply_target,
					&transaction, payload, transaction.data_size,
					offsets, transaction.offsets_size, BR_REPLY, self) < 0)
					return -ENOSPC;
			} else {
				BinderEndpoint *target = target_for(self, domain,
					(uint32_t)transaction.target);
				if (enqueue_transaction(target, &transaction, payload,
					transaction.data_size, offsets, transaction.offsets_size,
					BR_TRANSACTION, self) < 0)
					return -ENOSPC;
			}
			if (queue_word(f, BR_TRANSACTION_COMPLETE) < 0)
				return -ENOSPC;
			break;
		case BC_FREE_BUFFER:
			if (bwr.write_consumed + sizeof(binder_uintptr_t) > bwr.write_size)
				return -EINVAL;
			pos += sizeof(binder_uintptr_t);
			bwr.write_consumed += sizeof(binder_uintptr_t);
			break;
		case BC_ENTER_LOOPER:
		case BC_REGISTER_LOOPER:
		case BC_EXIT_LOOPER:
			break;
		default:
			return -EINVAL;
		}
	}
	if (self->queue_count != 0 && bwr.read_buffer != 0) {
		size_t used = 0;
		int status = deliver_transaction(t, &self->queue[0],
			bwr.read_buffer, bwr.read_size, &used);
		if (status == 0) {
			bwr.read_consumed = used;
			self->last_sender = self->queue[0].sender;
			dequeue_transaction(self);
		}
		else if (status != -ENOSPC)
			return status;
	}
	if (f->read_count != 0 && bwr.read_buffer != 0 && bwr.read_consumed == 0) {
		size_t n = f->read_count * sizeof(uint32_t);
		if (n > bwr.read_size) n = bwr.read_size;
		if (write_data(t, bwr.read_buffer, f->read_words, n) < 0)
			return -EFAULT;
		bwr.read_consumed = n;
		f->read_count = 0;
	}
	if (write_data(t, arg, &bwr, sizeof(bwr)) < 0)
		return -EFAULT;
	return 0;
}
int binder_callback(Extension *e, ExtensionEvent event, intptr_t data1, intptr_t data2)
{
	BinderConfig *c; Tracee *t = TRACEE(e); Sysnum s;
	switch (event) {
	case INITIALIZATION:
		e->config = talloc_zero(e, BinderConfig); if (!e->config) return -1;
		if (endpoint_for(t) == NULL) return -1;
		e->filtered_sysnums = filtered_sysnums; return 0;
	case INHERIT_PARENT:
		return 1;
	case INHERIT_CHILD: {
		Extension *parent = (Extension *)data1; BinderConfig *pc = talloc_get_type_abort(parent->config, BinderConfig);
		e->config = talloc_zero(e, BinderConfig); if (!e->config) return -1;
		if (endpoint_for(t) == NULL) return -1;
		memcpy(e->config, pc, sizeof(*pc)); e->filtered_sysnums = filtered_sysnums; return 0;
	}
	case GUEST_PATH:
		c = talloc_get_type_abort(e->config, BinderConfig);
		c->last_domain = binder_domain((const char *)data2);
		c->last_binder_path = c->last_domain != BINDER_DOMAIN_NONE;
		if (c->last_binder_path) { strcpy((char *)data1, "/dev/null"); return 1; }
		return 0;
	case SYSCALL_ENTER_START:
		c = talloc_get_type_abort(e->config, BinderConfig); s = get_sysnum(t, ORIGINAL);
		if (s == PR_mmap || s == PR_mmap2) {
			int fd = (int)peek_reg(t, CURRENT, SYSARG_5);
			BinderFd *f = find_fd(c, fd);
			if (f != NULL) {
				word_t flags = peek_reg(t, CURRENT, SYSARG_4);
				poke_reg(t, SYSARG_5, (word_t)-1);
				poke_reg(t, SYSARG_4, flags | MAP_ANONYMOUS);
			}
		}
		if (s == PR_ioctl) {
			int fd = (int)peek_reg(t, CURRENT, SYSARG_1); unsigned long req = (unsigned long)peek_reg(t, CURRENT, SYSARG_2);
			BinderFd *f = find_fd(c, fd);
			if (f && ((req >> 8) & 0xff) == BINDER_IOCTL_TYPE) {
				c->ioctl_pending = true; c->pending_fd = fd; c->pending_request = req; set_sysnum(t, PR_getpid);
			}
		}
		if (s == PR_close) forget_fd(c, (int)peek_reg(t, CURRENT, SYSARG_1));
		return 0;
	case SYSCALL_EXIT_END:
		c = talloc_get_type_abort(e->config, BinderConfig); s = get_sysnum(t, ORIGINAL);
		if ((s == PR_open || s == PR_openat || s == PR_openat2) && c->last_binder_path) {
			if ((long)peek_reg(t, CURRENT, SYSARG_RESULT) >= 0) remember_fd(c, (int)peek_reg(t, CURRENT, SYSARG_RESULT), c->last_domain);
			c->last_binder_path = false;
		}
		if ((s == PR_mknod || s == PR_mknodat) && c->last_binder_path) {
			if ((long)peek_reg(t, CURRENT, SYSARG_RESULT) < 0)
				result(t, 0);
			c->last_binder_path = false;
		}
		if (c->ioctl_pending && s == PR_ioctl) {
			BinderFd *f = find_fd(c, c->pending_fd); long r = 0; word_t arg = peek_reg(t, CURRENT, SYSARG_3);
			if (!f) r = -EBADF;
			else if (c->pending_request == BINDER_VERSION) { struct binder_version v = { BINDER_CURRENT_PROTOCOL_VERSION }; if (write_data(t, arg, &v, sizeof(v)) < 0) r = -EFAULT; }
			else if (c->pending_request == BINDER_SET_MAX_THREADS) { uint32_t n; if (read_data(t, &n, arg, sizeof(n)) < 0) r = -EFAULT; else f->max_threads = n; }
			else if (c->pending_request == BINDER_SET_CONTEXT_MGR ||
				 c->pending_request == BINDER_SET_CONTEXT_MGR_EXT) {
				BinderEndpoint *endpoint = endpoint_for(t);
				enum BinderDomain domain = f->domain;
				if (domain < 0 || domain >= BINDER_DOMAIN_COUNT)
					r = -ENODEV;
				else if (binder_broker.context_manager[domain] != NULL &&
				    binder_broker.context_manager[domain] != endpoint)
					r = -EBUSY;
				else {
					binder_broker.context_manager[domain] = endpoint;
					if (endpoint != NULL) endpoint->context_manager = true;
				}
			}
			else if (c->pending_request == BINDER_WRITE_READ) r = binder_process_write_read(t, f, arg);
			else if (c->pending_request == BINDER_THREAD_EXIT) { }
			else r = -ENOTTY;
			result(t, r); c->ioctl_pending = false;
		}
		return 0;
	default: return 0;
	}
}
