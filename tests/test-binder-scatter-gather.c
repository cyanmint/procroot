/*
 * SPDX-FileCopyrightText: NONE
 * SPDX-License-Identifier: GPL-2.0-or-later
 * Note: AI-generated contribution; no legal determination implied.
 */
/* Verify Binder scatter-gather transactions through the userspace broker. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <signal.h>
#include <sched.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

struct binder_transaction_data {
	uint64_t target;
	uint64_t cookie;
	uint32_t code;
	uint32_t flags;
	int32_t sender_pid;
	uint32_t sender_euid;
	uint64_t data_size;
	uint64_t offsets_size;
	uint64_t data_buffer;
	uint64_t offsets_buffer;
};

struct binder_transaction_data_sg {
	struct binder_transaction_data transaction_data;
	uint64_t buffers_size;
};

struct binder_write_read {
	uint64_t write_size;
	uint64_t write_consumed;
	uint64_t write_buffer;
	uint64_t read_size;
	uint64_t read_consumed;
	uint64_t read_buffer;
};

#define BINDER_SET_CONTEXT_MGR _IOW('b', 7, uint32_t)
#define BINDER_WRITE_READ _IOWR('b', 1, struct binder_write_read)
#define BC_TRANSACTION_SG _IOW('c', 17, struct binder_transaction_data_sg)
#define BC_REPLY_SG _IOW('c', 18, struct binder_transaction_data_sg)
#define BC_FREE_BUFFER _IOW('c', 3, uint64_t)
#define BR_TRANSACTION _IOR('r', 2, struct binder_transaction_data)
#define BR_REPLY _IOR('r', 3, struct binder_transaction_data)
#define BR_TRANSACTION_COMPLETE _IO('r', 6)
#define BC_TRANSACTION _IOW('c', 0, struct binder_transaction_data)
#define BINDER_TYPE_HANDLE 0x73682a85u
#define BINDER_TYPE_BINDER 0x73622a85u
#define BINDER_TYPE_PTR 0x70742a85u
#define BINDER_TYPE_FD 0x66642a85u
#define BINDER_TYPE_FDA 0x66646185u
#define BINDER_BUFFER_FLAG_HAS_PARENT 0x01u
#define TF_ONE_WAY 0x01u
#define TF_ACCEPT_FDS 0x10u
#define MAX_READ_SIZE 256
#define BINDER_MAPPING_SIZE (1024 * 1024)

static int consume_transaction_complete(int fd)
{
	struct binder_write_read bwr = {};
	uint32_t command = 0;

	bwr.read_size = sizeof(command);
	bwr.read_buffer = (uint64_t)(uintptr_t)&command;
	if (ioctl(fd, BINDER_WRITE_READ, &bwr) < 0) {
		perror("BINDER_WRITE_READ transaction completion");
		return -1;
	}
	if (bwr.read_consumed != sizeof(command) ||
	    command != BR_TRANSACTION_COMPLETE) {
		fprintf(stderr, "Binder transaction completion mismatch\n");
		return -1;
	}
	return 0;
}

static int transact_sg(int fd, uint32_t command, const char *payload,
		       uint32_t expected_reply)
{
	struct binder_transaction_data_sg sg = {};
	struct binder_write_read bwr = {};
	uint8_t writes[sizeof(command) + sizeof(sg)];
	uint8_t reads[MAX_READ_SIZE] = {};
	uint32_t returned_command;
	struct binder_transaction_data returned_transaction;
	const char *returned_payload;

	sg.transaction_data.target = 0;
	sg.transaction_data.code = 0x5347;
	sg.transaction_data.data_size = strlen(payload) + 1;
	sg.transaction_data.data_buffer = (uint64_t) (uintptr_t) payload;
	memcpy(writes, &command, sizeof(command));
	memcpy(writes + sizeof(command), &sg, sizeof(sg));

	bwr.write_size = sizeof(writes);
	bwr.write_buffer = (uint64_t) (uintptr_t) writes;
	bwr.read_size = sizeof(reads);
	bwr.read_buffer = (uint64_t) (uintptr_t) reads;
	if (ioctl(fd, BINDER_WRITE_READ, &bwr) < 0) {
		perror(command == BC_TRANSACTION_SG ?
		       "BINDER_WRITE_READ transaction SG" :
		       "BINDER_WRITE_READ reply SG");
		return -1;
	}
	if (bwr.write_consumed != sizeof(writes)) {
		fprintf(stderr, "SG write consumed %llu of %lu bytes\n",
			(unsigned long long) bwr.write_consumed,
			(unsigned long) sizeof(writes));
		return -1;
	}
	if (bwr.read_consumed < sizeof(returned_command) +
					 sizeof(returned_transaction)) {
		fprintf(stderr, "SG read consumed only %llu bytes\n",
			(unsigned long long) bwr.read_consumed);
		return -1;
	}
	memcpy(&returned_command, reads, sizeof(returned_command));
	memcpy(&returned_transaction, reads + sizeof(returned_command),
	       sizeof(returned_transaction));
	if (returned_command != expected_reply) {
		fprintf(stderr, "SG command returned 0x%08x, expected 0x%08x\n",
			returned_command, expected_reply);
		return -1;
	}
	if (returned_transaction.data_size != strlen(payload) + 1 ||
	    returned_transaction.data_buffer == 0) {
		fprintf(stderr, "SG transaction payload metadata mismatch\n");
		return -1;
	}
	returned_payload = (const char *) reads + sizeof(returned_command) +
		sizeof(returned_transaction);
	if (strcmp(returned_payload, payload) != 0) {
		fprintf(stderr, "SG payload mismatch: '%s'\n", returned_payload);
		return -1;
	}
	if (consume_transaction_complete(fd) < 0)
		return -1;
	return 0;
}

struct binder_buffer_object {
	uint32_t type;
	uint32_t flags;
	uint64_t buffer;
	uint64_t length;
	uint64_t parent;
	uint64_t parent_offset;
};

struct binder_fd_array_object {
	uint32_t type;
	uint32_t pad;
	uint64_t num_fds;
	uint64_t parent;
	uint64_t parent_offset;
};

static size_t align_to_8(size_t value)
{
	return (value + 7) & ~(size_t)7;
}

static int transact_sg_buffer(int fd, uint32_t command,
			      uint32_t expected_reply)
{
	enum { object_offset = 44 };
	const char extra[] = "scatter-buffer-payload";
	struct binder_buffer_object object = {};
	struct binder_transaction_data_sg sg = {};
	struct binder_write_read bwr = {};
	uint64_t offsets = object_offset;
	uint8_t writes[sizeof(uint32_t) + sizeof(sg)];
	uint8_t payload[object_offset + sizeof(object)] = {};
	uint8_t reads[MAX_READ_SIZE] = {};
	uint32_t returned_command;
	uint64_t returned_offset;
	struct binder_transaction_data returned_transaction;
	struct binder_buffer_object returned_object;
	size_t data_offset = sizeof(uint32_t) + sizeof(returned_transaction);
	size_t offsets_offset = data_offset + align_to_8(sizeof(payload));
	size_t extra_offset = offsets_offset + align_to_8(sizeof(offsets));

	object.type = BINDER_TYPE_PTR;
	object.buffer = (uint64_t) (uintptr_t) extra;
	object.length = sizeof(extra);
	memcpy(payload + object_offset, &object, sizeof(object));
	sg.transaction_data.target = 0;
	sg.transaction_data.code = 0x5347;
	sg.transaction_data.data_size = sizeof(payload);
	sg.transaction_data.offsets_size = sizeof(offsets);
	sg.transaction_data.data_buffer = (uint64_t) (uintptr_t) payload;
	sg.transaction_data.offsets_buffer = (uint64_t) (uintptr_t) &offsets;
	sg.buffers_size = align_to_8(sizeof(extra));
	memcpy(writes, &command, sizeof(command));
	memcpy(writes + sizeof(command), &sg, sizeof(sg));

	bwr.write_size = sizeof(writes);
	bwr.write_buffer = (uint64_t) (uintptr_t) writes;
	bwr.read_size = sizeof(reads);
	bwr.read_buffer = (uint64_t) (uintptr_t) reads;
	if (ioctl(fd, BINDER_WRITE_READ, &bwr) < 0) {
		perror(command == BC_TRANSACTION_SG ?
		       "BINDER_WRITE_READ SG buffer transaction" :
		       "BINDER_WRITE_READ SG buffer reply");
		return -1;
	}
	if (bwr.read_consumed < extra_offset + sg.buffers_size) {
		fprintf(stderr, "SG buffers read consumed only %llu bytes\n",
			(unsigned long long) bwr.read_consumed);
		return -1;
	}
	memcpy(&returned_command, reads, sizeof(returned_command));
	memcpy(&returned_transaction, reads + sizeof(returned_command),
	       sizeof(returned_transaction));
	memcpy(&returned_offset, reads + offsets_offset,
	       sizeof(returned_offset));
	if (returned_command != expected_reply ||
	    returned_transaction.data_size != sizeof(payload) ||
	    returned_transaction.offsets_size != sizeof(offsets) ||
	    returned_transaction.data_buffer !=
		(uint64_t) (uintptr_t) (reads + data_offset) ||
	    returned_transaction.offsets_buffer !=
		(uint64_t) (uintptr_t) (reads + offsets_offset)) {
		fprintf(stderr, "SG buffer transaction metadata mismatch\n");
		return -1;
	}
	memcpy(&returned_object, reads + data_offset + object_offset,
	       sizeof(returned_object));
	if (returned_object.type != BINDER_TYPE_PTR ||
	    returned_object.buffer !=
		(uint64_t) (uintptr_t) (reads + extra_offset) ||
	    returned_object.length != sizeof(extra) ||
	    returned_offset != object_offset ||
	    memcmp(reads + extra_offset, extra, sizeof(extra)) != 0) {
		fprintf(stderr, "SG out-of-line buffer was not copied and relocated\n");
		return -1;
	}
	if (consume_transaction_complete(fd) < 0)
		return -1;
	return 0;
}

static int transact_sg_parent_buffer(int fd, uint32_t command,
				     uint32_t expected_reply)
{
	enum { parent_object_offset = 4, child_object_offset = 44 };
	const char parent_tail[] = "parent";
	const char child_data[] = "child-buffer-payload";
	struct binder_buffer_object parent = {};
	struct binder_buffer_object child = {};
	struct binder_transaction_data_sg sg = {};
	struct binder_write_read bwr = {};
	uint64_t offsets[2] = { parent_object_offset, child_object_offset };
	uint8_t parent_data[16] = {};
	uint8_t payload[child_object_offset + sizeof(child)] = {};
	uint8_t writes[sizeof(uint32_t) + sizeof(sg)];
	uint8_t reads[MAX_READ_SIZE] = {};
	uint32_t returned_command;
	uint64_t returned_offsets[2];
	uint64_t parent_child_pointer;
	struct binder_transaction_data returned_transaction;
	struct binder_buffer_object returned_parent;
	struct binder_buffer_object returned_child;
	size_t data_offset = sizeof(uint32_t) + sizeof(returned_transaction);
	size_t payload_space = align_to_8(sizeof(payload));
	size_t offsets_offset = data_offset + payload_space;
	size_t extra_offset = offsets_offset + align_to_8(sizeof(offsets));
	size_t parent_space = align_to_8(sizeof(parent_data));

	memcpy(parent_data + sizeof(uint64_t), parent_tail, sizeof(parent_tail));
	parent.type = BINDER_TYPE_PTR;
	parent.buffer = (uint64_t) (uintptr_t) parent_data;
	parent.length = sizeof(parent_data);
	child.type = BINDER_TYPE_PTR;
	child.flags = BINDER_BUFFER_FLAG_HAS_PARENT;
	child.buffer = (uint64_t) (uintptr_t) child_data;
	child.length = sizeof(child_data);
	child.parent = 0;
	child.parent_offset = 0;
	memcpy(payload + parent_object_offset, &parent, sizeof(parent));
	memcpy(payload + child_object_offset, &child, sizeof(child));
	sg.transaction_data.target = 0;
	sg.transaction_data.code = 0x5347;
	sg.transaction_data.data_size = sizeof(payload);
	sg.transaction_data.offsets_size = sizeof(offsets);
	sg.transaction_data.data_buffer = (uint64_t) (uintptr_t) payload;
	sg.transaction_data.offsets_buffer = (uint64_t) (uintptr_t) offsets;
	sg.buffers_size = parent_space + align_to_8(sizeof(child_data));
	memcpy(writes, &command, sizeof(command));
	memcpy(writes + sizeof(command), &sg, sizeof(sg));

	bwr.write_size = sizeof(writes);
	bwr.write_buffer = (uint64_t) (uintptr_t) writes;
	bwr.read_size = sizeof(reads);
	bwr.read_buffer = (uint64_t) (uintptr_t) reads;
	if (ioctl(fd, BINDER_WRITE_READ, &bwr) < 0) {
		perror(command == BC_TRANSACTION_SG ?
		       "BINDER_WRITE_READ SG parent transaction" :
		       "BINDER_WRITE_READ SG parent reply");
		return -1;
	}
	if (bwr.read_consumed < extra_offset + sg.buffers_size) {
		fprintf(stderr, "SG parent buffers read consumed only %llu bytes\n",
			(unsigned long long) bwr.read_consumed);
		return -1;
	}
	memcpy(&returned_command, reads, sizeof(returned_command));
	memcpy(&returned_transaction, reads + sizeof(returned_command),
	       sizeof(returned_transaction));
	memcpy(&returned_offsets, reads + offsets_offset,
	       sizeof(returned_offsets));
	memcpy(&returned_parent, reads + data_offset + parent_object_offset,
	       sizeof(returned_parent));
	memcpy(&returned_child, reads + data_offset + child_object_offset,
	       sizeof(returned_child));
	memcpy(&parent_child_pointer, reads + extra_offset,
	       sizeof(parent_child_pointer));
	if (returned_command != expected_reply ||
	    returned_transaction.data_size != sizeof(payload) ||
	    returned_transaction.offsets_size != sizeof(offsets) ||
	    returned_transaction.data_buffer !=
		(uint64_t) (uintptr_t) (reads + data_offset) ||
	    returned_transaction.offsets_buffer !=
		(uint64_t) (uintptr_t) (reads + offsets_offset) ||
	    returned_offsets[0] != parent_object_offset ||
	    returned_offsets[1] != child_object_offset ||
	    returned_parent.type != BINDER_TYPE_PTR ||
	    returned_parent.buffer != (uint64_t) (uintptr_t) (reads + extra_offset) ||
	    returned_parent.length != sizeof(parent_data) ||
	    returned_child.type != BINDER_TYPE_PTR ||
	    returned_child.flags != BINDER_BUFFER_FLAG_HAS_PARENT ||
	    returned_child.parent != 0 || returned_child.parent_offset != 0 ||
	    returned_child.buffer != (uint64_t) (uintptr_t)
		(reads + extra_offset + parent_space) ||
	    returned_child.length != sizeof(child_data) ||
	    parent_child_pointer != (uint64_t) (uintptr_t)
		(reads + extra_offset + parent_space) ||
	    memcmp(reads + extra_offset + sizeof(uint64_t), parent_tail,
		   sizeof(parent_tail)) != 0 ||
	    memcmp(reads + extra_offset + parent_space, child_data,
		   sizeof(child_data)) != 0) {
		fprintf(stderr, "SG parent buffer fixup mismatch\n");
		return -1;
	}
	if (consume_transaction_complete(fd) < 0)
		return -1;
	return 0;
}

struct flat_binder_handle_object {
	uint32_t type;
	uint32_t flags;
	uint64_t handle;
	uint64_t cookie;
};

#define SHARED_FILES_STACK_SIZE (64 * 1024)

static int keep_shared_files_child(void *unused)
{
	(void)unused;
	for (;;)
		pause();
	return 0;
}

static pid_t start_shared_files_child(void **stack)
{
	pid_t child;

	*stack = mmap(NULL, SHARED_FILES_STACK_SIZE, PROT_READ | PROT_WRITE,
		MAP_PRIVATE | MAP_ANONYMOUS | MAP_STACK, -1, 0);
	if (*stack == MAP_FAILED)
		return -1;
	child = clone(keep_shared_files_child,
		(uint8_t *)*stack + SHARED_FILES_STACK_SIZE,
		CLONE_FILES | SIGCHLD, NULL);
	if (child < 0) {
		munmap(*stack, SHARED_FILES_STACK_SIZE);
		*stack = MAP_FAILED;
	}
	return child;
}

static void stop_shared_files_child(pid_t child, void *stack)
{
	if (child > 0) {
		(void)kill(child, SIGKILL);
		(void)waitpid(child, NULL, 0);
	}
	if (stack != MAP_FAILED)
		(void)munmap(stack, SHARED_FILES_STACK_SIZE);
}

static int count_open_fds(void)
{
	int count = 0;
	int fd;

	for (fd = 0; fd < 256; fd++)
		if (fcntl(fd, F_GETFD) >= 0 || errno != EBADF)
			count++;
	return count;
}

static int transact_sg_fd_array(int fd, int accept_fds, int malformed,
				int nested_parent, int external_files_sibling,
				int read_size_mode)
{
	enum {
		parent_object_offset = 4,
		child_object_offset = 44,
		grandchild_object_offset = 84,
		simple_fda_object_offset = 44,
		nested_fda_object_offset = 124,
		nested_fd_slot_offset = 44,
	};
	int pipe_fds[2];
	int received_fd;
	int32_t fd_slot;
	char value = 'f';
	char received_value = 0;
	struct binder_buffer_object parents[3] = {};
	struct binder_fd_array_object fda = {};
	struct binder_transaction_data_sg request_sg = {};
	struct binder_transaction_data_sg reply_sg = {};
	struct binder_write_read bwr = {};
	uint32_t command;
	uint32_t returned_command;
	uint64_t offsets[4] = {};
	uint8_t request_writes[sizeof(command) + sizeof(request_sg)];
	uint8_t reply_writes[sizeof(command) + sizeof(reply_sg)];
	uint8_t payload[nested_fda_object_offset + sizeof(fda)] = {};
	uint8_t reads[MAX_READ_SIZE * 4] __attribute__((aligned(16))) = {};
	uint8_t root_buffer[16] = {};
	uint8_t child_buffer[16] = {};
	uint8_t grandchild_buffer[48] = {};
	struct binder_transaction_data returned_transaction;
	size_t payload_size;
	size_t offsets_count;
	size_t buffers_size;
	size_t fd_slot_offset;
	size_t data_offset = sizeof(returned_command) + sizeof(returned_transaction);
	size_t offsets_offset;
	size_t extra_offset;
	pid_t shared_child = -1;
	void *shared_stack = MAP_FAILED;
	int fds_before_reply;

	if (pipe(pipe_fds) < 0) {
		perror("pipe Binder fd array");
		return -1;
	}
	fd_slot = pipe_fds[1];
	if (nested_parent) {
		parents[0].type = BINDER_TYPE_PTR;
		parents[0].buffer = (uint64_t)(uintptr_t)root_buffer;
		parents[0].length = sizeof(root_buffer);
		parents[1].type = BINDER_TYPE_PTR;
		parents[1].flags = BINDER_BUFFER_FLAG_HAS_PARENT;
		parents[1].buffer = (uint64_t)(uintptr_t)child_buffer;
		parents[1].length = sizeof(child_buffer);
		parents[1].parent = 0;
		parents[1].parent_offset = 0;
		parents[2].type = BINDER_TYPE_PTR;
		parents[2].flags = BINDER_BUFFER_FLAG_HAS_PARENT;
		parents[2].buffer = (uint64_t)(uintptr_t)grandchild_buffer;
		parents[2].length = sizeof(grandchild_buffer);
		parents[2].parent = 1;
		parents[2].parent_offset = 0;
		memcpy(grandchild_buffer + 12, &fd_slot, sizeof(fd_slot));
		memcpy(payload + parent_object_offset, &parents[0], sizeof(parents[0]));
		memcpy(payload + child_object_offset, &parents[1], sizeof(parents[1]));
		memcpy(payload + grandchild_object_offset, &parents[2], sizeof(parents[2]));
		offsets[0] = parent_object_offset;
		offsets[1] = child_object_offset;
		offsets[2] = grandchild_object_offset;
		offsets[3] = nested_fda_object_offset;
		payload_size = nested_fda_object_offset + sizeof(fda);
		offsets_count = 4;
		buffers_size = sizeof(root_buffer) + sizeof(child_buffer) +
			sizeof(grandchild_buffer);
		fd_slot_offset = nested_fd_slot_offset;
	}
	else {
		parents[0].type = BINDER_TYPE_PTR;
		parents[0].buffer = (uint64_t)(uintptr_t)&fd_slot;
		parents[0].length = sizeof(fd_slot);
		memcpy(payload + parent_object_offset, &parents[0], sizeof(parents[0]));
		offsets[0] = parent_object_offset;
		offsets[1] = simple_fda_object_offset;
		payload_size = simple_fda_object_offset + sizeof(fda);
		offsets_count = 2;
		buffers_size = align_to_8(sizeof(fd_slot));
		fd_slot_offset = 0;
	}
	fda.type = BINDER_TYPE_FDA;
	fda.num_fds = malformed == 1 ? 2 : 1;
	fda.parent = nested_parent ? 2 : 0;
	fda.parent_offset = malformed == 2 ? sizeof(fd_slot) :
		(nested_parent ? 12 : 0);
	memcpy(payload + (nested_parent ? nested_fda_object_offset :
		simple_fda_object_offset), &fda, sizeof(fda));
	offsets_offset = data_offset + align_to_8(payload_size);
	extra_offset = offsets_offset + align_to_8(offsets_count * sizeof(offsets[0]));

	/* Reply-side FD acceptance comes from this original request. */
	command = BC_TRANSACTION_SG;
	request_sg.transaction_data.target = 0;
	request_sg.transaction_data.flags = accept_fds ? TF_ACCEPT_FDS : 0;
	memcpy(request_writes, &command, sizeof(command));
	memcpy(request_writes + sizeof(command), &request_sg,
	       sizeof(request_sg));
	bwr = (struct binder_write_read) {
		.write_size = sizeof(request_writes),
		.write_buffer = (uint64_t)(uintptr_t)request_writes,
		.read_size = sizeof(reads),
		.read_buffer = (uint64_t)(uintptr_t)reads,
	};
	if (ioctl(fd, BINDER_WRITE_READ, &bwr) < 0 ||
	    bwr.read_consumed < sizeof(returned_command) +
					 sizeof(returned_transaction)) {
		perror("BINDER_WRITE_READ FDA request");
		close(pipe_fds[0]);
		close(pipe_fds[1]);
		return -1;
	}
	memcpy(&returned_command, reads, sizeof(returned_command));
	if (returned_command != BR_TRANSACTION) {
		fprintf(stderr, "FDA request returned command 0x%08x\n",
			returned_command);
		close(pipe_fds[0]);
		close(pipe_fds[1]);
		return -1;
	}
	if (consume_transaction_complete(fd) < 0) {
		close(pipe_fds[0]);
		close(pipe_fds[1]);
		return -1;
	}
	if (external_files_sibling) {
		shared_child = start_shared_files_child(&shared_stack);
		if (shared_child < 0) {
			perror("clone CLONE_FILES sibling");
			close(pipe_fds[0]);
			close(pipe_fds[1]);
			return -1;
		}
	}

	command = BC_REPLY_SG;
	reply_sg.transaction_data.target = UINT64_MAX;
	reply_sg.transaction_data.data_size = payload_size;
	reply_sg.transaction_data.offsets_size = offsets_count * sizeof(offsets[0]);
	reply_sg.transaction_data.data_buffer = (uint64_t)(uintptr_t)payload;
	reply_sg.transaction_data.offsets_buffer = (uint64_t)(uintptr_t)offsets;
	reply_sg.buffers_size = buffers_size;
	memcpy(reply_writes, &command, sizeof(command));
	memcpy(reply_writes + sizeof(command), &reply_sg, sizeof(reply_sg));
	memset(reads, 0, sizeof(reads));
	fds_before_reply = count_open_fds();
	bwr = (struct binder_write_read) {
		.write_size = sizeof(reply_writes),
		.write_buffer = (uint64_t)(uintptr_t)reply_writes,
		.read_size = read_size_mode == 1 ? 400 :
			(read_size_mode == 2 ? 256 : sizeof(reads)),
		.read_buffer = (uint64_t)(uintptr_t)reads,
	};
	if (ioctl(fd, BINDER_WRITE_READ, &bwr) < 0) {
		int reply_errno = errno;
		if (read_size_mode == 1 && reply_errno == ENOSPC) {
			int fds_after_reply = count_open_fds();

			close(pipe_fds[0]);
			close(pipe_fds[1]);
			if (fds_after_reply != fds_before_reply) {
				fprintf(stderr,
					"short-scratch FDA failure leaked a descriptor\n");
				return -1;
			}
			puts("BINDER_FDA_REJECT_SHORT_SCRATCH=PASS");
			return 0;
		}
		if (read_size_mode == 2) {
			close(pipe_fds[0]);
			close(pipe_fds[1]);
			fprintf(stderr, "256-byte FDA read buffer failed: errno=%d\n",
				reply_errno);
			return -1;
		}
		if (external_files_sibling && reply_errno == EOPNOTSUPP) {
			stop_shared_files_child(shared_child, shared_stack);
			close(pipe_fds[0]);
			close(pipe_fds[1]);
			puts("BINDER_FDA_REJECT_SHARED_FILES=PASS");
			return 0;
		}
		if (malformed != 0 && errno == EINVAL) {
			close(pipe_fds[0]);
			close(pipe_fds[1]);
			printf("BINDER_FD_ARRAY_REJECT_MALFORMED_%d=PASS\n",
				malformed);
			return 0;
		}
		if (!accept_fds && errno == EPERM) {
			close(pipe_fds[0]);
			close(pipe_fds[1]);
			puts("BINDER_FD_ARRAY_REJECT_NO_ACCEPT=PASS");
			return 0;
		}
		if (external_files_sibling) {
			stop_shared_files_child(shared_child, shared_stack);
			close(pipe_fds[0]);
			close(pipe_fds[1]);
			fprintf(stderr, "FDA shared-files reply failed with errno %d\n",
				reply_errno);
			return -1;
		}
		perror("BINDER_WRITE_READ FDA reply");
		close(pipe_fds[0]);
		close(pipe_fds[1]);
		return -1;
	}
	if (external_files_sibling) {
		fprintf(stderr,
			"FDA reply succeeded with an external CLONE_FILES sibling\n");
		stop_shared_files_child(shared_child, shared_stack);
		close(pipe_fds[0]);
		close(pipe_fds[1]);
		return -1;
	}
	if (read_size_mode == 1) {
		fprintf(stderr, "short-scratch FDA reply unexpectedly succeeded\n");
		close(pipe_fds[0]);
		close(pipe_fds[1]);
		return -1;
	}
	if (!accept_fds) {
		fprintf(stderr, "FDA reply was accepted without TF_ACCEPT_FDS\n");
		close(pipe_fds[0]);
		close(pipe_fds[1]);
		return -1;
	}
	if (bwr.read_consumed < extra_offset + reply_sg.buffers_size) {
		fprintf(stderr, "FDA reply read consumed only %llu bytes\n",
			(unsigned long long)bwr.read_consumed);
		close(pipe_fds[0]);
		close(pipe_fds[1]);
		return -1;
	}
	memcpy(&returned_command, reads, sizeof(returned_command));
	memcpy(&returned_transaction, reads + sizeof(returned_command),
	       sizeof(returned_transaction));
	memcpy(&received_fd, reads + extra_offset + fd_slot_offset,
	       sizeof(received_fd));
	if (returned_command != BR_REPLY ||
	    returned_transaction.data_size != payload_size ||
	    received_fd < 0 || received_fd == pipe_fds[1] ||
	    fcntl(received_fd, F_GETFD) < 0 ||
	    write(received_fd, &value, sizeof(value)) != sizeof(value) ||
	    read(pipe_fds[0], &received_value, sizeof(received_value)) !=
					 sizeof(received_value) ||
	    received_value != value) {
		fprintf(stderr, "FDA reply did not install the source descriptor\n");
		close(pipe_fds[0]);
		close(pipe_fds[1]);
		return -1;
	}
	close(received_fd);
	close(pipe_fds[0]);
	close(pipe_fds[1]);
	if (read_size_mode == 2)
		puts("BINDER_FDA_SMALL_READ_BUFFER=PASS");
	else
		puts(nested_parent ? "BINDER_FD_ARRAY_NESTED_PARENT=PASS" :
			"BINDER_FD_ARRAY=PASS");
	return 0;
}

static int transact_context_handle_zero(int fd)
{
	enum { object_offset = 4 };
	struct flat_binder_handle_object object = {};
	struct binder_transaction_data transaction = {};
	struct binder_write_read bwr = {};
	uint32_t command = BC_TRANSACTION;
	uint32_t returned_command;
	uint64_t offsets = object_offset;
	uint64_t returned_offset;
	uint8_t writes[sizeof(command) + sizeof(transaction)];
	uint8_t payload[object_offset + sizeof(object)] = {};
	uint8_t reads[MAX_READ_SIZE] = {};
	struct binder_transaction_data returned_transaction;
	struct flat_binder_handle_object returned_object;
	size_t data_offset = sizeof(returned_command) +
		sizeof(returned_transaction);
	size_t offsets_offset = data_offset + sizeof(payload);

	object.type = BINDER_TYPE_HANDLE;
	memcpy(payload + object_offset, &object, sizeof(object));
	transaction.target = 0;
	transaction.data_size = sizeof(payload);
	transaction.offsets_size = sizeof(offsets);
	transaction.data_buffer = (uint64_t) (uintptr_t) payload;
	transaction.offsets_buffer = (uint64_t) (uintptr_t) &offsets;
	memcpy(writes, &command, sizeof(command));
	memcpy(writes + sizeof(command), &transaction, sizeof(transaction));

	bwr.write_size = sizeof(writes);
	bwr.write_buffer = (uint64_t) (uintptr_t) writes;
	bwr.read_size = sizeof(reads);
	bwr.read_buffer = (uint64_t) (uintptr_t) reads;
	if (ioctl(fd, BINDER_WRITE_READ, &bwr) < 0) {
		perror("BINDER_WRITE_READ context handle 0");
		return -1;
	}
	if (bwr.read_consumed < offsets_offset + sizeof(offsets)) {
		fprintf(stderr, "context handle read consumed only %llu bytes\n",
			(unsigned long long) bwr.read_consumed);
		return -1;
	}
	memcpy(&returned_command, reads, sizeof(returned_command));
	memcpy(&returned_transaction, reads + sizeof(returned_command),
	       sizeof(returned_transaction));
	memcpy(&returned_offset, reads + offsets_offset,
	       sizeof(returned_offset));
	memcpy(&returned_object, reads + data_offset + object_offset,
	       sizeof(returned_object));
	if (returned_command != BR_TRANSACTION ||
	    returned_transaction.data_size != sizeof(payload) ||
	    returned_transaction.offsets_size != sizeof(offsets) ||
	    returned_transaction.data_buffer !=
		(uint64_t) (uintptr_t) (reads + data_offset) ||
	    returned_transaction.offsets_buffer !=
		(uint64_t) (uintptr_t) (reads + offsets_offset) ||
	    returned_offset != object_offset ||
	    returned_object.type != BINDER_TYPE_BINDER ||
	    returned_object.handle != 0 || returned_object.cookie != 0) {
		fprintf(stderr,
			"context handle zero was not translated to the manager-local binder object: type=%#x binder=%#llx cookie=%#llx\n",
			returned_object.type,
			(unsigned long long) returned_object.handle,
			(unsigned long long) returned_object.cookie);
		return -1;
	}
	puts("BINDER_CONTEXT_HANDLE_ZERO=PASS");
	return 0;
}

static int transact_fd_object(int fd)
{
	enum { object_offset = 188, payload_size = 249 };
	int pipe_fds[2];
	int received_fd = -1;
	char value = 'd';
	char received_value = 0;
	struct flat_binder_handle_object object = {
		.type = BINDER_TYPE_FD,
	};
	struct binder_transaction_data transaction = {};
	struct binder_write_read bwr = {};
	struct binder_write_read completion_bwr = {};
	uint32_t command = BC_TRANSACTION;
	uint32_t returned_command = 0;
	uint32_t free_command = BC_FREE_BUFFER;
	uint32_t completion = 0;
	uint64_t offsets = object_offset;
	uint64_t returned_offset = 0;
	uint64_t free_buffer = 0;
	uint8_t writes[sizeof(command) + sizeof(transaction)];
	uint8_t completion_writes[sizeof(free_command) + sizeof(free_buffer)];
	uint8_t payload[payload_size] = {};
	uint8_t returned_payload[payload_size] = {};
	uint8_t reads[MAX_READ_SIZE] __attribute__((aligned(16))) = {};
	struct binder_transaction_data returned_transaction;
	struct flat_binder_handle_object returned_object;
	size_t transaction_header_size = sizeof(returned_command) +
		sizeof(returned_transaction);
	size_t read_offset;
	int completion_received = 0;

	if (pipe(pipe_fds) < 0) {
		perror("pipe Binder fd object");
		return -1;
	}
	if (fcntl(pipe_fds[0], F_SETFL, O_NONBLOCK) < 0) {
		perror("fcntl Binder fd object pipe");
		close(pipe_fds[0]);
		close(pipe_fds[1]);
		return -1;
	}
	object.handle = (uint64_t)pipe_fds[1];
	memcpy(payload + object_offset, &object, sizeof(object));
	transaction.target = 0;
	transaction.code = 0x4644;
	transaction.flags = TF_ONE_WAY;
	transaction.data_size = sizeof(payload);
	transaction.offsets_size = sizeof(offsets);
	transaction.data_buffer = (uint64_t)(uintptr_t)payload;
	transaction.offsets_buffer = (uint64_t)(uintptr_t)&offsets;
	memcpy(writes, &command, sizeof(command));
	memcpy(writes + sizeof(command), &transaction, sizeof(transaction));
	bwr = (struct binder_write_read) {
		.write_size = sizeof(writes),
		.write_buffer = (uint64_t)(uintptr_t)writes,
		.read_size = sizeof(reads),
		.read_buffer = (uint64_t)(uintptr_t)reads,
	};
	if (ioctl(fd, BINDER_WRITE_READ, &bwr) < 0) {
		perror("BINDER_WRITE_READ direct FD object");
		close(pipe_fds[0]);
		close(pipe_fds[1]);
		return -1;
	}
	if (bwr.write_consumed != sizeof(writes) ||
	    bwr.read_consumed < transaction_header_size) {
		fprintf(stderr,
			"direct FD object transfer consumed unexpected sizes: write=%llu read=%llu\n",
			(unsigned long long)bwr.write_consumed,
			(unsigned long long)bwr.read_consumed);
		goto fail;
	}
	memcpy(&returned_command, reads, sizeof(returned_command));
	memcpy(&returned_transaction, reads + sizeof(returned_command),
	       sizeof(returned_transaction));
	if (returned_command != BR_TRANSACTION ||
	    returned_transaction.data_size != sizeof(payload) ||
	    returned_transaction.offsets_size != sizeof(offsets) ||
	    returned_transaction.data_buffer == 0 ||
	    returned_transaction.offsets_buffer == 0) {
		fprintf(stderr, "BINDER_FD_OBJECT=FAIL invalid transaction header\n");
		goto fail;
	}
	if ((returned_transaction.offsets_buffer & (sizeof(uint64_t) - 1)) != 0) {
		fprintf(stderr,
			"BINDER_FD_OBJECT=FAIL offsets buffer is not 8-byte aligned: %p\n",
			(void *)(uintptr_t)returned_transaction.offsets_buffer);
		goto fail;
	}
	memcpy(returned_payload,
	       (const void *)(uintptr_t)returned_transaction.data_buffer,
	       sizeof(returned_payload));
	memcpy(&returned_offset,
	       (const void *)(uintptr_t)returned_transaction.offsets_buffer,
	       sizeof(returned_offset));
	memcpy(&returned_object, returned_payload + object_offset,
	       sizeof(returned_object));
	received_fd = (int)returned_object.handle;
	read_offset = transaction_header_size;
	while (read_offset + sizeof(completion) <= bwr.read_consumed) {
		memcpy(&completion, reads + read_offset, sizeof(completion));
		if (completion != BR_TRANSACTION_COMPLETE) {
			fprintf(stderr,
				"BINDER_FD_OBJECT=FAIL unexpected trailing command %#x\n",
				completion);
			goto fail;
		}
		completion_received = 1;
		read_offset += sizeof(completion);
	}
	if (read_offset != bwr.read_consumed ||
	    returned_offset != object_offset ||
	    returned_object.type != BINDER_TYPE_FD ||
	    received_fd < 0 || received_fd == pipe_fds[1] ||
	    fcntl(received_fd, F_GETFD) < 0 ||
	    write(received_fd, &value, sizeof(value)) != sizeof(value) ||
	    read(pipe_fds[0], &received_value, sizeof(received_value)) !=
					 sizeof(received_value) ||
	    received_value != value) {
		fprintf(stderr, "BINDER_FD_OBJECT=FAIL descriptor was not transferred\n");
		goto fail;
	}
	free_buffer = returned_transaction.data_buffer;
	memcpy(completion_writes, &free_command, sizeof(free_command));
	memcpy(completion_writes + sizeof(free_command), &free_buffer,
	       sizeof(free_buffer));
	completion_bwr = (struct binder_write_read) {
		.write_size = sizeof(completion_writes),
		.write_buffer = (uint64_t)(uintptr_t)completion_writes,
	};
	if (ioctl(fd, BINDER_WRITE_READ, &completion_bwr) < 0) {
		perror("BINDER_WRITE_READ direct FD buffer free");
		goto fail;
	}
	if (completion_bwr.write_consumed != sizeof(completion_writes)) {
		fprintf(stderr, "BINDER_FD_OBJECT=FAIL buffer free not consumed\n");
		goto fail;
	}
	if (!completion_received && consume_transaction_complete(fd) < 0) {
		fprintf(stderr, "BINDER_FD_OBJECT=FAIL transaction completion missing\n");
		goto fail;
	}
	close(received_fd);
	close(pipe_fds[0]);
	close(pipe_fds[1]);
	puts("BINDER_FD_OBJECT=PASS");
	return 0;

fail:
	if (received_fd >= 0 && received_fd != pipe_fds[0] &&
	    received_fd != pipe_fds[1])
		close(received_fd);
	close(pipe_fds[0]);
	close(pipe_fds[1]);
	return -1;
}

static int64_t elapsed_ns(struct timespec start, struct timespec end)
{
	return (int64_t)(end.tv_sec - start.tv_sec) * 1000000000 +
		(end.tv_nsec - start.tv_nsec);
}

static int test_read_wait(int fd)
{
	int release_pipe[2];
	pid_t child;
	struct timespec start;
	struct timespec now;
	struct timespec delay = { .tv_sec = 0, .tv_nsec = 100000000 };
	struct binder_transaction_data transaction = {};
	uint32_t command = BC_TRANSACTION;
	uint8_t writes[sizeof(command) + sizeof(transaction)];
	uint8_t reads[MAX_READ_SIZE] = {};
	struct binder_write_read bwr;
	uint32_t returned_command;
	int empty_calls = 0;
	char token = 'x';
	int status;

	if (pipe(release_pipe) < 0) {
		perror("pipe Binder read wait");
		return -1;
	}
	child = fork();
	if (child < 0) {
		perror("fork Binder read wait");
		close(release_pipe[0]);
		close(release_pipe[1]);
		return -1;
	}
	if (child == 0) {
		close(release_pipe[1]);
		while (nanosleep(&delay, &delay) < 0 && errno == EINTR) {}
		transaction.target = 0;
		memcpy(writes, &command, sizeof(command));
		memcpy(writes + sizeof(command), &transaction,
		       sizeof(transaction));
		bwr = (struct binder_write_read) {
			.write_size = sizeof(writes),
			.write_buffer = (uint64_t)(uintptr_t)writes,
		};
		if (ioctl(fd, BINDER_WRITE_READ, &bwr) < 0)
			_exit(2);
		if (read(release_pipe[0], &token, 1) != 1)
			_exit(3);
		_exit(0);
	}
	close(release_pipe[0]);
	if (clock_gettime(CLOCK_MONOTONIC, &start) < 0) {
		perror("clock_gettime Binder read wait");
		kill(child, SIGKILL);
		waitpid(child, NULL, 0);
		close(release_pipe[1]);
		return -1;
	}
	for (;;) {
		memset(reads, 0, sizeof(reads));
		bwr = (struct binder_write_read) {
			.read_size = sizeof(reads),
			.read_buffer = (uint64_t)(uintptr_t)reads,
		};
		if (ioctl(fd, BINDER_WRITE_READ, &bwr) < 0) {
			perror("BINDER_WRITE_READ idle read");
			kill(child, SIGKILL);
			waitpid(child, NULL, 0);
			close(release_pipe[1]);
			return -1;
		}
		if (clock_gettime(CLOCK_MONOTONIC, &now) < 0) {
			perror("clock_gettime Binder read wait");
			kill(child, SIGKILL);
			waitpid(child, NULL, 0);
			close(release_pipe[1]);
			return -1;
		}
		if (bwr.read_consumed != 0)
			break;
		if (empty_calls == 0 && elapsed_ns(start, now) < 5000000) {
			fprintf(stderr,
				"idle Binder read returned in under 5 ms without work\n");
			kill(child, SIGKILL);
			waitpid(child, NULL, 0);
			close(release_pipe[1]);
			return -1;
		}
		if (elapsed_ns(start, now) > 2000000000) {
			fprintf(stderr, "Binder read did not receive queued work\n");
			kill(child, SIGKILL);
			waitpid(child, NULL, 0);
			close(release_pipe[1]);
			return -1;
		}
		empty_calls++;
	}
	if (bwr.read_consumed < sizeof(returned_command) +
					 sizeof(transaction)) {
		fprintf(stderr, "Binder read returned a truncated transaction\n");
		kill(child, SIGKILL);
		waitpid(child, NULL, 0);
		close(release_pipe[1]);
		return -1;
	}
	memcpy(&returned_command, reads, sizeof(returned_command));
	if (returned_command != BR_TRANSACTION) {
		fprintf(stderr, "Binder read returned command 0x%08x\n",
			returned_command);
		kill(child, SIGKILL);
		waitpid(child, NULL, 0);
		close(release_pipe[1]);
		return -1;
	}
	if (write(release_pipe[1], &token, 1) != 1 ||
	    waitpid(child, &status, 0) < 0 ||
	    !WIFEXITED(status) || WEXITSTATUS(status) != 0) {
		fprintf(stderr, "Binder read sender did not exit cleanly\n");
		close(release_pipe[1]);
		return -1;
	}
	close(release_pipe[1]);
	puts("BINDER_READ_WAIT=PASS");
	return 0;
}

int main(int argc, char **argv)
{
	uint32_t context_manager = 0;
	int fd = open("/dev/binder", O_RDWR | O_CLOEXEC);

	if (fd < 0) {
		perror("open /dev/binder");
		return 1;
	}
	if (mmap(NULL, BINDER_MAPPING_SIZE, PROT_READ, MAP_PRIVATE, fd, 0) ==
	    MAP_FAILED) {
		perror("mmap /dev/binder");
		close(fd);
		return 3;
	}
	if (ioctl(fd, BINDER_SET_CONTEXT_MGR, &context_manager) < 0) {
		perror("BINDER_SET_CONTEXT_MGR");
		close(fd);
		return 2;
	}
	if (argc == 2 && strcmp(argv[1], "--fd-only") == 0) {
		int status = transact_fd_object(fd);

		close(fd);
		return status < 0 ? 20 : 0;
	}
	if (argc != 1) {
		fprintf(stderr, "usage: %s [--fd-only]\n", argv[0]);
		close(fd);
		return 64;
	}
	if (transact_fd_object(fd) < 0) {
		close(fd);
		return 20;
	}
	if (test_read_wait(fd) < 0) {
		close(fd);
		return 10;
	}
	if (transact_sg(fd, BC_TRANSACTION_SG, "SG transaction", BR_TRANSACTION) < 0) {
		close(fd);
		return 3;
	}
	if (transact_sg(fd, BC_REPLY_SG, "SG reply", BR_REPLY) < 0) {
		close(fd);
		return 4;
	}
	if (transact_sg_buffer(fd, BC_TRANSACTION_SG, BR_TRANSACTION) < 0) {
		close(fd);
		return 5;
	}
	if (transact_sg_buffer(fd, BC_REPLY_SG, BR_REPLY) < 0) {
		close(fd);
		return 6;
	}
	if (transact_sg_parent_buffer(fd, BC_TRANSACTION_SG, BR_TRANSACTION) < 0) {
		close(fd);
		return 7;
	}
	if (transact_sg_parent_buffer(fd, BC_REPLY_SG, BR_REPLY) < 0) {
		close(fd);
		return 8;
	}
	if (transact_sg_fd_array(fd, 1, 0, 0, 0, 0) < 0) {
		close(fd);
		return 11;
	}
	if (transact_sg_fd_array(fd, 1, 0, 0, 0, 2) < 0) {
		close(fd);
		return 18;
	}
	if (transact_sg_fd_array(fd, 1, 0, 1, 0, 0) < 0) {
		close(fd);
		return 15;
	}
	if (transact_sg_fd_array(fd, 1, 0, 1, 0, 1) < 0) {
		close(fd);
		return 17;
	}
	if (transact_sg_fd_array(fd, 1, 0, 0, 1, 0) < 0) {
		close(fd);
		return 16;
	}
	if (transact_context_handle_zero(fd) < 0) {
		close(fd);
		return 9;
	}
	if (transact_sg_fd_array(fd, 0, 0, 0, 0, 0) < 0) {
		close(fd);
		return 12;
	}
	if (transact_sg_fd_array(fd, 1, 1, 0, 0, 0) < 0) {
		close(fd);
		return 13;
	}
	if (transact_sg_fd_array(fd, 1, 2, 0, 0, 0) < 0) {
		close(fd);
		return 14;
	}
	close(fd);
	puts("BINDER_SCATTER_GATHER=PASS");
	return 0;
}
