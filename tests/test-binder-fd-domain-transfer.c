/*
 * SPDX-FileCopyrightText: NONE
 * SPDX-License-Identifier: GPL-2.0-or-later
 * Note: AI-generated contribution; no legal determination implied.
 */
/* Check that a Binder-transferred hwbinder fd keeps its device domain. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>

#define MAPPING_SIZE (1024 * 1024)
#define REQUEST_CODE 0x46445251u
#define REPLY_CODE 0x46445250u
#define BINDER_TYPE_FD 0x66642a85u
#define TF_ACCEPT_FDS 0x10u
#define BINDER_SET_CONTEXT_MGR _IOW('b', 7, uint32_t)
#define BINDER_WRITE_READ _IOWR('b', 1, struct binder_write_read)
#define BC_TRANSACTION _IOW('c', 0, struct binder_transaction_data)
#define BC_REPLY _IOW('c', 1, struct binder_transaction_data)
#define BC_FREE_BUFFER _IOW('c', 3, uint64_t)
#define BR_TRANSACTION _IOR('r', 2, struct binder_transaction_data)
#define BR_REPLY _IOR('r', 3, struct binder_transaction_data)
#define BR_TRANSACTION_COMPLETE _IO('r', 6)

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

struct binder_write_read {
    uint64_t write_size;
    uint64_t write_consumed;
    uint64_t write_buffer;
    uint64_t read_size;
    uint64_t read_consumed;
    uint64_t read_buffer;
};

struct flat_binder_object {
    uint32_t type;
    uint32_t flags;
    union {
        uint32_t handle;
        int32_t fd;
        uint64_t binder;
    } object;
    uint64_t cookie;
};

static int open_mapped(const char *path, void **mapping)
{
    int fd = open(path, O_RDWR | O_CLOEXEC);
    if (fd < 0)
        return -1;
    *mapping = mmap(NULL, MAPPING_SIZE, PROT_READ, MAP_PRIVATE, fd, 0);
    if (*mapping == MAP_FAILED) {
        close(fd);
        return -1;
    }
    return fd;
}

static int send_command(int fd, uint32_t command,
                        const struct binder_transaction_data *transaction)
{
    uint8_t writes[sizeof(command) + sizeof(*transaction)];
    struct binder_write_read bwr = {};
    memcpy(writes, &command, sizeof(command));
    memcpy(writes + sizeof(command), transaction, sizeof(*transaction));
    bwr.write_size = sizeof(writes);
    bwr.write_buffer = (uint64_t)(uintptr_t)writes;
    if (ioctl(fd, BINDER_WRITE_READ, &bwr) < 0 ||
        bwr.write_consumed != sizeof(writes))
        return -1;
    return 0;
}

static int read_transaction(int fd, uint32_t expected,
                            struct binder_transaction_data *transaction)
{
    for (unsigned int attempt = 0; attempt < 20; attempt++) {
        uint8_t reads[1024] = {};
        struct binder_write_read bwr = {};
        size_t position = 0;
        bwr.read_size = sizeof(reads);
        bwr.read_buffer = (uint64_t)(uintptr_t)reads;
        if (ioctl(fd, BINDER_WRITE_READ, &bwr) < 0) {
            fprintf(stderr, "READ_IOCTL_FAILED errno=%d\n", errno);
            return -1;
        }
        while (position + sizeof(uint32_t) <= bwr.read_consumed) {
            uint32_t command;
            memcpy(&command, reads + position, sizeof(command));
            position += sizeof(command);
            if (command == BR_TRANSACTION_COMPLETE)
                continue;
            if (command != expected ||
                position + sizeof(*transaction) > bwr.read_consumed) {
                fprintf(stderr,
                        "READ_COMMAND_MISMATCH expected=%#x got=%#x consumed=%llu\n",
                        expected, command,
                        (unsigned long long)bwr.read_consumed);
                return -1;
            }
            memcpy(transaction, reads + position, sizeof(*transaction));
            return 0;
        }
        usleep(50000);
    }
    fprintf(stderr, "READ_TRANSACTION_TIMEOUT expected=%#x attempts=20\n",
            expected);
    return -1;
}

static int free_buffer(int fd, uint64_t address)
{
    uint8_t writes[sizeof(uint32_t) + sizeof(address)];
    struct binder_write_read bwr = {};
    uint32_t command = BC_FREE_BUFFER;
    memcpy(writes, &command, sizeof(command));
    memcpy(writes + sizeof(command), &address, sizeof(address));
    bwr.write_size = sizeof(writes);
    bwr.write_buffer = (uint64_t)(uintptr_t)writes;
    return ioctl(fd, BINDER_WRITE_READ, &bwr) < 0 ? -1 : 0;
}

static int client_process(int inherited_binder, int inherited_hwbinder,
                          int inherited_pipe_read, int inherited_pipe_write)
{
    void *mapping;
    int binder_fd;
    uint32_t token = REQUEST_CODE;
    struct binder_transaction_data request = {
        .target = 0,
        .code = REQUEST_CODE,
        .flags = TF_ACCEPT_FDS,
        .data_size = sizeof(token),
        .data_buffer = (uint64_t)(uintptr_t)&token,
    };
    struct binder_transaction_data reply;
    struct flat_binder_object objects[2];
    uint64_t offsets[2] = { 0, sizeof(objects[0]) };
    uint32_t context_manager = 0;
    int received_fds[2];
    char value = 'f';

    close(inherited_binder);
    close(inherited_hwbinder);
    close(inherited_pipe_read);
    close(inherited_pipe_write);
    binder_fd = open_mapped("/dev/binder", &mapping);
    if (binder_fd < 0 || send_command(binder_fd, BC_TRANSACTION, &request) < 0 ||
        read_transaction(binder_fd, BR_REPLY, &reply) < 0)
        return 20;
    if (reply.code != REPLY_CODE ||
        reply.data_size != sizeof(objects) ||
        reply.offsets_size != sizeof(offsets) ||
        reply.data_buffer < (uint64_t)(uintptr_t)mapping ||
        reply.data_buffer > (uint64_t)(uintptr_t)mapping + MAPPING_SIZE - sizeof(objects) ||
        reply.offsets_buffer < (uint64_t)(uintptr_t)mapping ||
        reply.offsets_buffer > (uint64_t)(uintptr_t)mapping + MAPPING_SIZE - sizeof(offsets))
        return 21;
    memcpy(objects, (const void *)(uintptr_t)reply.data_buffer, sizeof(objects));
    memcpy(offsets, (const void *)(uintptr_t)reply.offsets_buffer, sizeof(offsets));
    received_fds[0] = objects[0].object.fd;
    received_fds[1] = objects[1].object.fd;
    if (objects[0].type != BINDER_TYPE_FD ||
        objects[1].type != BINDER_TYPE_FD ||
        offsets[0] != 0 || offsets[1] != sizeof(objects[0]) ||
        received_fds[0] < 0 || received_fds[1] < 0 ||
        received_fds[0] == received_fds[1])
        return 22;
    if (free_buffer(binder_fd, reply.data_buffer) < 0)
        return 23;
    if (ioctl(received_fds[0], BINDER_SET_CONTEXT_MGR, &context_manager) < 0) {
        fprintf(stderr, "TRANSFERRED_HWBINDER_SET_CONTEXT_MGR=FAIL errno=%d\n", errno);
        return 24;
    }
    if (write(received_fds[1], &value, sizeof(value)) != sizeof(value)) {
        perror("write transferred second descriptor");
        return 25;
    }
    close(received_fds[0]);
    close(received_fds[1]);
    close(binder_fd);
    return 0;
}

int main(void)
{
    void *binder_mapping;
    void *hwbinder_mapping;
    uint32_t context_manager = 0;
    int binder_fd = open_mapped("/dev/binder", &binder_mapping);
    int hwbinder_fd;
    pid_t child;
    int status;
    struct binder_transaction_data request;
    struct binder_transaction_data reply;
    struct flat_binder_object objects[2] = {};
    uint64_t offsets[2] = { 0, sizeof(objects[0]) };
    int pipe_fds[2];
    char value = 0;

    if (binder_fd < 0) {
        perror("open /dev/binder");
        return 1;
    }
    if (ioctl(binder_fd, BINDER_SET_CONTEXT_MGR, &context_manager) < 0) {
        perror("BINDER_SET_CONTEXT_MGR /dev/binder");
        return 2;
    }
    hwbinder_fd = open_mapped("/dev/hwbinder", &hwbinder_mapping);
    if (hwbinder_fd < 0) {
        perror("open /dev/hwbinder");
        return 3;
    }
    if (pipe(pipe_fds) < 0) {
        perror("pipe direct FD reply");
        return 4;
    }
    child = fork();
    if (child < 0) {
        perror("fork");
        return 5;
    }
    if (child == 0)
        _exit(client_process(binder_fd, hwbinder_fd,
                             pipe_fds[0], pipe_fds[1]));
    if (read_transaction(binder_fd, BR_TRANSACTION, &request) < 0) {
        fprintf(stderr, "MANAGER_REQUEST_READ=FAIL errno=%d\n", errno);
        return 6;
    }
    if (request.code != REQUEST_CODE) {
        fprintf(stderr, "MANAGER_REQUEST_CODE=FAIL code=%#x\n", request.code);
        return 6;
    }
    if (free_buffer(binder_fd, request.data_buffer) < 0) {
        fprintf(stderr, "MANAGER_FREE_BUFFER=FAIL errno=%d\n", errno);
        return 6;
    }
    objects[0].type = BINDER_TYPE_FD;
    objects[0].object.fd = hwbinder_fd;
    objects[1].type = BINDER_TYPE_FD;
    objects[1].object.fd = pipe_fds[1];
    reply = (struct binder_transaction_data) {
        .code = REPLY_CODE,
        .data_size = sizeof(objects),
        .offsets_size = sizeof(offsets),
        .data_buffer = (uint64_t)(uintptr_t)objects,
        .offsets_buffer = (uint64_t)(uintptr_t)offsets,
    };
    if (send_command(binder_fd, BC_REPLY, &reply) < 0) {
        perror("reply with multiple direct FDs");
        (void)kill(child, SIGKILL);
        (void)waitpid(child, NULL, 0);
        return 7;
    }
    close(pipe_fds[1]);
    if (waitpid(child, &status, 0) != child) {
        perror("waitpid");
        return 8;
    }
    if (read(pipe_fds[0], &value, sizeof(value)) != sizeof(value) ||
        value != 'f') {
        fprintf(stderr, "second direct FD was not usable by the recipient\n");
        return 9;
    }
    close(pipe_fds[0]);
    close(hwbinder_fd);
    close(binder_fd);
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        fprintf(stderr, "FD_TRANSFER_CHILD_STATUS=%#x\n", status);
        return 10;
    }
    fprintf(stderr, "BINDER_FD_DOMAIN_TRANSFER_MULTIPLE=PASS\n");
    return 0;
}
