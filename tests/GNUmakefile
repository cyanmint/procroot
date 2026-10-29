DIR    = $(dir $(abspath $(firstword $(MAKEFILE_LIST))))
ROOTFS = $(DIR)/rootfs
PROOT  = $(DIR)/../src/procroot
CC     = gcc
PROOT_RAW = $(PROOT)

CHECK_TESTS = $(patsubst %,check-%, $(wildcard test-*.sh) $(wildcard test-*.c))

.PHONY: check clean_failure check_failure setup check-%

check: | clean_failure check_failure

memcheck: PROOT_RAW := $(PROOT)
memcheck: PROOT := $(shell which valgrind) -q --error-exitcode=1 $(PROOT)
memcheck: check

clean_failure:
	@rm -f failure

check_failure: $(CHECK_TESTS)
	@bash -c '! test -e failure'

check-%.sh: %.sh setup
	$(Q)env ROOT_RAW="$(PROOT_RAW)" PROOT="$(PROOT)" ROOTFS=$(ROOTFS) sh -ex $< $(silently); $(call check,$*)

check-%.c: $(ROOTFS)/bin/% setup
	$(call check_c,$*,$(PROOT) -b /proc -r $(ROOTFS) /bin/$*)

# Special cases.
check-test-bdc90417.c: test-bdc90417
	$(call check_c,$<,$(PROOT) -w . ./$<)

check-test-securebits.c: $(ROOTFS)/bin/test-securebits setup
	$(call check_c,$*,$(PROOT) -0 -b /proc -r $(ROOTFS) /bin/$*)

check-test-capset-drop.c: $(ROOTFS)/bin/test-capset-drop setup
	$(call check_c,$*,$(PROOT) -0 -b /proc -r $(ROOTFS) /bin/$*)

check-test-capget-fake-root.c: $(ROOTFS)/bin/test-capget-fake-root setup
	$(call check_c,$*,$(PROOT) -0 -b /proc -r $(ROOTFS) /bin/$* root)
	$(call check_c,$*,$(PROOT) -b /proc -r $(ROOTFS) /bin/$* nonroot)
	$(call check_c,$*,$(PROOT) -0 -b /proc -r $(ROOTFS) /bin/$* clear)
	$(call check_c,$*,$(PROOT) -0 -b /proc -r $(ROOTFS) /bin/$* drop)
	$(call check_c,$*,$(PROOT) -0 -b /proc -r $(ROOTFS) /bin/$* system)

check-test-ambient-caps.c: $(ROOTFS)/bin/test-ambient-caps setup
	$(call check_c,$*,$(PROOT) -0 -b /proc -r $(ROOTFS) /bin/$*)

check-test-rlimit-memlock.c: $(ROOTFS)/bin/test-rlimit-memlock setup
	$(call check_c,$*,$(PROOT) -0 -b /proc -r $(ROOTFS) /bin/$*)

check-test-binder-context-manager.c: test-binder-context-manager
	$(call check_c,$<,$(PROOT) -B -0 ./$<)

check-test-binder-epoll.c: test-binder-epoll
	$(call check_c,$<,$(PROOT) -B -0 ./$<)

check-test-binder-poll-notify.c: test-binder-poll-notify
	$(call check_c,$<,$(PROOT) -B -0 ./$<)

check-test-binder-read-word-backlog.c: test-binder-read-word-backlog
	$(call check_c,$<,$(PROOT) -B -0 ./$<)

check-test-binder-buffer-capacity.c: test-binder-buffer-capacity
	$(call check_c,$<,$(PROOT) -B -0 ./$<)

check-test-binder-mmap-transaction.c: test-binder-mmap-transaction
	$(call check_c,$<,$(PROOT) -B -0 ./$<)

check-test-binder-zero-payload.c: test-binder-zero-payload
	$(call check_c,$<,$(PROOT) -B -0 ./$<)

check-test-binder-free-unknown-buffer.c: test-binder-free-unknown-buffer
	$(call check_c,$<,$(PROOT) -B -0 ./$<)

check-test-binder-socket-shutdown.c: test-binder-socket-shutdown
	$(call check_c,$<,$(PROOT) -B -0 ./$<)

check-test-binder-security-context.c: test-binder-security-context
	$(call check_c,$<,$(PROOT) -B -0 ./$<)

check-test-binder-death-notification.c: test-binder-death-notification
	$(call check_c,$<,$(PROOT) -B -0 ./$<)

check-test-binder-death-owner-exit.c: test-binder-death-owner-exit
	$(call check_c,$<,$(PROOT) -B -0 ./$<)

check-test-binder-dead-handle-lifetime.c: test-binder-dead-handle-lifetime
	$(call check_c,$<,$(PROOT) -B -0 ./$<)

check-test-binder-refcount.c: test-binder-refcount
	$(call check_c,$<,$(PROOT) -B -0 ./$<)

check-test-binder-scatter-gather.c: test-binder-scatter-gather
	$(call check_c,$<,$(PROOT) -B -0 ./$<)

check-test-binder-fda-peer-credentials.c: test-binder-fda-peer-credentials
	$(call check_c,$<,./$<)

check-test-binder-fda-scratch.c: test-binder-fda-scratch
	$(call check_c,$<,./$<)

check-test-syscall-chain-reuse.c: test-syscall-chain-reuse
	$(call check_c,$<,./$<)

check-test-pthread-atfork.c: test-pthread-atfork
	$(call check_c,$<,$(PROOT) -B -0 ./$<)

check-test-fork-child-exit-race.c: test-fork-child-exit-race
	$(call check_c,$<,$(PROOT) -N ./$<)

check-test-binder-thread-routing.c: test-binder-thread-routing
	$(call check_c,$<,$(PROOT) -B -0 ./$<)

check-test-binder-thread-reply-routing.c: test-binder-thread-reply-routing
	$(call check_c,$<,$(PROOT) -B -0 ./$<)

check-test-binder-deferred-reply-frame.c: test-binder-deferred-reply-frame
	$(call check_c,$<,$(PROOT) -B -0 ./$<)

check-test-binder-dead-sender-reply.c: test-binder-dead-sender-reply
	$(call check_c,$<,$(PROOT) -B -0 ./$<)

check-test-binder-queued-reply-identity.c: test-binder-queued-reply-identity
	$(call check_c,$<,$(PROOT) -B -0 ./$<)

check-test-binder-shared-thread-fd-domain.c: test-binder-shared-thread-fd-domain
	$(call check_c,$<,$(PROOT) -B -0 ./$<)

check-test-binder-fd-domain-transfer.c: test-binder-fd-domain-transfer
	$(call check_c,$<,$(PROOT) -B -0 ./$<)

check-test-binder-nested-transaction.c: test-binder-nested-transaction
	$(call check_c,$<,$(PROOT) -B -0 ./$<)

check-test-binder-handle-translation.c: test-binder-handle-translation
	$(call check_c,$<,$(PROOT) -B -0 ./$<)

check-test-binder-hwbinder-handle-translation.c: test-binder-hwbinder-handle-translation
	$(call check_c,$<,$(PROOT) -B -0 ./$<)

check-test-binder-transfer-refcount.c: test-binder-transfer-refcount
	$(call check_c,$<,$(PROOT) -B -0 ./$<)

check-test-binder-reply-acquire.c: test-binder-reply-acquire
	$(call check_c,$<,$(PROOT) -B -0 ./$<)

check-test-binder-domain-isolation.c: test-binder-domain-isolation
	$(call check_c,$<,$(PROOT) -B -0 ./$<)

check-test-binder-domain-queue.c: test-binder-domain-queue
	$(call check_c,$<,$(PROOT) -B -0 ./$<)

check-test-binderfs-feature-path.sh: test-binderfs-feature-path

check-test-proot-properties-dir.c: test-proot-properties-dir
	$(call check_c,$<,$(PROOT) -B -0 ./$<)

check-test-proc-self-fd-realpath.c: test-proc-self-fd-realpath
	$(call check_c,$<,$(PROOT) -N -B -0 ./$<)

check-test-proc-pid-dirfd.c: test-proc-pid-dirfd
	$(call check_c,$<,$(PROOT) -N -B -0 ./$<)

check-test-pid-virt-sched.c: test-pid-virt-sched
	$(call check_c,$<,$(PROOT) -N -B -0 ./$<)

# Not supported anymore.
# check-test-af062114.c: test-af062114
# 	$(call check_c,$<,$(PROOT) -v -1 -q /bin/true -b . -b /lib -b /lib64 -b /proc -r $(ROOTFS) ./$< | grep -- --inhibit-rpath)
# 	$(call check_c,$<,$(PROOT) -v -1 -q /bin/true / ./$< | grep '^./$<') deprecated

check-test-5bed7141.c: test-5bed7141
	$(call check_c,$<,$(PROOT) ./$<)

check-test-5bed7143.c: test-5bed7143
	$(call check_c,$<,$(PROOT) -r $(ROOTFS) -b . ./$<)
	$(call check_c,$<,$(PROOT) ./$<)

check-test-16573e73.c: test-16573e73
	$(call check_c,$<,$(PROOT) ./$<)
	$(call check_c,$<,$(PROOT) ./$< 1)

check-test-82ba4ba1.c: test-82ba4ba1
	$(call check_c,$<,$(PROOT) -0 ./$<)
	$(call check_c,$<,! $(PROOT) -i 123:456 ./$<)

check-test-kkkkkkkk.c: test-kkkkkkkk
	$(call check_c,$<,$(PROOT) ./$<)

check-test-25069c12.c: test-25069c12
	$(call check_c,$<,$(PROOT) ./$<)

check-test-25069c13.c: test-25069c13
	$(call check_c,$<,$(PROOT) ./$<)

check-test-1ffc8309.c: test-1ffc8309
	$(call check_c,$<,env PROOT_FORCE_KOMPAT=1 $(PROOT) -k $(shell uname -r) ./$<)

check-test-c5a7a0f0.c: test-c5a7a0f0
	$(call check_c,$<,$(PROOT) -0 ./$<)
	$(call check_c,$<,! $(PROOT) -i 123:456 ./$<)

check-test-a3e68988.c: test-a3e68988
	@which gdb >/dev/null 2>&1 || rm -f $<
	$(call check_c,$<,$(PROOT) gdb -return-child-result -ex run -ex quit ./$<)

check-test-c47aeb7d.c: test-c47aeb7d
	@which gdb >/dev/null 2>&1 || rm -f $<
	$(call check_c,$<,$(PROOT) gdb -return-child-result -ex run -ex quit ./$<)

check-test-fdf487a0.c: test-fdf487a0
	$(call check_c,$<,echo test | $(PROOT) ./$<)

check-test-iiiiiiii.c: test-iiiiiiii
	$(call check_c,$<,echo test | env PROOT_DONT_POLLUTE_ROOTFS=1 $(PROOT) -b /bin:/this_shall_not_exist_outside_proot ./$<)

check-test-9c07fad8.c: test-9c07fad8
	$(call check_c,$<,$(PROOT) ./$<)

check-test-fa205b56.c: test-fa205b56
	$(call check_c,$<,$(PROOT) ./$<)

check_c = $(Q)if [ -e $< ]; then			\
		$(2) $(silently); $(call check,$(1))	\
	else						\
		echo "  CHECK	$(1) skipped";		\
	fi

check = case "$$?" in					\
		0)   echo "  CHECK	$(1) ok";;	\
		125) echo "  CHECK	$(1) skipped";;	\
		*)   echo "  CHECK	$(1) FAILED";	\
		     touch failure ;;			\
	esac

######################################################################
# Build a clean rootfs

ROOTFS_BIN = $(ROOTFS)/bin/true $(ROOTFS)/bin/false    				 \
       $(ROOTFS)/bin/pwd  $(ROOTFS)/bin/readlink $(ROOTFS)/bin/symlink		 \
       $(ROOTFS)/bin/abs-true $(ROOTFS)/bin/rel-true $(ROOTFS)/bin/echo		 \
       $(ROOTFS)/bin/argv0 $(ROOTFS)/bin/readdir $(ROOTFS)/bin/cat		 \
       $(ROOTFS)/bin/chdir_getcwd $(ROOTFS)/bin/fchdir_getcwd $(ROOTFS)/bin/argv \
       $(ROOTFS)/bin/fork-wait $(ROOTFS)/bin/ptrace $(ROOTFS)/bin/ptrace-2	 \
       $(ROOTFS)/bin/puts_proc_self_exe $(ROOTFS)/bin/exec $(ROOTFS)/bin/exec-m32 \
       $(ROOTFS)/bin/exec-suid $(ROOTFS)/bin/exec-sgid $(ROOTFS)/bin/exec-m32-suid \
       $(ROOTFS)/bin/exec-m32-sgid $(ROOTFS)/bin/getresuid $(ROOTFS)/bin/getresgid \
       $(ROOTFS)/bin/open_nofollow $(ROOTFS)/bin/fchmodat2 \
       $(ROOTFS)/bin/open_tree $(ROOTFS)/bin/fork_regs

ROOTFS_DIR = $(ROOTFS)/bin $(ROOTFS)/tmp

$(ROOTFS_BIN): | $(ROOTFS_DIR)

$(ROOTFS_DIR):
	@mkdir -p $@

setup: $(ROOTFS_BIN)

$(ROOTFS)/bin/abs-true:
	$(Q)ln -fs /bin/true $@

$(ROOTFS)/bin/rel-true:
	$(Q)ln -fs ./true $@

$(ROOTFS)/bin/exec-m32: exec.c
	$(Q)$(CC) -m32 -static $^ -o $@ $(silently) || true

$(ROOTFS)/bin/exec-suid: $(ROOTFS)/bin/exec
	$(Q)cp $^ $@
	$(Q)chmod u+s $@

$(ROOTFS)/bin/exec-sgid: $(ROOTFS)/bin/exec
	$(Q)cp $^ $@
	$(Q)chmod g+s $@

$(ROOTFS)/bin/exec-m32-suid: $(ROOTFS)/bin/exec-m32
	$(Q)cp $^     $@ $(silently) || true
	$(Q)chmod u+s $@ $(silently) || true

$(ROOTFS)/bin/exec-m32-sgid: $(ROOTFS)/bin/exec-m32
	$(Q)cp $^ $@      $(silently) || true
	$(Q)chmod g+s $@  $(silently) || true

.SECONDARY: $(patsubst %.c,$(ROOTFS)/bin/%, $(wildcard test-*.c))
$(ROOTFS)/bin/%: %.c
	$(Q)$(CC) -static $*.c -o $@ $(silently) || true

# Special cases.
test-bdc90417: test-bdc90417.c
	$(Q)$(CC) $< -o $@ $(silently) || true

test-pthread-atfork: test-pthread-atfork.c
	$(Q)$(CC) -pthread $< -o $@ $(silently) || true

test-fork-child-exit-race: test-fork-child-exit-race.c
	$(Q)$(CC) -pthread $< -o $@ $(silently) || true

test-binder-refcount: test-binder-refcount.c
	$(Q)$(CC) $< -o $@ $(silently) || true

test-binder-zero-payload: test-binder-zero-payload.c
	$(Q)$(CC) $< -o $@ $(silently) || true

test-binder-free-unknown-buffer: test-binder-free-unknown-buffer.c
	$(Q)$(CC) $< -o $@ $(silently) || true

test-binder-buffer-capacity: test-binder-buffer-capacity.c
	$(Q)$(CC) $< -o $@ $(silently) || true

test-binder-socket-shutdown: test-binder-socket-shutdown.c
	$(Q)$(CC) $< -o $@ $(silently) || true

test-binder-security-context: test-binder-security-context.c
	$(Q)$(CC) $< -o $@ $(silently) || true

test-binder-death-notification: test-binder-death-notification.c
	$(Q)$(CC) $< -o $@ $(silently) || true

test-binder-death-owner-exit: test-binder-death-owner-exit.c
	$(Q)$(CC) $< -o $@ $(silently) || true

test-binder-dead-handle-lifetime: test-binder-dead-handle-lifetime.c
	$(Q)$(CC) $< -o $@ $(silently) || true

test-binder-scatter-gather: test-binder-scatter-gather.c
	$(Q)$(CC) $< -o $@ $(silently) || true

test-binder-fda-peer-credentials: test-binder-fda-peer-credentials.c ../src/extension/binder/fda_courier.c
	$(Q)$(CC) -I../src $^ -o $@ $(silently) || true

test-binder-fda-scratch: test-binder-fda-scratch.c ../src/extension/binder/fda_courier.c
	$(Q)$(CC) -I../src $^ -o $@ $(silently) || true

test-syscall-chain-reuse: test-syscall-chain-reuse.c ../src/syscall/chain.c
	$(Q)$(CC) -I../src $^ -ltalloc -o $@ $(silently) || true

test-binder-thread-routing: test-binder-thread-routing.c
	$(Q)$(CC) $< -pthread -o $@ $(silently) || true

test-binder-thread-reply-routing: test-binder-thread-reply-routing.c
	$(Q)$(CC) $< -pthread -o $@ $(silently) || true

test-binder-deferred-reply-frame: test-binder-deferred-reply-frame.c
	$(Q)$(CC) $< -o $@ $(silently) || true

test-binder-queued-reply-identity: test-binder-queued-reply-identity.c
	$(Q)$(CC) $< -o $@ $(silently) || true

test-binder-shared-thread-fd-domain: test-binder-shared-thread-fd-domain.c
	$(Q)$(CC) $< -pthread -o $@ $(silently) || true

test-binder-fd-domain-transfer: test-binder-fd-domain-transfer.c
	$(Q)$(CC) $< -o $@ $(silently) || true

test-binder-nested-transaction: test-binder-nested-transaction.c
	$(Q)$(CC) $< -o $@ $(silently) || true

test-binder-handle-translation: test-binder-handle-translation.c
	$(Q)$(CC) $< -o $@ $(silently) || true

test-binder-hwbinder-handle-translation: test-binder-handle-translation.c
	$(Q)$(CC) -DBINDER_DEVICE_PATH='"/dev/hwbinder"' $< -o $@ $(silently) || true

test-binder-transfer-refcount: test-binder-transfer-refcount.c
	$(Q)$(CC) $< -o $@ $(silently) || true

test-binder-reply-acquire: test-binder-reply-acquire.c
	$(Q)$(CC) $< -o $@ $(silently) || true

test-binder-domain-isolation: test-binder-domain-isolation.c
	$(Q)$(CC) $< -o $@ $(silently) || true

test-binder-domain-queue: test-binder-domain-queue.c
	$(Q)$(CC) $< -o $@ $(silently) || true

test-binder-poll-notify: test-binder-poll-notify.c
	$(Q)$(CC) $< -o $@ $(silently) || true

test-binder-read-word-backlog: test-binder-read-word-backlog.c
	$(Q)$(CC) $< -o $@ $(silently) || true

test-binderfs-feature-path: test-binderfs-feature-path.c
	$(Q)$(CC) $< -o $@ $(silently) || true

test-proot-properties-dir: test-proot-properties-dir.c
	$(Q)$(CC) $< -o $@ $(silently) || true

test-proc-self-fd-realpath: test-proc-self-fd-realpath.c
	$(Q)$(CC) $< -o $@ $(silently) || true

test-proc-pid-dirfd: test-proc-pid-dirfd.c
	$(Q)$(CC) $< -o $@ $(silently) || true

test-pid-virt-sched: test-pid-virt-sched.c
	$(Q)$(CC) $< -o $@ $(silently) || true

# Not supported anymore.
# test-af062114: test-af062114.c
# 	$(Q)$(CC) $< -Wl,-rpath=foo -o $@ $(silently) || true

test-5bed7141: test-5bed7141.c
	$(Q)$(CC) $< -pthread -static -o $@ $(silently) || true

test-16573e73: test-16573e73.c
	$(Q)$(CC) $< -static -o $@ $(silently) || true

test-82ba4ba1: test-82ba4ba1.c
	$(Q)$(CC) $< -o $@ $(silently) || true

test-kkkkkkkk: test-kkkkkkkk.c
	$(Q)$(CC) $< -o $@ $(silently) || true

test-25069c12: test-25069c12.c
	$(Q)$(CC) $< -o $@ $(silently) || true

test-25069c13: test-25069c13.c
	$(Q)$(CC) $< -o $@ $(silently) || true

test-5bed7143: test-5bed7143.c
	$(Q)$(CC) $< -static -o $@ $(silently) || true

test-1ffc8309: test-1ffc8309.c
	$(Q)$(CC) $< -o $@ $(silently) || true

test-c5a7a0f0: test-c5a7a0f0.c
	$(Q)$(CC) $< -pthread -static -o $@ $(silently) || true

test-a3e68988: test-a3e68988.c
	$(Q)$(CC) $< -o $@ $(silently) || true

test-fdf487a0: test-fdf487a0.c
	$(Q)$(CC) $< -o $@ $(silently) || true

test-iiiiiiii: test-iiiiiiii.c
	$(Q)$(CC) $< -o $@ $(silently) || true

test-9c07fad8: test-9c07fad8.c
	$(Q)$(CC) -fPIE -pie $< -o $@ $(silently) || true

test-fa205b56: test-fa205b56.c
	$(Q)$(CC) $< -pthread -o $@ $(silently) || true

test-c47aeb7d: test-c47aeb7d.c
	$(Q)$(CC) $< -pthread -o $@ $(silently) || true

######################################################################
# Beautified output

V = 0
ifeq ($(V), 0)
    quiet = quiet_
    Q     = @
    silently = >/dev/null 2>&1
else
    quiet = 
    Q     = 
    silently = 
endif
