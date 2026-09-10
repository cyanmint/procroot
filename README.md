procroot
========
[![Travis build status](https://travis-ci.org/termux/proot.svg?branch=master)](https://travis-ci.org/termux/proot)

This is a copy of [the PRoot project](https://github.com/proot-me/PRoot/) with patches applied to work better under [Termux](https://termux.com).

This fork ("procroot") additionally adds user-space PID namespace
virtualization; see below.

Rebranding
----------

The built executable produced by `make -C src` is now named `procroot`
instead of `proot` (installed as `$(BINDIR)/procroot`). This is purely a
binary/output rename: source file names (e.g. `cli/proot.c`,
`cli/proot.h`), internal identifiers, environment variables (e.g.
`PROOT_UNBUNDLE_LOADER`), and all other references to "proot" throughout
the codebase and documentation are intentionally left unchanged, since
this remains a fork of the upstream PRoot project.

New feature: `-p` / `--proc`, user-space PID namespace virtualization
----------------------------------------------------------------------

`procroot` supports a new CLI switch, `-p` / `--proc`, which emulates a
PID namespace entirely in user-space (no root/`CAP_SYS_ADMIN`/real
`unshare(CLONE_NEWPID)` required):

* The initial guest process always appears as PID 1 (`getpid()`,
  `/proc/self`, `/proc/1/...`, `ps aux`, etc. all agree).
* Every subsequently created process/thread (`clone`, `clone3`, `fork`,
  `vfork`) is assigned the next sequential guest vPID/vTID, bidirectionally
  mapped to its real host PID/TID.
* PID-retrieval syscalls (`getpid`, `getppid`, `gettid`, `getpgid`,
  `getsid`) return the guest vPID/vTID instead of the host one.
* PID-targeting syscalls (`kill`, `tgkill`, `tkill`, `ptrace`,
  `sched_setaffinity`, `sched_getaffinity`, `process_madvise`,
  `ioprio_set`, `pidfd_open`) translate a guest vPID argument back to
  the corresponding host PID before it reaches the kernel.
* `/proc` is dynamically virtualized instead of being bound straight
  from the host:
  * `getdents64` on `/proc` hides host processes outside of the PRoot
    tree and renames the remaining numeric entries to their vPID.
  * `openat`/`readlink`/`stat` on `/proc/<vpid>/...` are rewritten to
    `/proc/<host_pid>/...` before hitting the host kernel.
  * `/proc/self` (and `/proc/thread-self`) always resolve to the
    calling guest process's own vPID/vTID, exactly like a real `/proc`.
  * `read()` on tracked `/proc/<pid>/status`, `/proc/<pid>/stat`, and
    `/proc/<pid>/statm` file descriptors patches PID-shaped fields
    (`Pid:`, `PPid:`, `Tgid:`, `NSpid:`, ...) from host PID to vPID.
  * Non-PID `/proc` entries (e.g. `/proc/cpuinfo`, `/proc/version`,
    `/proc/sys/...`) and all of `/sys` are mirrored transparently from
    the host.
* Best-effort fail-to-success spoofing: any operation targeting a
  mirrored `/sys` path or a non-PID `/proc` path that fails on the
  host (e.g. a permission-denied write to a sysfs attribute) is turned
  into an apparent successful no-op on the guest side, instead of
  surfacing the real failure.
* `-p`/`--proc` is mutually exclusive with binding the host `/proc` or
  `/sys` (`-b /proc`, `-b /sys`, or any equivalent `--bind=`): PID
  virtualization replaces standard `/proc`/`/sys` bind mounting, and
  combining them is rejected with a `FATAL` error at startup.

A standalone checker program that exercises these behaviors lives in
[`tests/checker`](tests/checker); it can be built and run with:

```sh
make -C src
make -C tests/checker
./src/procroot -p ./tests/checker/checker
```

It is also built and run automatically in CI (see
`.github/workflows/ci.yml`).
