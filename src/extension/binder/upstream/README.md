# Android Binder upstream reference

This directory contains source copied from the Linux kernel Binder implementation
used as the protocol and UAPI reference for procroot's userspace Binder
compatibility layer.

## Source and provenance

- Upstream repository: `https://github.com/torvalds/linux.git`
- Mirrored Android/Linux source: `android.googlesource.com/kernel/common`
- Checkout: Linux kernel commit `40288c9206c17eb66a603262e06a58d300d0f279`
- Copied files:
  - `drivers/android/binder.c` → `binder_kernel_reference.c`
  - `include/uapi/linux/android/binder.h` → `binder_uapi.h`
  - `COPYING`
  - `LICENSES/preferred/GPL-2.0`

## Copyright and license

The copied Binder implementation and UAPI retain their upstream copyright
headers and SPDX identifiers. In particular:

- `binder_kernel_reference.c` is GPL-2.0-only.
- `binder_uapi.h` is GPL-2.0 WITH Linux-syscall-note.
- The Binder source includes copyright notices for Google, Inc. and the
  original OpenBinder.org interface notice for PalmSource, Inc.

The complete license texts are preserved in `COPYING` and `GPL-2.0`. These
files are redistributed here for attribution and compliance; they are not
silently relicensed as procroot code.

## Relationship to procroot

`binder_kernel_reference.c` is a Linux kernel driver and cannot be compiled as
part of procroot: it depends on Linux kernel internals, locking primitives,
file-descriptor tables, kernel memory management, and kernel scheduler APIs.
It is therefore reference material, not a linked or compiled procroot object.

`binder_uapi.h` is the copied ABI reference. The executable userspace broker in
`../binder.c` is an independent procroot implementation that progressively
ports the observable Binder protocol while retaining this attribution.
Changes to the port must preserve the upstream ABI definitions and document
any intentional userspace adaptation.
