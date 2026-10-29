#!/usr/bin/env python3
# SPDX-FileCopyrightText: NONE
# SPDX-License-Identifier: GPL-2.0-or-later
# Note: AI-generated contribution; no legal determination implied.
"""Bounded Redroid init/ADB integration test; must run as a non-root user."""
import argparse
import os
import pathlib
import shutil
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import time


def process_snapshot(uid, rootfs_text):
    found = []
    for entry in pathlib.Path("/proc").iterdir():
        if not entry.name.isdecimal():
            continue
        try:
            status = (entry / "status").read_text()
            real_uid = int(next(line.split()[1] for line in status.splitlines()
                                if line.startswith("Uid:")))
            if real_uid != uid:
                continue
            args = (entry / "cmdline").read_bytes().replace(b"\0", b" ").decode(errors="replace").strip()
            if rootfs_text in args and ("qemu-aarch64" in args or "procroot" in args):
                found.append((int(entry.name), args))
        except (OSError, StopIteration, ValueError):
            continue
    return found


def recv_exact(sock, size):
    data = bytearray()
    while len(data) < size:
        part = sock.recv(size - len(data))
        if not part:
            raise ConnectionError("ADB peer closed the connection")
        data.extend(part)
    return bytes(data)


def adb_packet(command, arg0=0, arg1=0, payload=b""):
    cmd = int.from_bytes(command.encode("ascii"), "little")
    return struct.pack("<6I", cmd, arg0, arg1, len(payload),
                       sum(payload) & 0xffffffff, cmd ^ 0xffffffff) + payload


def recv_adb_packet(sock):
    header = recv_exact(sock, 24)
    cmd, arg0, arg1, length, checksum, magic = struct.unpack("<6I", header)
    if magic != (cmd ^ 0xffffffff) or length > 1024 * 1024:
        raise ValueError("invalid ADB packet header")
    payload = recv_exact(sock, length) if length else b""
    if (sum(payload) & 0xffffffff) != checksum:
        raise ValueError("invalid ADB packet checksum")
    return cmd.to_bytes(4, "little").decode("ascii", errors="replace"), arg0, arg1, payload


def adb_shell_probe(port, timeout_s=5):
    token = b"PROCROOT_REDDROID_ADB_OK"
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=timeout_s) as sock:
            sock.settimeout(timeout_s)
            sock.sendall(adb_packet("CNXN", 0x01000000, 4096, b"host::\0"))
            command, arg0, _, payload = recv_adb_packet(sock)
            if command == "AUTH":
                return "auth-required", payload[:64].decode(errors="replace")
            if command != "CNXN":
                return "unexpected-" + command, payload[:128].decode(errors="replace")
            sock.sendall(adb_packet("OPEN", 1, 0, b"shell:echo " + token + b"\0"))
            remote_id = None
            output = bytearray()
            deadline = time.monotonic() + timeout_s
            while time.monotonic() < deadline:
                command, arg0, arg1, payload = recv_adb_packet(sock)
                if command == "OKAY":
                    remote_id = arg0
                elif command == "WRTE":
                    output.extend(payload)
                    sock.sendall(adb_packet("OKAY", 1, arg0))
                elif command == "CLSE":
                    if remote_id is not None:
                        sock.sendall(adb_packet("CLSE", 1, arg0))
                    break
            text = output.decode(errors="replace")
            return ("shell-ok" if token.decode() in text else "shell-no-token"), text[:500]
    except (OSError, TimeoutError, ConnectionError, ValueError) as exc:
        return "unavailable", str(exc)


def copy_overlay(rootfs, guest_path, destination):
    source = rootfs / guest_path.lstrip("/")
    destination.mkdir(parents=True, exist_ok=True)
    if source.is_dir():
        shutil.copytree(source, destination, dirs_exist_ok=True, symlinks=True,
                        copy_function=shutil.copy2)
    elif source.exists():
        shutil.copy2(source, destination, follow_symlinks=False)


def main():
    if os.getuid() == 0:
        print("ERROR: refusing to run Android init as root", file=sys.stderr)
        return 2
    parser = argparse.ArgumentParser(description=__doc__)
    workspace = pathlib.Path(__file__).resolve().parents[2]
    project = workspace / "procroot"
    parser.add_argument("--rootfs", type=pathlib.Path, default=workspace / "redroid9")
    parser.add_argument("--procroot", type=pathlib.Path, default=project / "src/procroot")
    parser.add_argument("--qemu", default=os.environ.get("QEMU", shutil.which("qemu-aarch64")))
    parser.add_argument("--seconds", type=int, default=60)
    parser.add_argument("--adb-port", type=int, default=5555)
    args = parser.parse_args()
    rootfs = args.rootfs.resolve()
    procroot = args.procroot.resolve()
    qemu = pathlib.Path(args.qemu).resolve() if args.qemu else None
    if not (rootfs / "init").is_file() or not os.access(procroot, os.X_OK) or not qemu or not os.access(qemu, os.X_OK):
        parser.error("rootfs/init, executable procroot, and executable --qemu are required")
    if args.seconds < 10 or args.seconds > 180:
        parser.error("--seconds must be between 10 and 180")

    run_parent = workspace / ".procroot-qemu-build" / "init-runs"
    run_parent.mkdir(parents=True, exist_ok=True)
    run_dir = pathlib.Path(tempfile.mkdtemp(prefix="redroid-init-", dir=run_parent))
    bindings = []
    properties_host = pathlib.Path(tempfile.mkdtemp(prefix="procroot-redroid-props-", dir="/dev/shm"))
    properties_host.chmod(0o700)
    bindings.append((properties_host, "/dev/__properties__"))
    for label, guest in [
        ("binderfs", "/dev/binderfs"), ("socket", "/dev/socket"),
        ("data", "/data"), ("cache", "/cache"),
        ("persist", "/persist"), ("metadata", "/metadata"),
    ]:
        host = run_dir / label
        if guest in ("/dev/socket", "/dev/binderfs"):
            host.mkdir(parents=True, exist_ok=True)
        else:
            copy_overlay(rootfs, guest, host)
        bindings.append((host, guest))
    bindings.append((pathlib.Path("/dev/urandom"), "/dev/urandom"))
    bindings.append((pathlib.Path("/dev/null"), "/dev/null"))
    (run_dir / "tmp").mkdir()
    bindings.append((run_dir / "tmp", "/tmp"))
    for label, guest in [("kmsg", "/dev/kmsg"), ("kmsg-debug", "/dev/kmsg_debug"),
                         ("booting", "/dev/.booting"), ("coldboot", "/dev/.coldboot_done")]:
        source = rootfs / guest.lstrip("/")
        host = run_dir / label
        if guest in ("/dev/kmsg", "/dev/kmsg_debug", "/dev/.booting", "/dev/.coldboot_done") or not source.exists():
            host.touch()
        else:
            shutil.copy2(source, host, follow_symlinks=False)
        bindings.append((host, guest))

    before = {pid for pid, _ in process_snapshot(os.getuid(), str(rootfs))}
    cmd = [str(procroot), "--kill-on-exit", "-0", "-N", "-B", "-q",
           f"{qemu} -L {rootfs}", "-r", str(rootfs), "-w", "/"]
    for host, guest in bindings:
        cmd.extend(["-b", f"{host}:{guest}"])
    cmd.append("/init")
    log_path = run_dir / "procroot.log"
    print(f"uid={os.getuid()} timeout={args.seconds}s qemu={qemu}")
    print(f"init_log={log_path}")
    with log_path.open("wb") as log:
        process = subprocess.Popen(cmd, cwd=workspace, stdin=subprocess.DEVNULL,
                                   stdout=log, stderr=subprocess.STDOUT,
                                   start_new_session=True)
        try:
            process.wait(timeout=args.seconds)
            remained_alive = False
        except subprocess.TimeoutExpired:
            remained_alive = True
        adb_state, adb_detail = adb_shell_probe(args.adb_port)
        live = process_snapshot(os.getuid(), str(rootfs))
        print(f"init_alive_after_window={remained_alive} returncode={process.poll()}")
        print(f"host_processes={live}")
        print(f"adb_probe={adb_state}: {adb_detail}")
        try:
            os.killpg(process.pid, signal.SIGTERM)
            process.wait(timeout=5)
        except (ProcessLookupError, subprocess.TimeoutExpired):
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                pass
    time.sleep(0.2)
    survivors = [item for item in process_snapshot(os.getuid(), str(rootfs))
                 if item[0] not in before]
    for pid, _ in survivors:
        try:
            os.kill(pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
    if survivors:
        time.sleep(0.3)
        survivors = [item for item in process_snapshot(os.getuid(), str(rootfs))
                     if item[0] not in before]
    for pid, _ in survivors:
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    if survivors:
        time.sleep(0.2)
        survivors = [item for item in process_snapshot(os.getuid(), str(rootfs))
                     if item[0] not in before]
    print(f"matching_processes_after_cleanup={survivors}")
    if not survivors:
        shutil.rmtree(properties_host)
    else:
        print(f"property_backing_preserved={properties_host}")
    for label in ("kmsg", "kmsg-debug"):
        path = run_dir / label
        try:
            lines = [line for line in path.read_text(errors="replace").splitlines() if line]
        except OSError:
            lines = []
        print(f"{label}_lines={len(lines)}")
        for line in lines[-60:]:
            print(f"{label}: {line[:500]}")
    try:
        log_lines = log_path.read_text(errors="replace").splitlines()
    except OSError:
        log_lines = []
    for line in log_lines[-40:]:
        print(f"proot: {line[:500]}")
    if remained_alive and adb_state == "shell-ok" and not survivors:
        shutil.rmtree(run_dir)
        return 0
    print(f"run_state_preserved={run_dir}")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
