#!/usr/bin/env python3
"""Minimal ADB TCP transport backed by a procroot shell."""
import argparse
import os
import socket
import struct
import subprocess
import threading

A_OPEN = b"OPEN"
A_OKAY = b"OKAY"
A_CLSE = b"CLSE"
A_WRTE = b"WRTE"
A_CNXN = b"CNXN"
A_AUTH = b"AUTH"
A_STLS = b"STLS"
A_SYNC = b"SYNC"


def checksum(payload):
    return sum(payload) & 0xFFFFFFFF


def frame(command, arg0=0, arg1=0, payload=b""):
    value = int.from_bytes(command, "little")
    return struct.pack("<6I", value, arg0, arg1, len(payload),
                       checksum(payload), value ^ 0xFFFFFFFF) + payload


def recv_exact(sock, size):
    data = b""
    while len(data) < size:
        part = sock.recv(size - len(data))
        if not part:
            raise ConnectionError("adb peer disconnected")
        data += part
    return data


def recv_frame(sock):
    header = recv_exact(sock, 24)
    command, arg0, arg1, length, expected, magic = struct.unpack("<6I", header)
    if magic != (command ^ 0xFFFFFFFF):
        raise ValueError("invalid adb command magic")
    payload = recv_exact(sock, length) if length else b""
    if checksum(payload) != expected:
        raise ValueError("invalid adb payload checksum")
    return command.to_bytes(4, "little"), arg0, arg1, payload


def send_wrte(sock, remote, local, payload):
    sock.sendall(frame(A_WRTE, local, remote, payload))


def run_shell(sock, local, remote, spec, rootfs, procroot):
    remote = 1
    if spec.startswith("shell,v2"):
        command = spec.split(":", 1)[1].rstrip("\0") if ":" in spec else "/system/bin/sh"
    elif spec.startswith("shell:"):
        command = spec[6:].rstrip("\0") or "/system/bin/sh"
    else:
        command = "/system/bin/sh"
    argv = [procroot, "-0", "-N", "--binder", "-r", rootfs, "-w", "/",
            "/system/bin/sh", "-c", command]
    try:
        proc = subprocess.Popen(argv, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT)
        # Device OKAY addresses the device stream first, then the host stream.
        sock.sendall(frame(A_OKAY, remote, local))
        while True:
            data = proc.stdout.read(65536)
            if not data:
                break
            # Shell v2 prefixes each stream packet with stdout channel 1.
            if spec.startswith("shell,v2"):
                data = b"\x01" + data
            sock.sendall(frame(A_WRTE, remote, local, data))
            # The host acknowledges every device WRTE with an OKAY.
            ack, _, _, _ = recv_frame(sock)
            if ack != A_OKAY:
                return
        proc.wait()
        if spec.startswith("shell,v2"):
            sock.sendall(frame(A_WRTE, remote, local, b"\x03" + struct.pack("<I", proc.returncode & 0xffffffff)))
            ack, _, _, _ = recv_frame(sock)
            if ack != A_OKAY:
                return
        sock.sendall(frame(A_CLSE, remote, local))
    except (BrokenPipeError, ConnectionError):
        return


def handle(conn, rootfs, procroot):
    with conn:
        try:
            cmd, arg0, arg1, payload = recv_frame(conn)
            if cmd == A_CNXN:

                banner = (b"device::ro.product.name=redroid;"
                          b"ro.product.model=redroid-procroot;"
                          b"ro.product.device=redroid_arm64;\0")
                conn.sendall(frame(A_CNXN, 0x01000000, 4096, banner))
            elif cmd == A_AUTH:
                return
            else:
                return
            while True:
                cmd, arg0, arg1, payload = recv_frame(conn)

                if cmd != A_OPEN:
                    if cmd == A_CLSE:
                        return
                    continue
                run_shell(conn, arg0, arg1, payload.decode(errors="replace"), rootfs, procroot)
                return
        except (ConnectionError, ValueError, BrokenPipeError):
            return


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--rootfs", required=True)
    parser.add_argument("--procroot", required=True)
    parser.add_argument("--port", type=int, default=5555)
    args = parser.parse_args()
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", args.port))
    listener.listen(16)
    print(f"ADB bridge listening on 127.0.0.1:{args.port}", flush=True)
    while True:
        conn, _ = listener.accept()

        threading.Thread(target=handle, args=(conn, args.rootfs, args.procroot), daemon=True).start()


if __name__ == "__main__":
    main()
