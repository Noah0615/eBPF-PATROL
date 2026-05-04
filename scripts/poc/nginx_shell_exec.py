#!/usr/bin/env python3
import ctypes
import os
import sys


def set_comm(name: bytes) -> None:
    libc = ctypes.CDLL(None)
    pr_set_name = 15
    if libc.prctl(pr_set_name, name, 0, 0, 0) != 0:
        raise OSError(ctypes.get_errno(), "prctl(PR_SET_NAME) failed")


def main() -> None:
    shell = "/bin/bash" if os.path.exists("/bin/bash") else "/bin/sh"
    flag = "-lc" if shell.endswith("bash") else "-c"

    # eBPF reads current comm at sys_enter_execve, before the new shell image
    # replaces this process. Setting comm to nginx simulates a web workload
    # unexpectedly spawning a shell without requiring a real nginx exploit.
    set_comm(b"nginx")
    os.execv(shell, [shell, flag, "echo patrol-poc-nginx-shell; sleep 1"])


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"nginx_shell_exec.py failed: {exc}", file=sys.stderr)
        sys.exit(1)
