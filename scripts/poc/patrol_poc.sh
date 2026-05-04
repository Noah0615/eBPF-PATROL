#!/usr/bin/env sh
set -u

section() {
	printf "\n== %s ==\n" "$1"
}

run() {
	name="$1"
	shift
	section "$name"
	"$@"
	rc=$?
	printf "[%s] exit=%s\n" "$name" "$rc"
	sleep 1
}

shell_exec() {
	if [ -x /bin/bash ]; then
		/bin/bash -lc 'echo patrol-poc-shell'
	else
		/bin/sh -c 'echo patrol-poc-shell'
	fi
}

python_exec() {
	if command -v python3 >/dev/null 2>&1; then
		python3 -c 'print("patrol-poc-python")'
	else
		echo "python3 not found; skipping"
	fi
}

sensitive_reads() {
	dd if=/etc/shadow of=/dev/null bs=1 count=1 2>/dev/null || true
	dd if=/proc/kcore of=/dev/null bs=1 count=0 2>/dev/null || true
}

docker_socket_open() {
	if [ -S /var/run/docker.sock ]; then
		dd if=/var/run/docker.sock of=/dev/null bs=1 count=0 2>/dev/null || true
	elif [ -S /run/docker.sock ]; then
		dd if=/run/docker.sock of=/dev/null bs=1 count=0 2>/dev/null || true
	else
		echo "docker socket not present; skipping"
	fi
}

namespace_unshare() {
	if command -v unshare >/dev/null 2>&1; then
		unshare -m /bin/true 2>/dev/null || true
	else
		echo "unshare not found; skipping"
	fi
}

mount_attempt() {
	mkdir -p /tmp/patrol-poc-mnt
	mount -t tmpfs patrol-poc /tmp/patrol-poc-mnt 2>/dev/null || true
	umount /tmp/patrol-poc-mnt 2>/dev/null || true
	rmdir /tmp/patrol-poc-mnt 2>/dev/null || true
}

ptrace_attempt() {
	if command -v strace >/dev/null 2>&1; then
		strace -o /tmp/patrol-poc-strace.log /bin/true 2>/dev/null || true
		rm -f /tmp/patrol-poc-strace.log
	else
		echo "strace not found; skipping"
	fi
}

printf "INTENT-BPF safe detection PoC\n"
printf "Run patrold in another terminal before starting this script.\n"

run "shell exec" shell_exec
run "python exec" python_exec
run "sensitive file open" sensitive_reads
run "docker socket open" docker_socket_open
run "namespace unshare" namespace_unshare
run "mount attempt" mount_attempt
run "ptrace attempt" ptrace_attempt

printf "\nDone. Check patrold logs for detect-shell-exec, deny-shadow-access, deny-kcore-access, detect-unshare-namespace, detect-mount-syscall, and detect-ptrace-abuse.\n"
