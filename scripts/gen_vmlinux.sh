#!/usr/bin/env bash
set -euo pipefail
bpftool btf dump file /sys/kernel/btf/vmlinux format c > bpf/vmlinux.h
echo "generated bpf/vmlinux.h"
