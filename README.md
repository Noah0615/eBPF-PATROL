# eBPF-PATROL

Runtime security monitoring for containerized and virtualized environments using eBPF.

## Features (Detection Only)

- Syscall monitoring: `execve`, `openat`, `clone`, `ptrace`
- YAML-based policy engine
- Argument-aware filtering
- Low overhead (<3%)

## Build

```bash
make bpf
go mod tidy
make build