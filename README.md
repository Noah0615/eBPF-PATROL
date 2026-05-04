# eBPF-PATROL / INTENT-BPF

Runtime security monitoring for containerized environments using eBPF.

This prototype implements the userspace side of 3-way cross-validation:

- Policy: global security rules from `configs/policies.yaml`
- Intent: workload expectations from `configs/intents.yaml`
- Context: runtime anomaly signals from syscall metadata

The current eBPF programs use tracepoints, so most events are observe-and-react.
`KILL` verdicts call `Process.Kill()` from userspace. True inline syscall denial
requires moving selected hooks, such as exec and file access, to BPF LSM programs.

## Features

- Syscall monitoring: `execve`, `openat`, `clone`, `unshare`, `mount`, `ptrace`, `socket`
- YAML-based policy and intent configuration
- Decision fusion with `ALLOW`, `ALERT`, `DENY`, and `KILL` verdicts
- Default container scope filter for Kubernetes/container cgroups

## Build in a Linux lab environment

```bash
make bpf
go test ./internal/fusion ./internal/intent
make build
sudo ./bin/patrold \
  --policy configs/policies.yaml \
  --intent configs/intents.yaml \
  --bpf gen/patrol_bpfel.o \
  --scope containers
```

Use `--scope all` for local non-Kubernetes experiments. The default
`containers` mode suppresses host noise from processes such as kubelet,
VS Code server, shells, and node tooling unless their cgroup path looks
containerized. Kubernetes runtime infrastructure processes such as
`containerd-shim` are also ignored in `containers` mode.

## Kubernetes intent materialization

The agent can automatically map Kubernetes pod labels to local cgroup IDs.
It periodically reads pods through `kubectl`, matches each pod against
`selector.matchLabels` in `configs/intents.yaml`, scans `/sys/fs/cgroup` for
the pod UID, and injects the matched intent into the in-memory cgroup intent
table.

```bash
sudo -E ./bin/patrold \
  --scope containers \
  --k8s-intents \
  --k8s-mode kubectl \
  --k8s-sync-interval 10s
```

Use `sudo -E` when your kubeconfig is provided through `KUBECONFIG`.
If you only want pods scheduled on one node:

```bash
sudo -E ./bin/patrold --scope containers --k8s-intents --k8s-node <node-name>
```

If startup fails with a missing BPF program such as `trace_unshare`, the Go
binary and `gen/patrol_bpfel.o` are out of sync. Rebuild the BPF object:

```bash
make clean
make bpf
make build
```

## Safe PoC

Detection validation scripts are in `scripts/poc/`. Start `patrold`, then run
the shell/Python triggers from a disposable pod or with `--scope all` in a local
lab. See `scripts/poc/README.md`.
