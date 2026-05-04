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
- **WorkloadIntent CRD** for Kubernetes-native intent declaration
- **Validating Admission Webhook** for pre-binding intents at pod creation
- Decision fusion with `ALLOW`, `ALERT`, `DENY`, and `KILL` verdicts
- Default container scope filter for Kubernetes/container cgroups
- **False-positive reduction**: grace period, enforcement modes, priority-based matching

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
Runtime setup events from `runc:*` and runc self-mount paths are suppressed so
pod creation, `kubectl exec`, and `kubectl cp` do not drown out workload events.

## Kubernetes intent materialization

### Mode 1: kubectl (polling)

The agent periodically reads pods through `kubectl`, matches each pod against
`selector.matchLabels` in `configs/intents.yaml`, scans `/sys/fs/cgroup` for
the pod UID, and injects the matched intent into the in-memory cgroup intent
table and the `intent_flags` eBPF map.

```bash
sudo -E ./bin/patrold \
  --scope containers \
  --k8s-intents \
  --k8s-mode kubectl \
  --k8s-sync-interval 10s
```

### Mode 2: CRD (informer-driven, recommended)

Instead of YAML files and polling, use Kubernetes-native **WorkloadIntent CRD**
with client-go informers for real-time, event-driven intent materialization.

#### 1. Deploy the CRD

```bash
make deploy-crd
# or: kubectl apply -f deploy/crd/workloadintent-crd.yaml
```

#### 2. Create WorkloadIntent resources

```yaml
apiVersion: patrol.ebpf.io/v1alpha1
kind: WorkloadIntent
metadata:
  name: web-server
  namespace: default
spec:
  selector:
    matchLabels:
      app: nginx
  allowShell: false
  allowNamespaceOps: false
  allowPrivilegeOps: false
  allowDockerSock: false
  expectedProcesses: ["nginx"]
  enforcementMode: enforce   # enforce | audit | learn
  gracePeriodSeconds: 15      # startup noise 무시
  priority: 100               # 높을수록 우선
```

```bash
kubectl apply -f deploy/crd/samples/
kubectl get workloadintents -A   # or: kubectl get wi -A
```

#### 3. Run patrold in CRD mode

```bash
sudo -E ./bin/patrold \
  --scope containers \
  --k8s-intents \
  --k8s-mode crd \
  --k8s-sync-interval 5s
```

#### 4. Enable Admission Webhook (optional)

```bash
# TLS 인증서 생성
make webhook-cert

# RBAC, Webhook 배포
make deploy

# 또는 직접 실행 시 webhook 플래그 추가
sudo -E ./bin/patrold \
  --k8s-intents --k8s-mode crd \
  --webhook-enable \
  --webhook-port 8443 \
  --webhook-cert-dir /certs
```

The webhook:
- Adds `patrol.ebpf.io/matched-intent` annotation to pods at creation
- Warns when no WorkloadIntent matches a pod's labels
- Validates `requireApproval` for privileged diagnostic intents
- Checks securityContext contradictions (e.g., privileged pod + no allowPrivilegeOps)

## False-positive reduction

The system includes several mechanisms to minimize false positives:

| Mechanism | Description |
|-----------|-------------|
| **Grace Period** | `gracePeriodSeconds` ignores violations during container startup (library loading, config reads) |
| **Enforcement Mode** | `audit` mode logs violations without blocking; `learn` mode builds baselines |
| **Priority** | When multiple intents match, highest priority wins — prevents conflicting decisions |
| **matchExpressions** | Precise label matching with In/NotIn/Exists/DoesNotExist operators |
| **TTL** | Auto-expire debug/diagnostic intents to prevent stale permissions |
| **Webhook Pre-validation** | Catches securityContext misconfigurations before pods start |
| **Context Resolver** | Runtime infrastructure noise (runc, containerd-shim) is filtered out |

## Kernel fast path and LSM deny

When Kubernetes intent materialization is enabled, the agent writes compact
intent flags into the eBPF map:

```text
cgroup_id -> {
  allow_shell,
  allow_namespace_ops,
  allow_privilege_ops,
  allow_docker_sock
}
```

The BPF LSM hooks use this map for immediate kernel decisions:

- `lsm/bprm_check_security`: denies shell execution when `allow_shell=false`
- `lsm/file_open`: denies docker.sock when `allow_docker_sock=false`
- `lsm/file_open`: hard-denies `/etc/shadow` and `/proc/kcore`

This is the first kernel-side fast path. The userspace 3-way engine still runs
for explainability and telemetry.

Admin policy is also injected into an eBPF map. `deny` policies for `open`
events are converted to compact `parent/name` keys:

```text
/etc/shadow          -> etc/shadow
/proc/kcore          -> proc/kcore
/var/run/docker.sock -> run/docker.sock
```

Those targets are stored in `hard_deny_names`, and `lsm/file_open` checks that map
before allowing the open.

BPF LSM requires kernel support. Check the lab kernel with:

```bash
cat /sys/kernel/security/lsm
```

The output should include `bpf`. If LSM attach fails, enable BPF LSM support in
the kernel or boot with an LSM list that includes `bpf`.

If startup fails with a missing BPF program such as `trace_unshare`, the Go
binary and `gen/patrol_bpfel.o` are out of sync. Rebuild the BPF object:

```bash
make clean
make bpf
make build
```

## Project structure

```
eBPF-PATROL/
├── bpf/                         # eBPF C programs (kernel side)
│   ├── patrol.bpf.c             # Tracepoint + LSM hooks
│   └── common.h                 # Shared structs (event, intent_flags)
├── cmd/patrold/                 # CLI entrypoint
├── configs/                     # YAML-based policy and intent files
├── deploy/                      # Kubernetes deployment manifests
│   ├── crd/                     # WorkloadIntent CRD + samples
│   ├── rbac.yaml                # ServiceAccount, ClusterRole
│   ├── webhook.yaml             # ValidatingWebhookConfiguration
│   └── daemonset.yaml           # DaemonSet for patrold
├── internal/
│   ├── analyzer/                # 3-way cross-validation orchestrator
│   ├── app/                     # Application lifecycle
│   ├── bpf/                     # eBPF object loader, map updaters
│   ├── contextcheck/            # Context resolver (Axis 3)
│   ├── enforcer/                # SIGKILL enforcement
│   ├── event/                   # Ring buffer event reader
│   ├── fusion/                  # Decision fusion engine
│   ├── intent/                  # Intent engine (Axis 2)
│   ├── k8s/                     # Kubernetes integration
│   │   ├── crd/                 # WorkloadIntent CRD types
│   │   ├── crd_watcher.go       # CRD informer
│   │   ├── informer_source.go   # Pod informer
│   │   ├── watcher.go           # Intent materializer
│   │   └── source.go            # PodSource interface
│   ├── policy/                  # Policy engine (Axis 1)
│   ├── scope/                   # Container scope filter
│   ├── verdict/                 # Verdict types
│   └── webhook/                 # Admission webhook
│       ├── handler.go           # Pod validation logic
│       ├── lookup.go            # IntentLookup adapter
│       └── server.go            # HTTPS server
└── scripts/
    ├── gen-webhook-cert.sh      # Dev TLS cert generator
    └── poc/                     # Detection validation scripts
```

## Safe PoC

Detection validation scripts are in `scripts/poc/`. Start `patrold`, then run
the shell/Python triggers from a disposable pod or with `--scope all` in a local
lab. See `scripts/poc/README.md`.
