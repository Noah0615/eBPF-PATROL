# eBPF-PATROL 기술 보고서 — Part 1: 시스템 개요 및 아키텍처

## 1. 시스템 개요

**eBPF-PATROL**은 Kubernetes 환경에서 컨테이너 탈출(Container Escape) 공격을 실시간으로 탐지하고 차단하는 커널 수준 보안 시스템이다. 핵심 혁신은 **"워크로드 의도 기반 3-Way Cross-Validation"** 아키텍처로, 쿠버네티스가 관리하는 워크로드의 설계 의도(Intent)를 eBPF Map에 주입하여 커널 레벨에서 실시간으로 허용/차단 판정을 수행한다.

### 1.1 해결하려는 문제

기존 컨테이너 보안 도구(Falco, Tetragon 등)는 **시그니처 기반** 또는 **정적 정책 기반**으로 동작하여 다음과 같은 한계를 가진다:

| 한계 | 설명 |
|------|------|
| 높은 오탐률 | 디버깅 Pod에서 정당한 shell 실행도 공격으로 탐지 |
| 문맥 부재 | "누가 왜 이 Pod를 만들었는가"를 모름 |
| 느린 대응 | 유저스페이스에서 이벤트를 수집 후 판단 → 이미 공격이 완료될 수 있음 |

eBPF-PATROL은 **Kubernetes의 의도(Intent)**를 커널에 직접 주입함으로써 이 문제를 해결한다.

### 1.2 핵심 설계 원칙

1. **Identity-Aware Kernel Enforcement**: 컨테이너의 "정체성"(역할, 허용 행위)을 커널 메모리에 보관하여 syscall 발생 즉시 판단
2. **3-Way Cross-Validation**: Policy(규칙) + Intent(의도) + Context(문맥) 세 축의 교차 검증으로 오탐 최소화
3. **Dual-Path Enforcement**: 커널 LSM Hook(고속 차단) + Userspace Analyzer(심층 분석) 이중 방어

---

## 2. 전체 아키텍처

시스템은 3개 계층으로 구성된다:

```
┌─────────────────────────────────────────────────────────────────┐
│                    Kubernetes Control Plane                      │
│  ┌──────────────┐  ┌───────────────┐  ┌──────────────────────┐  │
│  │ WorkloadIntent│  │ Pod Lifecycle │  │ Admission Webhook    │  │
│  │ CRD (v1alpha1)│  │ (Informer)   │  │ (ValidatingWebhook)  │  │
│  └──────┬───────┘  └──────┬────────┘  └──────────┬───────────┘  │
│         │                 │                      │              │
├─────────┼─────────────────┼──────────────────────┼──────────────┤
│         ▼                 ▼                      ▼              │
│                   Userspace Agent (patrold)                      │
│  ┌─────────────┐  ┌────────────────┐  ┌─────────────────────┐  │
│  │ CRD Watcher │  │ K8s Watcher    │  │ 3-Way Analyzer      │  │
│  │ (Informer)  │→ │ (Materializer) │  │ ┌───────┬────┬────┐ │  │
│  └─────────────┘  └───────┬────────┘  │ │Policy │Int.│Ctx.│ │  │
│                           │           │ └───┬───┴──┬─┴──┬─┘ │  │
│                           │           │     └──────┼────┘   │  │
│                           │           │      Fusion Engine  │  │
│                           │           └──────────┬──────────┘  │
│                           ▼                      ▼              │
│                    eBPF Map Update          Enforcer (SIGKILL)  │
├───────────────────────────┼──────────────────────┼──────────────┤
│                    Linux Kernel                                  │
│  ┌─────────────────┐  ┌──────────────┐  ┌───────────────────┐  │
│  │ intent_flags Map│  │ LSM Hooks    │  │ Tracepoints       │  │
│  │ (BPF_MAP_HASH) │← │ bprm_check   │  │ sys_enter_execve  │  │
│  │                 │  │ file_open    │  │ sys_enter_openat  │  │
│  └─────────────────┘  └──────────────┘  │ sys_enter_mount   │  │
│                                         │ sys_enter_clone   │  │
│                                         │ sys_enter_unshare │  │
│                                         │ sys_enter_ptrace  │  │
│                                         └───────┬───────────┘  │
│                                                 │              │
│                                          RingBuffer → Userspace│
└─────────────────────────────────────────────────────────────────┘
```

### 2.1 계층별 역할 요약

| 계층 | 역할 | 핵심 컴포넌트 |
|------|------|--------------|
| **Kubernetes** | 워크로드 의도 선언, Pod 라이프사이클 관리 | WorkloadIntent CRD, Admission Webhook |
| **Userspace** | 의도 동기화, 심층 분석, 최종 판정 | CRD Watcher, K8s Watcher, 3-Way Analyzer |
| **Kernel** | 실시간 이벤트 수집, 고속 차단 | eBPF Tracepoints, LSM Hooks, BPF Maps |

---

## 3. 배포 아키텍처

### 3.1 DaemonSet 기반 전 노드 배포

각 Kubernetes 노드에 `patrol-agent` Pod가 하나씩 배포된다:

```yaml
# deploy/daemonset.yaml
spec:
  template:
    spec:
      hostPID: true          # 호스트 PID namespace 접근 → 프로세스 SIGKILL 용
      tolerations:
        - operator: Exists   # 모든 노드(Master 포함)에 배포
      containers:
        - name: patrold
          securityContext:
            privileged: true # eBPF 프로그램 커널 로드에 필수
          volumeMounts:
            - name: sys-fs-cgroup        # cgroup ID 스캔용
              mountPath: /sys/fs/cgroup
            - name: sys-kernel-debug     # eBPF 디버깅용
              mountPath: /sys/kernel/debug
            - name: proc                 # 프로세스 정보 조회용
              mountPath: /host/proc
```

**설계 근거:**
- `privileged: true` — eBPF 프로그램을 커널에 로드(`bpf()` syscall)하기 위해 `CAP_BPF`, `CAP_SYS_ADMIN` 권한 필요
- `hostPID: true` — Userspace Enforcer가 악성 프로세스에 `SIGKILL`을 보내기 위해 호스트 PID namespace 접근 필요
- `tolerations: Exists` — Master 노드 포함 클러스터 전체를 감시망에 포함

### 3.2 RBAC 및 네임스페이스

```yaml
# deploy/rbac.yaml
- apiGroups: ["patrol.ebpf.io"]
  resources: ["workloadintents", "workloadintents/status"]
  verbs: ["get", "list", "watch", "update", "patch"]
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["get", "list", "watch"]
```

`patrol-system` 네임스페이스에 격리 배포되며, ClusterRole을 통해 모든 네임스페이스의 Pod와 WorkloadIntent CRD를 감시할 권한을 가진다.
