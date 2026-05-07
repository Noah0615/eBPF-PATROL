# eBPF-PATROL 기술 보고서 — Part 2: 커널 데이터 수집 및 의도 주입

## 4. 커널 데이터 수집 계층

### 4.1 eBPF Tracepoint (심층 모니터링)

7개의 시스템 콜을 tracepoint로 감시한다. 각 tracepoint는 이벤트 발생 시 프로세스 정보(PID, UID, cgroup_id, comm, 인자)를 수집하여 16MB RingBuffer로 Userspace에 전달한다.

```c
// bpf/patrol.bpf.c — 감시 대상 시스템 콜
SEC("tracepoint/syscalls/sys_enter_execve")   // 프로그램 실행 (shell, 도구)
SEC("tracepoint/syscalls/sys_enter_openat")   // 파일 열기 (/etc/shadow 등)
SEC("tracepoint/syscalls/sys_enter_mount")    // 파일시스템 마운트 (탈출 핵심)
SEC("tracepoint/syscalls/sys_enter_clone")    // 프로세스/namespace 생성
SEC("tracepoint/syscalls/sys_enter_unshare")  // namespace 분리 (탈출 핵심)
SEC("tracepoint/syscalls/sys_enter_ptrace")   // 프로세스 디버깅/조작
SEC("tracepoint/syscalls/sys_enter_socket")   // 네트워크 소켓 생성
```

**이벤트 구조체** (`bpf/common.h`):
```c
struct event {
    __u32 type;        // EVENT_EXEC=1, EVENT_OPEN=2, ...
    __u32 pid, tgid, ppid, uid, gid;
    __u64 cgroup_id;   // ← 컨테이너 식별의 핵심 키
    __u64 timestamp;
    char  comm[16];    // 프로세스 이름 (예: "bash", "runc:[2:INIT]")
    char  arg1[128];   // 실행 파일 경로 또는 열려는 파일 경로
    char  arg2[128];   // mount의 target 등 보조 인자
    __u32 flags;       // open flags, clone flags 등
};
```

### 4.2 eBPF LSM Hook (고속 차단 — Fast Path)

LSM(Linux Security Module) Hook은 tracepoint와 달리 **syscall을 커널 내부에서 직접 차단(`return -1`)**할 수 있다.

#### 4.2.1 실행 차단 (`lsm/bprm_check_security`)
```c
// bpf/patrol.bpf.c:114-143
SEC("lsm/bprm_check_security")
int BPF_PROG(lsm_exec, struct linux_binprm *bprm, int ret) {
    cgroup_id = bpf_get_current_cgroup_id();
    
    // 1단계: intent_flags 맵에서 이 컨테이너의 허용 규칙을 조회
    flags = bpf_map_lookup_elem(&intent_flags, &cgroup_id);
    if (!flags) return 0;  // 등록되지 않은 cgroup → 통과
    
    // 2단계: shell 실행 금지인데 shell을 실행하려 하면 즉시 차단
    if (!flags->allow_shell && is_shell_path(path)) {
        emit_lsm_event(EVENT_EXEC, path, 1);  // 이벤트 보고
        return -1;  // EPERM — 커널 레벨에서 즉시 거부
    }
    return 0;
}
```

#### 4.2.2 파일 접근 차단 (`lsm/file_open`)
```c
// bpf/patrol.bpf.c:145-194
SEC("lsm/file_open")
int BPF_PROG(lsm_file_open, struct file *file, int ret) {
    // hard_deny_names 맵에서 차단 대상 파일명 조회
    // (예: "shadow" → /etc/shadow, "kcore" → /proc/kcore)
    deny = bpf_map_lookup_elem(&hard_deny_names, &deny_key);
    if (deny && *deny) {
        emit_lsm_event(EVENT_OPEN, name, 1);
        return -1;  // 즉시 차단
    }
    
    // docker.sock 접근 차단
    if (!flags->allow_docker_sock && is_docker_sock_name(name)) {
        return -1;
    }
}
```

### 4.3 BPF Maps 구조

| Map 이름 | 타입 | Key | Value | 용도 |
|----------|------|-----|-------|------|
| `intent_flags` | HASH (64K) | `cgroup_id` (u64) | `intent_flags` 구조체 | 컨테이너별 허용 행위 플래그 |
| `hard_deny_names` | HASH (1K) | 파일명+부모디렉토리 | u32 (1=차단) | 정책 기반 무조건 파일 차단 |
| `events` | RINGBUF (16MB) | — | `event` 구조체 | 커널→Userspace 이벤트 전달 |

**`intent_flags` 구조체** (`bpf/common.h`):
```c
struct intent_flags {
    __u32 allow_shell;          // shell 실행 허용 여부
    __u32 allow_namespace_ops;  // namespace 조작 허용 여부
    __u32 allow_privilege_ops;  // ptrace 등 특권 연산 허용 여부
    __u32 allow_docker_sock;    // 컨테이너 런타임 소켓 접근 허용 여부
};
```

---

## 5. 의도(Intent) 주입 파이프라인

쿠버네티스의 워크로드 의도가 커널 eBPF Map에 도달하기까지의 전체 데이터 흐름이다.

```
[개발자가 CRD 작성]
        │
        ▼
┌─────────────────────┐
│ WorkloadIntent CRD  │  "nginx는 shell 금지, mount 금지"
│ (patrol.ebpf.io)    │
└────────┬────────────┘
         │ K8s API Server에 저장
         ▼
┌─────────────────────┐
│ CRD Watcher         │  client-go dynamic informer로 실시간 감시
│ (crd_watcher.go)    │  Add/Update/Delete 이벤트 핸들링
└────────┬────────────┘
         │ Intent 객체로 변환
         ▼
┌─────────────────────┐
│ K8s Watcher          │  Pod Informer로 실행 중인 Pod 감시
│ (watcher.go)         │  Pod labels ↔ Intent selector 매칭
└────────┬────────────┘
         │ Pod UID 추출
         ▼
┌─────────────────────┐
│ Cgroup Scanner       │  /sys/fs/cgroup 트리를 순회하며
│ (cgroup_scanner.go)  │  Pod UID가 포함된 cgroup 디렉토리의
│                      │  inode 번호(= cgroup_id)를 추출
└────────┬────────────┘
         │ cgroup_id → Intent 매핑 완성
         ▼
┌─────────────────────┐
│ IntentFlagUpdater    │  Go의 cilium/ebpf 라이브러리로
│ (intent_flags.go)    │  eBPF Map에 Put(cgroup_id, flags)
└────────┬────────────┘
         │ 커널 메모리에 직접 기록
         ▼
┌─────────────────────┐
│ intent_flags BPF Map │  LSM Hook이 syscall마다
│ (커널 메모리)         │  이 Map을 O(1)로 조회하여 즉시 판정
└─────────────────────┘
```

### 5.1 CRD → Intent 변환 (crd_watcher.go)

```go
// CRD Informer가 WorkloadIntent 변경을 감지하면 호출
func (w *CRDWatcher) handleCRDEvent(obj interface{}, action string) {
    uns := obj.(*unstructured.Unstructured)
    wi := unstructuredToWorkloadIntent(uns)  // JSON → Go 구조체
    converted := crdtypes.ToIntent(wi)       // CRD 스펙 → 내부 Intent 객체
    
    w.intents[key] = converted  // 메모리에 캐시
    w.onChange()                 // 콜백 → IntentSet.Intents 갱신
}
```

### 5.2 Pod ↔ Intent 매칭 (watcher.go)

```go
func (w *Watcher) sync(ctx context.Context) {
    pods := w.source.ListPods(ctx)           // K8s API에서 Pod 목록 조회
    
    for _, pod := range pods {
        // Pod의 labels와 Intent의 selector.matchLabels를 비교
        matched, ok := w.intents.MatchByLabels(pod.Metadata.Labels)
        // 예: pod labels={app:nginx, tier:frontend} 
        //     intent selector={app:nginx} → 매칭!
    }
    
    // Pod UID로 cgroup 트리를 스캔하여 cgroup_id를 찾음
    cgroups := ScanCgroups("/sys/fs/cgroup", uids)
    
    // cgroup_id → MaterializedIntent 매핑 생성 후 eBPF Map에 주입
    w.updater.UpdateIntentFlags(next)
}
```

### 5.3 Cgroup ID 추출 (cgroup_scanner.go)

```go
func ScanCgroups(root string, podUIDs []string) (map[string][]CgroupMatch, error) {
    filepath.WalkDir(root, func(path string, entry fs.DirEntry, ...) {
        for uid, variants := range needles {
            if containsVariant(path, variants) {
                // cgroup 디렉토리의 inode = 커널이 사용하는 cgroup_id
                syscall.Stat(path, &stat)
                matches[uid] = append(matches[uid], CgroupMatch{
                    CgroupID: uint64(stat.Ino),  // ← 이것이 BPF Map의 Key
                    Path:     path,
                })
            }
        }
    })
}
```

---

## 6. 오탐 감소 메커니즘

### 6.1 Grace Period (유예 기간)
컨테이너 시작 직후 라이브러리 로딩, 설정 파일 읽기 등의 정상 노이즈가 발생한다. `gracePeriodSeconds` 동안은 위반을 탐지하되 차단하지 않는다.

```go
// internal/intent/evaluator.go
elapsed := time.Now().Unix() - materialized.MaterializedAt
if elapsed < int64(graceSec) {
    return IntentResult{Verdict: IntentUnknown, Reason: "grace period active"}
}
```

### 6.2 Enforcement Mode (시행 모드)
- **enforce**: 위반 시 즉시 차단
- **audit**: 위반을 로그만 남기고 차단하지 않음 (안전한 정책 테스트)
- **learn**: 행동 패턴을 관찰하여 베이스라인 구축

### 6.3 Priority 기반 매칭
여러 Intent가 같은 Pod에 매칭될 때, 가장 높은 priority의 Intent만 적용하여 모호한 판정을 방지한다.

### 6.4 TTL 자동 만료
디버깅용 임시 권한은 `ttlSeconds` 후 자동 만료되어 과도한 권한이 남아있지 않도록 한다.

### 6.5 Scope Filter
호스트 프로세스, 컨테이너 런타임(containerd, kubelet, runc) 등의 정상 인프라 노이즈를 사전 필터링한다.
