# eBPF-PATROL 기술 보고서 — Part 3: 3-Way 분석 엔진 및 실제 탐지 시나리오

## 7. 3-Way Cross-Validation 엔진

커널에서 올라온 이벤트는 Userspace의 **Analyzer**에서 3개의 독립적 평가 축을 통과한 후, **Fusion Engine**이 최종 판정을 내린다.

### 7.1 평가 축 1: Policy Evaluator (정적 규칙)

관리자가 `configs/policies.yaml`에 정의한 보편적 보안 규칙이다. 워크로드의 의도와 무관하게 적용되는 "절대 규칙"에 해당한다.

| 정책 이름 | 감시 대상 | 액션 | 설명 |
|----------|---------|------|------|
| `detect-shell-exec` | exec(/bash, /sh) | log | shell 실행 탐지 (최종 판정은 Intent+Context에 위임) |
| `deny-shadow-access` | open(/etc/shadow) | deny | 인증 정보 파일 접근 무조건 차단 |
| `deny-kcore-access` | open(/proc/kcore) | deny | 커널 메모리 접근 무조건 차단 |
| `deny-docker-sock-access` | open(docker.sock) | deny | 런타임 소켓 접근 무조건 차단 |
| `deny-core-pattern-write` | open(core_pattern) | kill | CVE-2025-31133 공격 경로 차단 |
| `detect-mount-syscall` | mount | alert | 파일시스템 마운트 탐지 |
| `detect-unshare-namespace` | unshare | alert | 네임스페이스 분리 탐지 |

**판정 결과**: `PolicyAllow` / `PolicyDeny` / `PolicySuspicious`

### 7.2 평가 축 2: Intent Evaluator (워크로드 의도)

쿠버네티스 CRD로 선언된 해당 컨테이너의 "설계 의도"와 실제 행동을 비교한다.

```go
// internal/intent/evaluator.go — evaluate() 함수
func (i Intent) evaluate(e *event.Event) IntentResult {
    switch e.Type {
    case EventExec:
        // shell 허용 여부 확인
        if isShell(e.Arg1) && !i.Spec.AllowShell {
            return IntentDeny  // "web-server does not allow shell execution"
        }
        // 예상 프로세스 목록 확인
        if len(i.Spec.ExpectedProcesses) > 0 && !containsAny(e.Arg1, ...) {
            return IntentDeny  // "web-server does not expect process /usr/bin/curl"
        }
    case EventMount:
        if !i.Spec.AllowNamespaceOps {
            return IntentDeny  // "web-server does not allow mount operations"
        }
    case EventPtrace:
        if !i.Spec.AllowPrivilegeOps {
            return IntentDeny  // "web-server does not allow ptrace"
        }
    }
}
```

**판정 결과**: `IntentAllow` / `IntentDeny` / `IntentUnknown`

### 7.3 평가 축 3: Context Resolver (런타임 문맥)

이벤트의 전후 맥락을 분석하여 "지금 상황이 정상인가?"를 판단한다.

| 검사 항목 | 판정 | 예시 |
|----------|------|------|
| shell을 실행한 부모가 shell이 아님 | ANOMALOUS (0.9) | nginx 프로세스가 /bin/bash 실행 |
| 리버스 셸 도구 실행 | SUSPICIOUS (0.7) | nc, python, socat 실행 |
| 민감 경로 쓰기 시도 | ANOMALOUS (0.95) | /sys/fs/cgroup/release_agent 쓰기 |
| 10초 내 같은 이벤트 200회 이상 | SUSPICIOUS (0.65) | brute-force 시도 |
| 라이브러리/locale 파일 읽기 | NORMAL (0.0) | 정상 앱 동작 |

**판정 결과**: `ContextNormal` / `ContextSuspicious` / `ContextAnomalous`

### 7.4 Fusion Engine (최종 판정)

세 축의 판정을 조합하여 4단계 최종 판정을 내린다.

```
┌──────────────┬──────────────┬──────────────┬──────────┬────────────┐
│ Policy       │ Intent       │ Context      │ 최종판정  │ Confidence │
├──────────────┼──────────────┼──────────────┼──────────┼────────────┤
│ DENY         │ (any)        │ (any)        │ DENY     │ 1.00       │
│ ALLOW        │ DENY         │ ANOMALOUS    │ KILL     │ 0.95       │
│ ALLOW        │ DENY         │ NORMAL       │ DENY     │ 0.90       │
│ ALLOW        │ ALLOW        │ ANOMALOUS    │ DENY     │ 0.80       │
│ ALLOW        │ ALLOW        │ SUSPICIOUS   │ ALERT    │ 0.70       │
│ ALLOW        │ ALLOW        │ NORMAL       │ ALLOW    │ 1.00       │
│ ALLOW        │ UNKNOWN      │ ANOMALOUS    │ DENY     │ 0.75       │
│ SUSPICIOUS   │ ALLOW        │ ANOMALOUS    │ DENY     │ 0.85       │
│ ALLOW        │ UNKNOWN      │ NORMAL       │ ALLOW    │ 0.50       │
└──────────────┴──────────────┴──────────────┴──────────┴────────────┘
```

**핵심 설계**: Intent가 DENY이고 Context가 ANOMALOUS인 조합이 **KILL**(0.95)로 가장 강력한 판정을 받는다. 이는 "설계 의도를 위반했고, 런타임 상황도 비정상"인 경우로, 공격 가능성이 가장 높다.

---

## 8. 이중 방어 체계 (Dual-Path Enforcement)

| 경로 | 위치 | 속도 | 능력 | 용도 |
|------|------|------|------|------|
| **Fast Path** | 커널 LSM Hook | ~μs | syscall 직접 거부(`return -1`) | 명백한 위반 즉시 차단 |
| **Deep Path** | Userspace Analyzer | ~ms | 3-Way 교차 검증, SIGKILL | 복합 위협 심층 분석 |

Fast Path는 BPF Map만 조회하여 O(1) 판정을 내리므로 성능 오버헤드가 극히 낮다. Deep Path는 Policy+Intent+Context를 모두 교차 검증하여 복합적 위협과 미등록 컨테이너를 감지한다.

---

## 9. 실제 공격 탐지 시나리오

### 9.1 시나리오: nginx 컨테이너 내 shell 실행

```
1. 공격자가 nginx 취약점을 이용하여 /bin/bash 실행 시도
2. 커널 LSM Hook 발동:
   → intent_flags[cgroup_id].allow_shell == false
   → return -1 (EPERM) → 커널에서 즉시 차단
3. 동시에 Tracepoint가 이벤트를 RingBuffer로 전송
4. Userspace Analyzer 3-Way 판정:
   → Policy: ALLOW (detect-shell-exec, action=log)
   → Intent: DENY (web-server does not allow shell execution)
   → Context: ANOMALOUS (nginx 프로세스가 shell 실행 → 비정상)
   → Fusion: KILL (Confidence 0.95)
5. 출력: 💀 KILL: Policy=ALLOW Intent=DENY(web-server) Context=ANOMALOUS
```

### 9.2 시나리오: 디버그 Pod에서 정당한 shell 실행

```
1. 관리자가 debug-pod (allowShell=true, mode=audit)에서 /bin/sh 실행
2. 커널 LSM Hook:
   → intent_flags[cgroup_id].allow_shell == true → 통과
3. Userspace Analyzer 3-Way 판정:
   → Policy: ALLOW (detect-shell-exec, action=log)
   → Intent: ALLOW (debug-pod allows shell execution)
   → Context: NORMAL (정상 세션에서 shell 실행)
   → Fusion: ALLOW (Confidence 1.0)
4. 결과: 정상 허용 → 오탐 없음
```

### 9.3 시나리오: CVE-2025-31133 컨테이너 탈출

```
1. 공격자가 runc maskedPaths race condition으로 /proc/sys/kernel/core_pattern 변조 시도
2. 컨테이너 내에서 core_pattern 파일 open 발생
3. Userspace Analyzer 3-Way 판정:
   → Policy: KILL (deny-core-pattern-write 정책 매칭)
   → Fusion: 즉시 KILL (Confidence 1.0, Policy DENY는 최우선)
4. 프로세스 SIGKILL → 공격 실패
```

---

## 10. Admission Webhook (사전 방어)

Pod가 생성되기 전에 WorkloadIntent와의 정합성을 검증하는 **사전 방어선**이다.

```yaml
# deploy/webhook.yaml
webhooks:
  - name: pod-intent.patrol.ebpf.io
    failurePolicy: Ignore   # Webhook 장애 시 Pod 생성을 막지 않음
    rules:
      - operations: ["CREATE", "UPDATE"]
        resources: ["pods"]
    namespaceSelector:
      matchExpressions:
        - key: kubernetes.io/metadata.name
          operator: NotIn
          values: ["kube-system", "patrol-system"]  # 시스템 NS 제외
```

Webhook은 Pod 생성 요청을 가로채서:
1. 매칭되는 WorkloadIntent가 있는지 확인
2. Pod의 `SecurityContext`가 Intent와 모순되지 않는지 검증
3. Intent annotation을 Pod에 자동 주입

---

## 11. 한계점 및 향후 과제

| 한계 | 설명 | 개선 방향 |
|------|------|----------|
| 수동 runc 컨테이너 미탐지 | K8s를 거치지 않고 직접 runc로 생성한 컨테이너는 cgroup 식별 실패 | cgroup 패턴 확장 또는 `--scope all` 모드 사용 |
| Intent 수동 작성 필요 | 개발자가 WorkloadIntent CRD를 직접 작성해야 함 | learn 모드로 자동 베이스라인 생성 |
| 단일 노드 테스트 한정 | 현재 실험은 단일 노드 Vagrant 환경에서 수행 | 다중 노드 클러스터에서 성능 벤치마크 필요 |
| Tracepoint 기반 차단 지연 | Tracepoint는 syscall을 직접 막지 못하고 SIGKILL 방식 사용 | LSM Hook 커버리지 확대 |

---

## 12. 프로젝트 디렉토리 구조

```
ebpf-patrol/
├── bpf/
│   ├── patrol.bpf.c          # eBPF 커널 프로그램 (Tracepoint + LSM Hook)
│   ├── common.h              # 커널-유저 공유 데이터 구조체
│   └── vmlinux.h             # 커널 타입 정의
├── cmd/patrold/main.go       # CLI 엔트리포인트
├── configs/
│   ├── policies.yaml         # 정적 보안 정책 (10개 규칙)
│   └── intents.yaml          # YAML 기반 워크로드 의도 (CRD 대안)
├── deploy/
│   ├── crd/workloadintent-crd.yaml  # WorkloadIntent CRD 정의
│   ├── crd/samples/                 # CRD 샘플 (web-server, debug-pod 등)
│   ├── daemonset.yaml               # 전 노드 배포 DaemonSet
│   ├── rbac.yaml                    # 권한 설정
│   └── webhook.yaml                 # Admission Webhook 설정
├── internal/
│   ├── analyzer/analyzer.go         # 3-Way 분석 엔진 + 로그 출력
│   ├── app/app.go                   # 애플리케이션 라이프사이클 관리
│   ├── bpf/                         # eBPF Map 조작 (intent_flags, policy_map)
│   ├── contextcheck/resolver.go     # Context 평가기 (런타임 이상 탐지)
│   ├── enforcer/action.go           # Userspace 강제 집행 (SIGKILL)
│   ├── event/                       # 커널 이벤트 파싱
│   ├── fusion/fusion.go             # 3-Way 판정 합산 엔진
│   ├── intent/                      # Intent 평가기 + 타입 정의
│   ├── k8s/                         # CRD Watcher, Pod Informer, Cgroup Scanner
│   ├── policy/                      # Policy 평가기
│   ├── scope/filter.go              # 노이즈 필터링 (컨테이너 식별)
│   ├── verdict/types.go             # 판정 타입 정의 (4단계)
│   └── webhook/                     # Admission Webhook 핸들러
└── Makefile                         # 빌드/배포 자동화
```
