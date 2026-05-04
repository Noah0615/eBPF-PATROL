# eBPF Map Fast Path와 LSM 즉시 차단

이 문서는 현재 구현된 1번, 2번 단계만 쉽게 설명한다.

## 1. eBPF Map Fast Path

Kubernetes watcher는 pod label을 보고 intent를 찾는다.

예를 들어 pod에 이런 label이 있으면:

```yaml
app: nginx
```

`configs/intents.yaml`의 `web-server-intent`와 매칭된다.

그 다음 watcher는 `/sys/fs/cgroup`에서 이 pod의 cgroup ID를 찾고,
아래처럼 eBPF map에 넣는다.

```text
intent_flags[cgroup_id] = {
  allow_shell: 0,
  allow_namespace_ops: 0,
  allow_privilege_ops: 0,
  allow_docker_sock: 0
}
```

이 map은 커널 안의 eBPF 프로그램이 바로 읽을 수 있다.

## 2. BPF LSM Inline Deny

LSM은 Linux Security Module의 줄임말이다.
커널이 중요한 보안 결정을 내리기 직전에 호출하는 문이라고 생각하면 된다.

이번 구현에서는 두 문에 eBPF를 붙였다.

- `bprm_check_security`: 프로그램 실행 직전
- `file_open`: 파일을 열기 직전

예를 들어 nginx 컨테이너가 `/bin/bash`를 실행하려 하면:

1. 커널이 실행 직전에 eBPF LSM 프로그램을 부른다.
2. eBPF가 현재 cgroup ID를 확인한다.
3. `intent_flags` map에서 이 cgroup의 `allow_shell` 값을 읽는다.
4. `allow_shell`이 0이면 `-EPERM`을 반환한다.
5. 커널이 shell 실행을 바로 거절한다.

즉, 이 단계부터는 userspace가 나중에 kill하는 것보다 빠르게 막을 수 있다.

## 현재 커널 fast path가 막는 것

- `allow_shell=false`인 cgroup에서 shell 실행
- `allow_docker_sock=false`인 cgroup에서 docker.sock open
- `/etc/shadow` open
- `/proc/kcore` open

주의: `file_open` LSM fast path는 verifier 제약 때문에 전체 경로가 아니라
파일 이름 basename을 먼저 본다. 그래서 커널 fast path는 `shadow`, `kcore`,
`docker.sock`처럼 빠른 차단 신호를 처리하고, 전체 경로 설명과 자세한
분석은 기존 tracepoint/userspace 엔진이 계속 담당한다.

## 아직 userspace가 맡는 것

- 상세한 3-way decision fusion
- 설명 가능한 로그
- context anomaly 판단
- Kubernetes pod 이름, namespace, label 기반 설명
- mount/unshare/ptrace 같은 observe-and-react 이벤트

## 실행 조건

BPF LSM은 커널 지원이 필요하다.

실습 환경에서 확인:

```bash
cat /sys/kernel/security/lsm
```

출력 안에 `bpf`가 있어야 한다.

없으면 LSM attach가 실패할 수 있다.
