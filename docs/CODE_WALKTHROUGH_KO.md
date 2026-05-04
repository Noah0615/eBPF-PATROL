# INTENT-BPF 코드 쉬운 설명

이 프로젝트는 컨테이너 안에서 일어나는 행동을 보고,
"이 행동이 원래 해도 되는 일인가?"를 판단하는 탐지기다.

쉽게 말하면 학교 교문 앞 선생님처럼 동작한다.

- 학생이 누구인지 본다: 컨테이너, 프로세스, cgroup
- 뭘 하려는지 본다: exec, open, mount, unshare, ptrace
- 규칙에 맞는지 본다: policy
- 이 학생이 원래 해도 되는 일인지 본다: intent
- 지금 상황이 이상한지 본다: context
- 마지막으로 통과, 경고, 거절, 퇴장 중 하나를 고른다: fusion

## 1. eBPF 코드

파일: `bpf/patrol.bpf.c`

이 코드는 커널 안에 들어가서 syscall이 발생하는 순간을 본다.

예를 들어 컨테이너 안에서 이런 일이 생기면:

```bash
/bin/bash
cat /etc/shadow
unshare -m
mount -t tmpfs test /mnt
strace /bin/true
```

eBPF가 "방금 이런 syscall이 들어왔다"는 작은 쪽지를 만든다.
그 쪽지에는 이런 정보가 들어간다.

- PID: 누가 했는가
- UID: 어떤 사용자 권한인가
- Comm: 프로세스 이름이 뭔가
- CgroupID: 어느 컨테이너 쪽인가
- Arg1/Arg2: 어떤 파일이나 명령을 대상으로 했는가
- Flags: syscall 옵션은 뭔가

그 다음 이 쪽지를 ringbuf라는 통로로 Go 프로그램에게 보낸다.

## 2. 이벤트 읽기

파일:

- `internal/event/types.go`
- `internal/event/reader.go`

이 코드는 eBPF가 보낸 쪽지를 Go 구조체로 바꾼다.

커널에서는 바이트 덩어리로 오기 때문에 사람이 읽기 어렵다.
그래서 Go에서 이런 모양으로 바꾼다.

```go
Event{
    Type: exec,
    Pid: 1234,
    Comm: "nginx",
    Arg1: "/bin/bash",
    CgroupID: 7472,
}
```

이제 다른 코드들이 이 이벤트를 쉽게 검사할 수 있다.

## 3. Scope Filter

파일: `internal/scope/filter.go`

이 코드는 "우리가 볼 이벤트인가?"를 먼저 고른다.

처음에는 host의 VS Code, kubelet, containerd-shim 같은 이벤트까지
너무 많이 잡혀서 로그가 쏟아졌다. 그래서 문지기를 만들었다.

기본값 `--scope containers`에서는:

- 컨테이너 cgroup처럼 보이는 이벤트는 본다.
- host 개발 도구 이벤트는 줄인다.
- containerd-shim, kubelet 같은 런타임 인프라 프로세스는 제외한다.

로컬에서 일부러 테스트할 때는:

```bash
sudo ./bin/patrold --scope all
```

이렇게 하면 host 이벤트까지 볼 수 있다.

## 4. Policy Engine

파일:

- `configs/policies.yaml`
- `internal/policy/evaluator.go`
- `internal/policy/matcher.go`

Policy는 관리자가 적어둔 보안 규칙이다.

예를 들면:

- `/etc/shadow`는 열면 안 된다.
- `/proc/kcore`는 열면 안 된다.
- docker.sock은 열면 안 된다.
- mount, unshare, ptrace는 수상하다.

Policy Engine은 이벤트를 보고 YAML 규칙과 비교한다.

결과는 보통 세 가지다.

- `ALLOW`: 정책상 문제 없음
- `SUSPICIOUS`: 수상해서 알림 필요
- `DENY`: 정책상 위험함

## 5. Intent Engine

파일:

- `configs/intents.yaml`
- `internal/intent/evaluator.go`

Intent는 "이 컨테이너는 원래 이런 일을 해야 한다"는 약속이다.

예를 들어 nginx 컨테이너라면:

- 웹서버 실행은 정상
- shell 실행은 이상함
- mount는 이상함
- ptrace는 이상함
- docker.sock 접근은 이상함

반대로 debug pod라면:

- shell 실행은 정상일 수 있음

그래서 같은 `/bin/bash` 실행이라도,
어떤 컨테이너에서 실행됐는지에 따라 결과가 달라진다.

이게 이 프로젝트의 핵심이다.

## 6. Context Resolver

파일: `internal/contextcheck/resolver.go`

Context는 "지금 상황이 이상한가?"를 본다.

예를 들면:

- nginx라는 이름의 프로세스가 갑자기 shell을 실행하면 이상하다.
- `/etc/shadow`를 열면 이상하다.
- `/proc/kcore`를 열면 이상하다.
- mount를 하면 이상하다.
- unshare를 하면 이상하다.
- root가 아닌 사용자가 ptrace를 하면 더 이상하다.

반대로 정상 노이즈도 걸러낸다.

- `/lib/...`
- `/usr/lib/...`
- `/etc/ld.so.cache`
- locale 파일
- `/proc/*/stat`
- read-only `/sys/fs/cgroup/...`

이런 파일들은 프로그램이 평소에도 자주 읽으므로 경고하지 않는다.

## 7. Decision Fusion

파일: `internal/fusion/fusion.go`

Fusion은 세 명의 심사위원 의견을 합쳐 최종 판결을 낸다.

세 심사위원은 다음과 같다.

- Policy: 규칙상 위험한가?
- Intent: 이 컨테이너가 해도 되는 행동인가?
- Context: 지금 상황이 이상한가?

최종 판결은 다음 중 하나다.

- `ALLOW`: 허용
- `ALERT`: 경고
- `DENY`: 차단 판정
- `KILL`: 프로세스 종료

예시:

```text
Policy: ALLOW
Intent: DENY
Context: ANOMALOUS
Final: KILL
```

뜻:

"관리자 정책에는 직접 걸리지 않았지만,
nginx가 하면 안 되는 shell 실행이고,
상황도 이상하므로 프로세스를 종료한다."

## 8. Analyzer

파일: `internal/analyzer/analyzer.go`

Analyzer는 전체 흐름을 연결하는 재판장이다.

순서는 다음과 같다.

1. Scope Filter로 볼 이벤트인지 확인한다.
2. Policy Engine에게 물어본다.
3. Intent Engine에게 물어본다.
4. Context Resolver에게 물어본다.
5. Fusion으로 최종 verdict를 만든다.
6. 필요하면 로그를 찍고, KILL이면 프로세스를 종료한다.

## 9. PoC 스크립트

폴더: `scripts/poc/`

탐지가 되는지 확인하기 위한 안전한 테스트 코드다.

- `patrol_poc.sh`: 여러 syscall을 일부러 발생시킨다.
- `nginx_shell_exec.py`: nginx처럼 보이는 프로세스가 shell을 실행하게 만든다.
- `poc-pod.yaml`: Kubernetes에서 테스트할 disposable pod다.

실제 탈출 exploit은 아니고,
탐지기가 제대로 보는지 확인하기 위한 신호 발생기다.

## 10. 지금 버전의 중요한 한계

현재 eBPF는 tracepoint 기반이다.

그래서 대부분의 syscall은:

1. syscall이 들어온다.
2. eBPF가 관찰한다.
3. userspace가 판단한다.
4. 위험하면 로그를 찍거나 프로세스를 kill한다.

즉, 커널 안에서 syscall을 바로 `-EPERM`으로 막는 구조는 아직 아니다.

진짜 inline 차단을 하려면 다음 단계에서 BPF LSM hook을 추가해야 한다.

우선 적용하기 좋은 LSM 대상은:

- exec 실행 차단
- file open 차단

이다.
