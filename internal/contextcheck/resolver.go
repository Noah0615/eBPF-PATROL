package contextcheck

import (
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"ebpf-patrol/internal/event"
	"ebpf-patrol/internal/verdict"
)

type Resolver struct {
	events      map[string][]time.Time
	burstAlerts map[string]time.Time
}

func New() *Resolver {
	return &Resolver{
		events:      make(map[string][]time.Time),
		burstAlerts: make(map[string]time.Time),
	}
}

func (r *Resolver) Evaluate(e *event.Event) verdict.ContextResult {
	// Context는 "지금 분위기가 이상한가?"를 보는 부분이다.
	// 같은 syscall이라도 누가, 언제, 어떤 파일을 대상으로 했는지에 따라 위험도가 달라진다.
	switch e.Type {
	case event.EventExec:
		if isShell(e.Arg1) && !isShell(e.Comm) {
			return verdict.ContextResult{
				Verdict: verdict.ContextAnomalous,
				Reason:  fmt.Sprintf("unexpected shell execution from process %q", e.Comm),
				Score:   0.9,
			}
		}
		if isReverseShellTool(e.Arg1) {
			return verdict.ContextResult{
				Verdict: verdict.ContextSuspicious,
				Reason:  fmt.Sprintf("network-capable shell tool executed: %s", e.Arg1),
				Score:   0.7,
			}
		}
	case event.EventOpen:
		// cgroupfs나 라이브러리 파일을 읽는 것은 런타임에서 자주 일어나는 정상 행동이다.
		// 먼저 진짜 위험한 write 시도를 확인하고, 그 다음 정상 노이즈를 제외한다.
		if isSensitiveWritePath(e.Arg1) && isWriteOpen(e.Flags) {
			return verdict.ContextResult{
				Verdict: verdict.ContextAnomalous,
				Reason:  fmt.Sprintf("sensitive control file write attempt: %s", e.Arg1),
				Score:   0.95,
			}
		}
		if isBenignOpenPath(e.Arg1, e.Flags) {
			return verdict.ContextResult{Verdict: verdict.ContextNormal, Reason: "benign runtime file access", Score: 0.0}
		}
		if containsAny(e.Arg1, []string{"/etc/shadow", "/proc/kcore", "/root/.ssh"}) {
			// 민감한 파일을 읽으려는 행동은 강한 이상 신호로 본다.
			return verdict.ContextResult{
				Verdict: verdict.ContextAnomalous,
				Reason:  fmt.Sprintf("sensitive host path access: %s", e.Arg1),
				Score:   0.9,
			}
		}
	case event.EventMount:
		// mount는 컨테이너 탈출 과정에서 자주 등장하는 행동이다.
		return verdict.ContextResult{
			Verdict: verdict.ContextAnomalous,
			Reason:  fmt.Sprintf("mount operation from process %q", e.Comm),
			Score:   0.85,
		}
	case event.EventUnshare:
		// unshare는 새로운 namespace를 만드는 syscall이다.
		// host namespace로 넘어가려는 공격 흐름에서 중요한 단서가 된다.
		return verdict.ContextResult{
			Verdict: verdict.ContextAnomalous,
			Reason:  fmt.Sprintf("namespace unshare from process %q", e.Comm),
			Score:   0.9,
		}
	case event.EventPtrace:
		// ptrace는 프로세스를 추적하는 기능이다.
		// root가 아닌 사용자의 ptrace는 더 수상하게 본다.
		score := 0.75
		state := verdict.ContextSuspicious
		if e.Uid != 0 {
			score = 0.9
			state = verdict.ContextAnomalous
		}
		return verdict.ContextResult{
			Verdict: state,
			Reason:  fmt.Sprintf("ptrace operation from uid %d", e.Uid),
			Score:   score,
		}
	}

	if burst := r.recordAndCheckBurst(e); burst != nil {
		// 너무 많은 이벤트가 짧은 시간에 몰리면 이상할 수 있다.
		// 다만 로그 폭주를 막기 위해 같은 종류의 burst는 쿨다운을 둔다.
		return *burst
	}

	return verdict.ContextResult{Verdict: verdict.ContextNormal, Reason: "runtime context is normal", Score: 0.0}
}

func (r *Resolver) recordAndCheckBurst(e *event.Event) *verdict.ContextResult {
	// 최근 10초 동안 같은 cgroup에서 같은 이벤트가 몇 번 났는지 센다.
	// 예: open 이벤트가 비정상적으로 많으면 파일 스캔일 수 있다.
	now := time.Now()
	key := fmt.Sprintf("%d:%s", e.CgroupID, e.Type.String())
	windowStart := now.Add(-10 * time.Second)

	recent := r.events[key]
	kept := recent[:0]
	for _, ts := range recent {
		if ts.After(windowStart) {
			kept = append(kept, ts)
		}
	}
	kept = append(kept, now)
	r.events[key] = kept

	if len(kept) >= 200 {
		if last, ok := r.burstAlerts[key]; ok && now.Sub(last) < 30*time.Second {
			return nil
		}
		r.burstAlerts[key] = now
		return &verdict.ContextResult{
			Verdict: verdict.ContextSuspicious,
			Reason:  fmt.Sprintf("event burst detected: %d %s events in 10s", len(kept), e.Type.String()),
			Score:   0.65,
		}
	}

	return nil
}

func isShell(path string) bool {
	base := filepath.Base(path)
	switch base {
	case "sh", "bash", "dash", "ash", "zsh", "ksh":
		return true
	default:
		return false
	}
}

func isReverseShellTool(path string) bool {
	base := filepath.Base(path)
	switch base {
	case "nc", "ncat", "netcat", "socat", "python", "python3", "perl", "ruby":
		return true
	default:
		return false
	}
}

func isBenignOpenPath(path string, flags uint32) bool {
	// 프로그램이 시작할 때 libc, locale, timezone 같은 파일을 읽는 것은 정상이다.
	// 이런 파일까지 경고하면 쓸모없는 알림이 너무 많아진다.
	if path == "" {
		return true
	}

	if containsAny(path, []string{
		"/etc/ld.so.cache",
		"/usr/lib/locale/",
		"/usr/share/locale/",
		"/usr/share/zoneinfo/",
		"/var/cache/ldconfig/",
	}) {
		return true
	}

	if strings.HasPrefix(path, "/sys/fs/cgroup/") && !isWriteOpen(flags) {
		return true
	}

	if strings.HasPrefix(path, "/lib/") ||
		strings.HasPrefix(path, "/lib64/") ||
		strings.HasPrefix(path, "/usr/lib/") ||
		strings.HasPrefix(path, "/usr/lib64/") {
		return true
	}

	if strings.HasPrefix(path, "/proc/") && strings.HasSuffix(path, "/stat") {
		return true
	}
	if strings.HasPrefix(path, "/proc/") && strings.HasSuffix(path, "/cmdline") {
		return true
	}

	return false
}

func isSensitiveWritePath(path string) bool {
	// 아래 파일들은 컨테이너 탈출 PoC에서 자주 언급되는 위험한 제어 지점이다.
	// 읽기보다 쓰기 시도가 더 위험하므로 write open인지 함께 확인한다.
	return containsAny(path, []string{
		"/sys/fs/cgroup/release_agent",
		"/sys/fs/cgroup/notify_on_release",
		"/proc/sys/kernel/",
		"/proc/sys/vm/",
		"/proc/sys/net/",
		"/proc/sysrq-trigger",
	})
}

func isWriteOpen(flags uint32) bool {
	const (
		oWRONLY = 1
		oRDWR   = 2
	)
	return flags&oWRONLY != 0 || flags&oRDWR != 0
}

func containsAny(value string, patterns []string) bool {
	for _, pattern := range patterns {
		if strings.Contains(value, pattern) {
			return true
		}
	}
	return false
}
