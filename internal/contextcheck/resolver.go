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
			return verdict.ContextResult{
				Verdict: verdict.ContextAnomalous,
				Reason:  fmt.Sprintf("sensitive host path access: %s", e.Arg1),
				Score:   0.9,
			}
		}
	case event.EventMount:
		return verdict.ContextResult{
			Verdict: verdict.ContextAnomalous,
			Reason:  fmt.Sprintf("mount operation from process %q", e.Comm),
			Score:   0.85,
		}
	case event.EventUnshare:
		return verdict.ContextResult{
			Verdict: verdict.ContextAnomalous,
			Reason:  fmt.Sprintf("namespace unshare from process %q", e.Comm),
			Score:   0.9,
		}
	case event.EventPtrace:
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
		return *burst
	}

	return verdict.ContextResult{Verdict: verdict.ContextNormal, Reason: "runtime context is normal", Score: 0.0}
}

func (r *Resolver) recordAndCheckBurst(e *event.Event) *verdict.ContextResult {
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
