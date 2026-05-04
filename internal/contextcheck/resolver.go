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
	events map[string][]time.Time
}

func New() *Resolver {
	return &Resolver{events: make(map[string][]time.Time)}
}

func (r *Resolver) Evaluate(e *event.Event) verdict.ContextResult {
	if burst := r.recordAndCheckBurst(e); burst != nil {
		return *burst
	}

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

func containsAny(value string, patterns []string) bool {
	for _, pattern := range patterns {
		if strings.Contains(value, pattern) {
			return true
		}
	}
	return false
}
