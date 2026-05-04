package intent

import (
	"fmt"
	"path/filepath"
	"strings"

	"ebpf-patrol/internal/event"
	"ebpf-patrol/internal/verdict"
)

func (s *IntentSet) Evaluate(e *event.Event) verdict.IntentResult {
	if s == nil {
		return verdict.IntentResult{Verdict: verdict.IntentUnknown, Reason: "intent set is not configured"}
	}

	for _, candidate := range s.Intents {
		if candidate.matches(e) {
			return candidate.evaluate(e)
		}
	}

	return verdict.IntentResult{Verdict: verdict.IntentUnknown, Reason: "no matching workload intent"}
}

func (i Intent) matches(e *event.Event) bool {
	if len(i.Match.CgroupIDs) > 0 {
		for _, id := range i.Match.CgroupIDs {
			if id == e.CgroupID {
				return true
			}
		}
		return false
	}

	if i.Match.CommEquals != "" && e.Comm != i.Match.CommEquals {
		return false
	}

	if len(i.Match.CommContains) > 0 {
		for _, pattern := range i.Match.CommContains {
			if strings.Contains(e.Comm, pattern) {
				return true
			}
		}
		return false
	}

	return i.Match.CommEquals != ""
}

func (i Intent) evaluate(e *event.Event) verdict.IntentResult {
	result := verdict.IntentResult{
		Verdict:       verdict.IntentAllow,
		Reason:        "event matches workload intent",
		MatchedIntent: i.Name,
	}

	switch e.Type {
	case event.EventExec:
		if isShell(e.Arg1) && !i.Spec.AllowShell {
			result.Verdict = verdict.IntentDeny
			result.Reason = fmt.Sprintf("%s does not allow shell execution", i.Name)
			return result
		}
		if len(i.Spec.ExpectedProcesses) > 0 && !containsAny(e.Arg1, i.Spec.ExpectedProcesses) {
			result.Verdict = verdict.IntentDeny
			result.Reason = fmt.Sprintf("%s does not expect process %q", i.Name, e.Arg1)
			return result
		}
	case event.EventClone, event.EventUnshare:
		if hasNamespaceCloneFlag(e.Flags) && !i.Spec.AllowNamespaceOps {
			result.Verdict = verdict.IntentDeny
			result.Reason = fmt.Sprintf("%s does not allow namespace operations", i.Name)
			return result
		}
	case event.EventMount:
		if !i.Spec.AllowNamespaceOps {
			result.Verdict = verdict.IntentDeny
			result.Reason = fmt.Sprintf("%s does not allow mount operations", i.Name)
			return result
		}
	case event.EventPtrace:
		if !i.Spec.AllowPrivilegeOps {
			result.Verdict = verdict.IntentDeny
			result.Reason = fmt.Sprintf("%s does not allow ptrace or privileged operations", i.Name)
			return result
		}
	case event.EventOpen:
		if isDockerSock(e.Arg1) && !i.Spec.AllowDockerSock {
			result.Verdict = verdict.IntentDeny
			result.Reason = fmt.Sprintf("%s does not allow docker socket access", i.Name)
			return result
		}
	}

	return result
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

func isDockerSock(path string) bool {
	return strings.Contains(path, "/var/run/docker.sock") || strings.Contains(path, "/run/docker.sock")
}

func containsAny(value string, patterns []string) bool {
	for _, pattern := range patterns {
		if strings.Contains(value, pattern) {
			return true
		}
	}
	return false
}

func hasNamespaceCloneFlag(flags uint32) bool {
	const (
		cloneNewNS   = 0x00020000
		cloneNewUTS  = 0x04000000
		cloneNewIPC  = 0x08000000
		cloneNewUSER = 0x10000000
		cloneNewPID  = 0x20000000
		cloneNewNET  = 0x40000000
	)

	mask := uint32(cloneNewNS | cloneNewUTS | cloneNewIPC | cloneNewUSER | cloneNewPID | cloneNewNET)
	return flags&mask != 0
}
