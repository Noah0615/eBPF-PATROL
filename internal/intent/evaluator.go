package intent

import (
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"ebpf-patrol/internal/event"
	"ebpf-patrol/internal/verdict"
)

func (s *IntentSet) Evaluate(e *event.Event) verdict.IntentResult {
	// Intent는 "이 컨테이너는 원래 이런 일을 해야 한다"는 약속이다.
	// 예: nginx는 웹서버라서 shell이나 mount가 필요 없고,
	//     debug pod는 shell 실행이 필요할 수 있다.
	if s == nil {
		return verdict.IntentResult{Verdict: verdict.IntentUnknown, Reason: "intent set is not configured"}
	}

	if materialized, ok := s.LookupMaterialized(e.CgroupID); ok {
		// ── 오탐 감소: Grace Period 확인 ──
		// 컨테이너 시작 직후에는 라이브러리 로딩, 설정 파일 읽기 등으로
		// 정상 노이즈가 발생한다. grace period 동안은 violation을 차단하지 않고
		// UNKNOWN으로 완화하여 false positive를 방지한다.
		graceSec := materialized.Intent.Meta.GracePeriodSeconds
		if graceSec > 0 && materialized.MaterializedAt > 0 {
			elapsed := time.Now().Unix() - materialized.MaterializedAt
			if elapsed < int64(graceSec) {
				return verdict.IntentResult{
					Verdict:       verdict.IntentUnknown,
					Reason:        fmt.Sprintf("grace period active (%ds/%ds elapsed)", elapsed, graceSec),
					MatchedIntent: materialized.Intent.Name,
				}
			}
		}

		// ── 오탐 감소: TTL 만료 확인 ──
		ttl := materialized.Intent.Meta.TTLSeconds
		if ttl > 0 && materialized.MaterializedAt > 0 {
			elapsed := time.Now().Unix() - materialized.MaterializedAt
			if elapsed > int64(ttl) {
				return verdict.IntentResult{
					Verdict:       verdict.IntentDeny,
					Reason:        fmt.Sprintf("intent %q expired (TTL %ds exceeded)", materialized.Intent.Name, ttl),
					MatchedIntent: materialized.Intent.Name,
				}
			}
		}

		result := materialized.Intent.evaluate(e)
		result.MatchedIntent = materialized.Intent.Name

		// ── 오탐 감소: Enforcement Mode 확인 ──
		// audit 모드에서는 violation을 탐지하되 DENY 대신 ALLOW로 완화한다.
		// 이를 통해 새 intent를 안전하게 테스트할 수 있다.
		if result.Verdict == verdict.IntentDeny {
			mode := materialized.Intent.Meta.EnforcementMode
			if mode == "audit" || mode == "learn" {
				result.Verdict = verdict.IntentAllow
				result.Reason = fmt.Sprintf("[%s mode] %s", mode, result.Reason)
			}
		}

		if result.Reason == "event matches workload intent" {
			result.Reason = fmt.Sprintf("event matches Kubernetes intent %s/%s", materialized.Namespace, materialized.PodName)
		}
		return result
	}

	for _, candidate := range s.Intents {
		if candidate.matches(e) {
			return candidate.evaluate(e)
		}
	}

	return verdict.IntentResult{Verdict: verdict.IntentUnknown, Reason: "no matching workload intent"}
}

func (s *IntentSet) LookupMaterialized(cgroupID uint64) (MaterializedIntent, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	materialized, ok := s.Materialized[cgroupID]
	return materialized, ok
}

func (s *IntentSet) ReplaceMaterialized(next map[uint64]MaterializedIntent) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.Materialized = next
}

func (s *IntentSet) MatchByLabels(labels map[string]string) (Intent, bool) {
	if s == nil {
		return Intent{}, false
	}

	// 오탐 감소: 여러 intent가 같은 pod에 매칭될 수 있다.
	// priority가 가장 높은 것을 선택하여 모호한 판정을 방지한다.
	var best *Intent
	bestPriority := -1

	for i := range s.Intents {
		candidate := &s.Intents[i]
		if selectorMatches(candidate.Selector.MatchLabels, labels) {
			if candidate.Meta.Priority > bestPriority {
				best = candidate
				bestPriority = candidate.Meta.Priority
			} else if best == nil {
				best = candidate
			}
		}
	}

	if best != nil {
		return *best, true
	}
	return Intent{}, false
}

func selectorMatches(selector map[string]string, labels map[string]string) bool {
	if len(selector) == 0 {
		return false
	}

	for key, want := range selector {
		if labels[key] != want {
			return false
		}
	}
	return true
}

func (i Intent) matches(e *event.Event) bool {
	// 지금 MVP는 cgroup ID 또는 process comm 이름으로 Intent를 찾는다.
	// 다음 단계에서는 Kubernetes watcher가 pod/container 정보를 보고
	// cgroup ID에 정확히 Intent를 붙이는 방식으로 발전시킬 수 있다.
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
	// 이벤트가 Intent와 매칭되면, 그 행동이 약속 안에 있는지 확인한다.
	// 약속 밖 행동이면 Intent DENY를 반환한다.
	result := verdict.IntentResult{
		Verdict:       verdict.IntentAllow,
		Reason:        "event matches workload intent",
		MatchedIntent: i.Name,
	}

	switch e.Type {
	case event.EventExec:
		// shell 실행은 컨테이너 침해 뒤에 자주 보이는 행동이다.
		// 하지만 debug pod처럼 shell이 필요한 경우도 있어서 Intent로 구분한다.
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
		// namespace 조작은 컨테이너 탈출 시나리오에서 중요한 신호다.
		if hasNamespaceCloneFlag(e.Flags) && !i.Spec.AllowNamespaceOps {
			result.Verdict = verdict.IntentDeny
			result.Reason = fmt.Sprintf("%s does not allow namespace operations", i.Name)
			return result
		}
	case event.EventMount:
		// mount는 파일시스템 경계를 바꾸는 행동이라 일반 앱 컨테이너에는 보통 필요 없다.
		if !i.Spec.AllowNamespaceOps {
			result.Verdict = verdict.IntentDeny
			result.Reason = fmt.Sprintf("%s does not allow mount operations", i.Name)
			return result
		}
	case event.EventPtrace:
		// ptrace는 다른 프로세스를 들여다보는 기능이다.
		// 진단 pod에는 필요할 수 있지만, 일반 서비스에는 위험할 수 있다.
		if !i.Spec.AllowPrivilegeOps {
			result.Verdict = verdict.IntentDeny
			result.Reason = fmt.Sprintf("%s does not allow ptrace or privileged operations", i.Name)
			return result
		}
	case event.EventOpen:
		// docker.sock을 만지면 컨테이너가 호스트 Docker를 조종할 수 있어 매우 위험하다.
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
