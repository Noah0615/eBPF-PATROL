package policy

import (
	"fmt"
	"strings"

	"ebpf-patrol/internal/event"
	"ebpf-patrol/internal/verdict"
)

func (ps *PolicySet) Evaluate(e *event.Event) verdict.PolicyResult {
	// Policy는 관리자가 쓴 "절대 규칙"에 가깝다.
	// 예: /etc/shadow 접근, docker.sock 접근처럼 위험한 행동을 찾는다.
	if ps == nil {
		return verdict.PolicyResult{Verdict: verdict.PolicyAllow, Reason: "policy set is not configured"}
	}

	for _, pol := range ps.Policies {
		// 위에서부터 차례대로 규칙을 확인하고, 처음 맞는 규칙을 결과로 쓴다.
		if pol.Matches(e) {
			return verdict.PolicyResult{
				Verdict:     actionToVerdict(pol.Action),
				Reason:      fmt.Sprintf("%s: %s", pol.Name, pol.Description),
				MatchedRule: pol.Name,
				Severity:    pol.Severity,
			}
		}
	}

	return verdict.PolicyResult{Verdict: verdict.PolicyAllow, Reason: "no policy matched"}
}

func actionToVerdict(action string) verdict.PolicyVerdict {
	// YAML의 action 문자열을 프로그램이 이해하는 판정 값으로 바꾼다.
	// deny/block/kill은 강한 차단, alert/warn은 수상함, 나머지는 허용이다.
	switch strings.ToLower(action) {
	case "deny", "block", "reject", "kill":
		return verdict.PolicyDeny
	case "alert", "warn", "suspicious":
		return verdict.PolicySuspicious
	default:
		return verdict.PolicyAllow
	}
}
