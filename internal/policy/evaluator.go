package policy

import (
	"fmt"
	"strings"

	"ebpf-patrol/internal/event"
	"ebpf-patrol/internal/verdict"
)

func (ps *PolicySet) Evaluate(e *event.Event) verdict.PolicyResult {
	if ps == nil {
		return verdict.PolicyResult{Verdict: verdict.PolicyAllow, Reason: "policy set is not configured"}
	}

	for _, pol := range ps.Policies {
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
	switch strings.ToLower(action) {
	case "deny", "block", "reject", "kill":
		return verdict.PolicyDeny
	case "alert", "warn", "suspicious":
		return verdict.PolicySuspicious
	default:
		return verdict.PolicyAllow
	}
}
