package analyzer

import (
	"fmt"
	"log"
	"time"

	"ebpf-patrol/internal/contextcheck"
	"ebpf-patrol/internal/enforcer"
	"ebpf-patrol/internal/event"
	"ebpf-patrol/internal/fusion"
	"ebpf-patrol/internal/intent"
	"ebpf-patrol/internal/policy"
	"ebpf-patrol/internal/verdict"
)

type Analyzer struct {
	policies *policy.PolicySet
	intents  *intent.IntentSet
	context  *contextcheck.Resolver
	stats    map[string]int
}

func New(policies *policy.PolicySet, intents *intent.IntentSet) *Analyzer {
	return &Analyzer{
		policies: policies,
		intents:  intents,
		context:  contextcheck.New(),
		stats:    make(map[string]int),
	}
}

func (a *Analyzer) Analyze(e *event.Event) {
	policyResult := a.policies.Evaluate(e)
	intentResult := a.intents.Evaluate(e)
	contextResult := a.context.Evaluate(e)
	decision := fusion.Decide(policyResult, intentResult, contextResult)

	if shouldLog(decision) {
		a.handleDecision(e, decision)
	}
}

func (a *Analyzer) handleDecision(e *event.Event, d verdict.Decision) {
	key := string(d.Final)
	if d.Policy.MatchedRule != "" {
		key = d.Policy.MatchedRule
	}
	a.stats[key]++

	timestamp := time.Now()
	severity := d.Policy.Severity
	if severity == "" {
		severity = severityFor(d.Final)
	}

	logMsg := fmt.Sprintf("[%s] [%s] Verdict=%s Confidence=%.2f Type=%s PID=%d PPID=%d UID=%d Comm=%s Arg1=%s Arg2=%s Cgroup=%d Policy=%s Intent=%s Context=%s Reason=%s",
		timestamp.Format("2006-01-02 15:04:05"),
		severity,
		d.Final,
		d.Confidence,
		e.Type.String(),
		e.Pid,
		e.Ppid,
		e.Uid,
		e.Comm,
		e.Arg1,
		e.Arg2,
		e.CgroupID,
		d.Policy.Verdict,
		d.Intent.Verdict,
		d.Context.Verdict,
		d.Reason,
	)

	switch d.Final {
	case verdict.FinalAllow:
		log.Println(logMsg)
	case verdict.FinalAlert:
		log.Println(logMsg)
		fmt.Printf("ALERT: %s (PID=%d, Comm=%s, Arg=%s)\n", d.Reason, e.Pid, e.Comm, e.Arg1)
	case verdict.FinalDeny:
		log.Println(logMsg)
		fmt.Printf("DENY: %s (PID=%d, Comm=%s, Arg=%s)\n", d.Reason, e.Pid, e.Comm, e.Arg1)
	case verdict.FinalKill:
		log.Println(logMsg)
		fmt.Printf("KILL: %s (PID=%d, Comm=%s, Arg=%s)\n", d.Reason, e.Pid, e.Comm, e.Arg1)
		if err := enforcer.Kill(e.Pid); err != nil {
			log.Printf("kill pid %d failed: %v", e.Pid, err)
		}
	default:
		log.Println(logMsg)
	}
}

func (a *Analyzer) PrintStats() {
	fmt.Println("\n=== Detection Statistics ===")
	for name, count := range a.stats {
		fmt.Printf("%s: %d detections\n", name, count)
	}
}

func shouldLog(d verdict.Decision) bool {
	return d.Final != verdict.FinalAllow || d.Policy.MatchedRule != "" || d.Intent.MatchedIntent != ""
}

func severityFor(final verdict.FinalVerdict) string {
	switch final {
	case verdict.FinalKill, verdict.FinalDeny:
		return "CRITICAL"
	case verdict.FinalAlert:
		return "HIGH"
	default:
		return "INFO"
	}
}
