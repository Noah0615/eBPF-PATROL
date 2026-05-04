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
	"ebpf-patrol/internal/scope"
	"ebpf-patrol/internal/verdict"
)

type Analyzer struct {
	policies *policy.PolicySet
	intents  *intent.IntentSet
	context  *contextcheck.Resolver
	scope    *scope.Filter
	stats    map[string]int
}

func New(policies *policy.PolicySet, intents *intent.IntentSet, scopeMode string) *Analyzer {
	return &Analyzer{
		policies: policies,
		intents:  intents,
		context:  contextcheck.New(),
		scope:    scope.New(scopeMode),
		stats:    make(map[string]int),
	}
}

func (a *Analyzer) Analyze(e *event.Event) {
	// Analyzer는 탐지기의 "재판장" 역할을 한다.
	// 1. 먼저 우리가 볼 대상인지 확인한다. 기본값은 컨테이너 관련 이벤트만 본다.
	// 2. Policy, Intent, Context 세 명의 심사위원에게 같은 이벤트를 보여준다.
	// 3. Fusion이 세 의견을 합쳐 최종 결론을 낸다.
	if !a.scope.ShouldAnalyze(e) {
		return
	}

	policyResult := a.policies.Evaluate(e)
	intentResult := a.intents.Evaluate(e)
	contextResult := a.context.Evaluate(e)
	decision := fusion.Decide(policyResult, intentResult, contextResult)

	if shouldLog(decision) {
		a.handleDecision(e, decision)
	}
}

func (a *Analyzer) handleDecision(e *event.Event, d verdict.Decision) {
	// 최종 결론이 나오면 사람이 읽을 수 있는 로그로 바꾼다.
	// DENY/KILL 같은 강한 결론은 화면에도 바로 보여준다.
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

	// ── 3-way cross-validation 통합 로그 ──
	// Policy, Intent, Context 각 축의 판정과 최종 Fusion 결과를 모두 표시
	intentInfo := string(d.Intent.Verdict)
	if d.Intent.MatchedIntent != "" {
		intentInfo = fmt.Sprintf("%s(%s)", d.Intent.Verdict, d.Intent.MatchedIntent)
	}

	logMsg := fmt.Sprintf("[%s] [%s] Verdict=%s Type=%s PID=%d PPID=%d UID=%d Comm=%s Arg1=%s Cgroup=%d | Policy=%s Intent=%s Context=%s | Reason=%s",
		timestamp.Format("2006-01-02 15:04:05"),
		severity,
		d.Final,
		e.Type.String(),
		e.Pid,
		e.Ppid,
		e.Uid,
		e.Comm,
		e.Arg1,
		e.CgroupID,
		d.Policy.Verdict,
		intentInfo,
		d.Context.Verdict,
		d.Reason,
	)

	switch d.Final {
	case verdict.FinalAllow:
		log.Println(logMsg)
	case verdict.FinalAlert:
		log.Println(logMsg)
		fmt.Printf("🚨 ALERT: %s (PID=%d, Comm=%s, Arg=%s)\n", d.Reason, e.Pid, e.Comm, e.Arg1)
	case verdict.FinalDeny:
		log.Println(logMsg)
		fmt.Printf("🛑 DENY: Policy=%s Intent=%s Context=%s → %s (PID=%d, Comm=%s, Arg=%s)\n",
			d.Policy.Verdict, intentInfo, d.Context.Verdict, d.Reason, e.Pid, e.Comm, e.Arg1)
	case verdict.FinalKill:
		log.Println(logMsg)
		fmt.Printf("💀 KILL: Policy=%s Intent=%s Context=%s → %s (PID=%d, Comm=%s, Arg=%s)\n",
			d.Policy.Verdict, intentInfo, d.Context.Verdict, d.Reason, e.Pid, e.Comm, e.Arg1)
		// 지금 버전은 tracepoint 기반이라 커널 안에서 syscall을 바로 막지는 못한다.
		// 대신 아주 위험하다고 판단한 프로세스는 userspace에서 kill한다.
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
	// 정상 이벤트는 너무 많아서 전부 찍으면 로그가 폭포처럼 쏟아진다.
	// 그래서 정책에 걸렸거나, 최종 결론이 ALLOW가 아닐 때만 주로 기록한다.
	return d.Final != verdict.FinalAllow || d.Policy.MatchedRule != ""
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
