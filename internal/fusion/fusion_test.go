package fusion

import (
	"testing"

	"ebpf-patrol/internal/verdict"
)

func TestDecideIntentViolationWithAnomalyKills(t *testing.T) {
	got := Decide(
		verdict.PolicyResult{Verdict: verdict.PolicyAllow},
		verdict.IntentResult{Verdict: verdict.IntentDeny, Reason: "shell not allowed"},
		verdict.ContextResult{Verdict: verdict.ContextAnomalous},
	)

	if got.Final != verdict.FinalKill {
		t.Fatalf("Final = %s, want %s", got.Final, verdict.FinalKill)
	}
}

func TestDecideUnknownIntentAnomalyDenies(t *testing.T) {
	got := Decide(
		verdict.PolicyResult{Verdict: verdict.PolicyAllow},
		verdict.IntentResult{Verdict: verdict.IntentUnknown},
		verdict.ContextResult{Verdict: verdict.ContextAnomalous},
	)

	if got.Final != verdict.FinalDeny {
		t.Fatalf("Final = %s, want %s", got.Final, verdict.FinalDeny)
	}
}

func TestDecideAllAxesAllow(t *testing.T) {
	got := Decide(
		verdict.PolicyResult{Verdict: verdict.PolicyAllow},
		verdict.IntentResult{Verdict: verdict.IntentAllow},
		verdict.ContextResult{Verdict: verdict.ContextNormal},
	)

	if got.Final != verdict.FinalAllow {
		t.Fatalf("Final = %s, want %s", got.Final, verdict.FinalAllow)
	}
}
