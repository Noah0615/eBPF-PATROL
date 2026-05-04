package intent

import (
	"testing"

	"ebpf-patrol/internal/event"
	"ebpf-patrol/internal/verdict"
)

func TestEvaluateDeniesShellWhenIntentDisallowsIt(t *testing.T) {
	intents := &IntentSet{Intents: []Intent{
		{
			Name: "web",
			Match: IntentMatch{
				CommContains: []string{"nginx"},
			},
			Spec: IntentSpec{AllowShell: false},
		},
	}}

	got := intents.Evaluate(&event.Event{
		Type: event.EventExec,
		Comm: "nginx",
		Arg1: "/bin/bash",
	})

	if got.Verdict != verdict.IntentDeny {
		t.Fatalf("Verdict = %s, want %s", got.Verdict, verdict.IntentDeny)
	}
}

func TestEvaluateAllowsDiagnosticPtrace(t *testing.T) {
	intents := &IntentSet{Intents: []Intent{
		{
			Name: "diagnostic",
			Match: IntentMatch{
				CommContains: []string{"strace"},
			},
			Spec: IntentSpec{AllowPrivilegeOps: true},
		},
	}}

	got := intents.Evaluate(&event.Event{
		Type: event.EventPtrace,
		Comm: "strace",
	})

	if got.Verdict != verdict.IntentAllow {
		t.Fatalf("Verdict = %s, want %s", got.Verdict, verdict.IntentAllow)
	}
}

func TestMatchByLabels(t *testing.T) {
	intents := &IntentSet{Intents: []Intent{
		{
			Name: "web",
			Selector: LabelSelector{MatchLabels: map[string]string{
				"app":  "nginx",
				"tier": "frontend",
			}},
		},
	}}

	got, ok := intents.MatchByLabels(map[string]string{
		"app":  "nginx",
		"tier": "frontend",
	})
	if !ok {
		t.Fatal("MatchByLabels did not match")
	}
	if got.Name != "web" {
		t.Fatalf("Name = %s, want web", got.Name)
	}
}
