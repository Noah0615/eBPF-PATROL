package fusion

import "ebpf-patrol/internal/verdict"

func Decide(policy verdict.PolicyResult, intent verdict.IntentResult, context verdict.ContextResult) verdict.Decision {
	decision := verdict.Decision{
		Policy:  policy,
		Intent:  intent,
		Context: context,
	}

	if policy.Verdict == verdict.PolicyDeny {
		decision.Final = verdict.FinalDeny
		decision.Confidence = 1.0
		decision.Reason = policy.Reason
		return decision
	}

	if intent.Verdict == verdict.IntentDeny {
		if context.Verdict == verdict.ContextAnomalous {
			decision.Final = verdict.FinalKill
			decision.Confidence = 0.95
			decision.Reason = "intent violation with anomalous runtime context"
			return decision
		}
		decision.Final = verdict.FinalDeny
		decision.Confidence = 0.9
		decision.Reason = intent.Reason
		return decision
	}

	if policy.Verdict == verdict.PolicyAllow && intent.Verdict == verdict.IntentAllow {
		switch context.Verdict {
		case verdict.ContextNormal:
			decision.Final = verdict.FinalAllow
			decision.Confidence = 1.0
			decision.Reason = "all axes agree"
		case verdict.ContextSuspicious:
			decision.Final = verdict.FinalAlert
			decision.Confidence = 0.7
			decision.Reason = context.Reason
		case verdict.ContextAnomalous:
			decision.Final = verdict.FinalDeny
			decision.Confidence = 0.8
			decision.Reason = context.Reason
		}
		return decision
	}

	if intent.Verdict == verdict.IntentUnknown {
		if context.Verdict == verdict.ContextAnomalous {
			decision.Final = verdict.FinalDeny
			decision.Confidence = 0.75
			decision.Reason = "no intent matched and runtime context is anomalous"
			return decision
		}
		if policy.Verdict == verdict.PolicySuspicious || context.Verdict == verdict.ContextSuspicious {
			decision.Final = verdict.FinalAlert
			decision.Confidence = 0.6
			decision.Reason = firstNonEmpty(policy.Reason, context.Reason, "suspicious event without matching intent")
			return decision
		}
		decision.Final = verdict.FinalAllow
		decision.Confidence = 0.5
		decision.Reason = "no intent matched, policy allows"
		return decision
	}

	if policy.Verdict == verdict.PolicySuspicious {
		if context.Verdict == verdict.ContextAnomalous {
			decision.Final = verdict.FinalDeny
			decision.Confidence = 0.85
			decision.Reason = context.Reason
			return decision
		}
		decision.Final = verdict.FinalAlert
		decision.Confidence = 0.5
		decision.Reason = policy.Reason
		return decision
	}

	decision.Final = verdict.FinalAllow
	decision.Confidence = 0.3
	decision.Reason = "default allow"
	return decision
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}
