package fusion

import "ebpf-patrol/internal/verdict"

func Decide(policy verdict.PolicyResult, intent verdict.IntentResult, context verdict.ContextResult) verdict.Decision {
	// Fusion은 세 심사위원의 말을 모아 최종 판결을 내리는 곳이다.
	// Policy: "규칙상 위험한가?"
	// Intent: "이 컨테이너가 원래 해도 되는 행동인가?"
	// Context: "지금 상황이 이상한가?"
	decision := verdict.Decision{
		Policy:  policy,
		Intent:  intent,
		Context: context,
	}

	if policy.Verdict == verdict.PolicyDeny {
		// 관리자가 절대 안 된다고 정한 것은 가장 강하게 본다.
		// 예: /etc/shadow, /proc/kcore, docker.sock 접근
		decision.Final = verdict.FinalDeny
		decision.Confidence = 1.0
		decision.Reason = policy.Reason
		return decision
	}

	if intent.Verdict == verdict.IntentDeny {
		// 워크로드의 약속을 어긴 경우다.
		// 예: nginx 역할인데 갑자기 /bin/bash를 실행함
		if context.Verdict == verdict.ContextAnomalous {
			// 약속도 어겼고 상황도 이상하면 공격 가능성이 높다고 보고 KILL한다.
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
		// 규칙도 통과했고, 워크로드 의도에도 맞는 경우다.
		// 이때는 Context만 마지막으로 확인한다.
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
		// 아직 이 cgroup/pod에 맞는 Intent가 없을 수 있다.
		// UNKNOWN만으로 공격이라고 단정하면 오탐이 너무 많아진다.
		if context.Verdict == verdict.ContextAnomalous {
			decision.Final = verdict.FinalDeny
			decision.Confidence = 0.75
			decision.Reason = "no intent matched and runtime context is anomalous"
			return decision
		}
		if policy.Verdict == verdict.PolicySuspicious {
			decision.Final = verdict.FinalAlert
			decision.Confidence = 0.6
			decision.Reason = firstNonEmpty(policy.Reason, "suspicious policy match without matching intent")
			return decision
		}
		if context.Verdict == verdict.ContextSuspicious {
			// "조금 수상함" 정도는 UNKNOWN intent와 만나도 바로 ALERT로 올리지 않는다.
			// 라이브러리 로딩, cgroup 파일 읽기 같은 정상 노이즈가 많기 때문이다.
			decision.Final = verdict.FinalAllow
			decision.Confidence = 0.4
			decision.Reason = "weak context signal without matching intent"
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
