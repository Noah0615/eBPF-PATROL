// Package crd — converter.go
// WorkloadIntent CRD spec → 내부 intent.Intent 변환기.
// CRD의 풍부한 메타데이터(priority, enforcementMode, gracePeriod 등)를
// 기존 분석 파이프라인이 이해하는 형식으로 바꾸되, 오탐 감소 필드를 보존한다.
package crd

import (
	"ebpf-patrol/internal/intent"
)

// ToIntent converts a WorkloadIntent CRD spec into the internal Intent type.
func ToIntent(wi *WorkloadIntent) intent.Intent {
	matchLabels := make(map[string]string)
	if wi.Spec.Selector.MatchLabels != nil {
		for k, v := range wi.Spec.Selector.MatchLabels {
			matchLabels[k] = v
		}
	}

	result := intent.Intent{
		Name: wi.Name,
		Selector: intent.LabelSelector{
			MatchLabels: matchLabels,
		},
		Spec: intent.IntentSpec{
			AllowShell:        wi.Spec.AllowShell,
			AllowNamespaceOps: wi.Spec.AllowNamespaceOps,
			AllowPrivilegeOps: wi.Spec.AllowPrivilegeOps,
			AllowDockerSock:   wi.Spec.AllowDockerSock,
		},
	}

	// expectedProcesses
	if len(wi.Spec.ExpectedProcesses) > 0 {
		result.Spec.ExpectedProcesses = make([]string, len(wi.Spec.ExpectedProcesses))
		copy(result.Spec.ExpectedProcesses, wi.Spec.ExpectedProcesses)
	}

	// allowedPaths
	if wi.Spec.AllowedPaths != nil {
		result.Spec.AllowedPaths = intent.AllowedPaths{
			Read:  make([]string, len(wi.Spec.AllowedPaths.Read)),
			Write: make([]string, len(wi.Spec.AllowedPaths.Write)),
		}
		copy(result.Spec.AllowedPaths.Read, wi.Spec.AllowedPaths.Read)
		copy(result.Spec.AllowedPaths.Write, wi.Spec.AllowedPaths.Write)
	}

	// 오탐 감소 필드 → IntentMeta로 전달
	result.Meta = intent.IntentMeta{
		Priority:           wi.Spec.Priority,
		EnforcementMode:    wi.Spec.EnforcementMode,
		GracePeriodSeconds: wi.Spec.GracePeriodSeconds,
		TTLSeconds:         wi.Spec.TTLSeconds,
		RequireApproval:    wi.Spec.RequireApproval,
		AuditLevel:         wi.Spec.AuditLevel,
		Namespace:          wi.Namespace,
		Source:             "crd",
	}

	return result
}

// MatchesPodLabels checks whether a WorkloadIntent selector matches the given pod labels.
// Supports both matchLabels and matchExpressions for precise targeting (reduces FP).
func MatchesPodLabels(wi *WorkloadIntent, podLabels map[string]string) bool {
	// matchLabels: ALL must match
	for key, want := range wi.Spec.Selector.MatchLabels {
		if podLabels[key] != want {
			return false
		}
	}

	// matchExpressions: ALL must be satisfied
	for _, expr := range wi.Spec.Selector.MatchExpressions {
		val, exists := podLabels[expr.Key]
		switch expr.Operator {
		case "In":
			if !contains(expr.Values, val) {
				return false
			}
		case "NotIn":
			if contains(expr.Values, val) {
				return false
			}
		case "Exists":
			if !exists {
				return false
			}
		case "DoesNotExist":
			if exists {
				return false
			}
		default:
			return false
		}
	}

	return len(wi.Spec.Selector.MatchLabels) > 0 || len(wi.Spec.Selector.MatchExpressions) > 0
}

func contains(slice []string, value string) bool {
	for _, s := range slice {
		if s == value {
			return true
		}
	}
	return false
}
