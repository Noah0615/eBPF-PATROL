// Package crd defines the Go types for the patrol.ebpf.io/v1alpha1 WorkloadIntent CRD.
package crd

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	GroupName = "patrol.ebpf.io"
	Version   = "v1alpha1"
	Kind      = "WorkloadIntent"
	Resource  = "workloadintents"
)

// WorkloadIntent declares the expected runtime behavior of a workload.
// The eBPF-PATROL agent matches pods via label selectors and enforces
// these behavioral contracts at the kernel level.
type WorkloadIntent struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   WorkloadIntentSpec   `json:"spec"`
	Status WorkloadIntentStatus `json:"status,omitempty"`
}

// WorkloadIntentSpec is the desired state of a WorkloadIntent.
type WorkloadIntentSpec struct {
	// Selector for matching pods by labels.
	Selector Selector `json:"selector"`

	// NamespaceSelector optionally restricts to namespaces with matching labels.
	NamespaceSelector *NamespaceSelector `json:"namespaceSelector,omitempty"`

	// ─── 행위 허용 플래그 ───

	// AllowShell controls whether shell execution (sh/bash/dash/ash/zsh/ksh) is permitted.
	AllowShell bool `json:"allowShell"`

	// AllowNamespaceOps controls namespace manipulation (unshare, setns, mount).
	AllowNamespaceOps bool `json:"allowNamespaceOps"`

	// AllowPrivilegeOps controls privileged operations (ptrace, CAP_SYS_ADMIN).
	AllowPrivilegeOps bool `json:"allowPrivilegeOps"`

	// AllowDockerSock controls access to container runtime sockets.
	AllowDockerSock bool `json:"allowDockerSock"`

	// ─── 세밀한 제어 ───

	// ExpectedProcesses lists process names that are expected inside this workload.
	ExpectedProcesses []string `json:"expectedProcesses,omitempty"`

	// AllowedPaths declares filesystem path prefixes the workload may access.
	AllowedPaths *AllowedPaths `json:"allowedPaths,omitempty"`

	// ─── 오탐 감소 제어 ───

	// Priority determines which intent wins when multiple match the same pod.
	// Higher value = higher priority.
	Priority int `json:"priority"`

	// EnforcementMode controls the action taken on violations:
	//   enforce: actively block violations.
	//   audit:   log violations without blocking.
	//   learn:   observe and build a behavioral baseline.
	EnforcementMode string `json:"enforcementMode"`

	// GracePeriodSeconds is the startup grace period during which violations
	// are logged but NOT blocked, preventing false positives from container
	// startup noise.
	GracePeriodSeconds int `json:"gracePeriodSeconds"`

	// TTLSeconds auto-expires this intent after N seconds. 0 = no expiry.
	TTLSeconds int `json:"ttlSeconds,omitempty"`

	// RequireApproval requires an approval annotation on the pod.
	RequireApproval bool `json:"requireApproval,omitempty"`

	// AuditLevel controls audit log verbosity: minimal, standard, verbose.
	AuditLevel string `json:"auditLevel,omitempty"`
}

// Selector matches pods by labels.
type Selector struct {
	MatchLabels      map[string]string    `json:"matchLabels,omitempty"`
	MatchExpressions []SelectorExpression `json:"matchExpressions,omitempty"`
}

// SelectorExpression is a single label requirement.
type SelectorExpression struct {
	Key      string   `json:"key"`
	Operator string   `json:"operator"`
	Values   []string `json:"values,omitempty"`
}

// NamespaceSelector restricts intent matching to certain namespaces.
type NamespaceSelector struct {
	MatchLabels map[string]string `json:"matchLabels,omitempty"`
}

// AllowedPaths declares read and write path prefixes.
type AllowedPaths struct {
	Read  []string `json:"read,omitempty"`
	Write []string `json:"write,omitempty"`
}

// WorkloadIntentStatus is the observed state of a WorkloadIntent.
type WorkloadIntentStatus struct {
	MatchedPods         int                `json:"matchedPods"`
	MaterializedCgroups int                `json:"materializedCgroups"`
	LastSyncTime        string             `json:"lastSyncTime,omitempty"`
	Conditions          []IntentCondition  `json:"conditions,omitempty"`
}

// IntentCondition describes the state of a WorkloadIntent at a point in time.
type IntentCondition struct {
	Type               string `json:"type"`
	Status             string `json:"status"`
	LastTransitionTime string `json:"lastTransitionTime,omitempty"`
	Reason             string `json:"reason,omitempty"`
	Message            string `json:"message,omitempty"`
}

// WorkloadIntentList is a list of WorkloadIntent resources.
type WorkloadIntentList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`

	Items []WorkloadIntent `json:"items"`
}
