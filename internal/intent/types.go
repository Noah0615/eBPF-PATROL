package intent

import "sync"

type IntentSet struct {
	Intents      []Intent                      `yaml:"intents"`
	mu           sync.RWMutex                  `yaml:"-"`
	Materialized map[uint64]MaterializedIntent `yaml:"-"`
}

type Intent struct {
	Name     string        `yaml:"name"`
	Selector LabelSelector `yaml:"selector"`
	Match    IntentMatch   `yaml:"match"`
	Spec     IntentSpec    `yaml:"spec"`
	Meta     IntentMeta    `yaml:"-"` // CRD에서 주입되는 오탐 감소 메타데이터
}

type LabelSelector struct {
	MatchLabels map[string]string `yaml:"matchLabels"`
}

type IntentMatch struct {
	CgroupIDs    []uint64 `yaml:"cgroup_ids"`
	CommEquals   string   `yaml:"comm_equals"`
	CommContains []string `yaml:"comm_contains"`
}

type IntentSpec struct {
	AllowShell        bool         `yaml:"allowShell"`
	AllowNamespaceOps bool         `yaml:"allowNamespaceOps"`
	AllowPrivilegeOps bool         `yaml:"allowPrivilegeOps"`
	AllowDockerSock   bool         `yaml:"allowDockerSock"`
	AllowedPaths      AllowedPaths `yaml:"allowedPaths"`
	ExpectedProcesses []string     `yaml:"expectedProcesses"`
}

type AllowedPaths struct {
	Read  []string `yaml:"read"`
	Write []string `yaml:"write"`
}

type MaterializedIntent struct {
	Intent         Intent
	PodName        string
	Namespace      string
	PodUID         string
	ContainerID    string
	CgroupPath     string
	MaterializedBy string
	MaterializedAt int64 // Unix timestamp: grace period 계산에 사용
}

// IntentMeta carries CRD-sourced metadata for false-positive reduction.
// YAML intents get zero-value defaults (enforce mode, 0 grace period).
type IntentMeta struct {
	Priority           int    // 높을수록 우선: 겹치는 intent 중 가장 정확한 것 사용
	EnforcementMode    string // "enforce" | "audit" | "learn"
	GracePeriodSeconds int    // 시작 후 N초간 violation을 차단하지 않음
	TTLSeconds         int    // 자동 만료 시간 (0 = 만료 없음)
	RequireApproval    bool   // 사전 승인 필요 여부
	AuditLevel         string // "minimal" | "standard" | "verbose"
	Namespace          string // CRD의 네임스페이스
	Source             string // "yaml" | "crd"
}

