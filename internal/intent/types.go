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
}
