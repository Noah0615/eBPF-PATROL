package intent

type IntentSet struct {
	Intents []Intent `yaml:"intents"`
}

type Intent struct {
	Name  string      `yaml:"name"`
	Match IntentMatch `yaml:"match"`
	Spec  IntentSpec  `yaml:"spec"`
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
