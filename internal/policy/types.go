package policy

type PolicySet struct {
	Policies []Policy `yaml:"policies"`
}

type Policy struct {
	Name        string      `yaml:"name"`
	Type        string      `yaml:"type"`
	Match       MatchRule   `yaml:"match"`
	Action      string      `yaml:"action"`
	Description string      `yaml:"description"`
	Severity    string      `yaml:"severity"`
}

type MatchRule struct {
	FileContains []string `yaml:"file_contains"`
	PathContains []string `yaml:"path_contains"`
	CommEquals   string   `yaml:"comm_equals"`
	CommContains []string `yaml:"comm_contains"`
	UidNot       *uint32  `yaml:"uid_not"`
	UidEquals    *uint32  `yaml:"uid_equals"`
	FlagsAny     *uint32  `yaml:"flags_any"`
}