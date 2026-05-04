// 규칙이 어떻게 생겼는지 설계도
package policy

type Config struct {
	Policies []Policy `yaml:"policies"`
}

type Policy struct {
	Name   string    `yaml:"name"`
	Type   string    `yaml:"type"`
	Match  MatchSpec `yaml:"match"`
	Action string    `yaml:"action"`
}

type MatchSpec struct {
	FileContains []string `yaml:"file_contains"`
	CommEquals   []string `yaml:"comm_equals"`
}