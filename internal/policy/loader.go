// 규칙 적힌 파일을 읽어서 프로그램이 이해할 수 있게 바꾸는 것
package policy

import (
	"os"

	"gopkg.in/yaml.v3"
)

func LoadFromFile(path string) ([]Policy, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var cfg Config
	if err := yaml.Unmarshal(b, &cfg); err != nil {
		return nil, err
	}

	return cfg.Policies, nil
}