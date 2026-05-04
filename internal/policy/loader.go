package policy

import (
	"os"

	"gopkg.in/yaml.v3"
)

func LoadPolicies(path string) (*PolicySet, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var ps PolicySet
	if err := yaml.Unmarshal(data, &ps); err != nil {
		return nil, err
	}

	return &ps, nil
}