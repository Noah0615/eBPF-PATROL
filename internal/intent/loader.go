package intent

import (
	"errors"
	"os"

	"gopkg.in/yaml.v3"
)

func Load(path string) (*IntentSet, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return &IntentSet{}, nil
		}
		return nil, err
	}

	var intents IntentSet
	if err := yaml.Unmarshal(data, &intents); err != nil {
		return nil, err
	}
	intents.Materialized = make(map[uint64]MaterializedIntent)

	return &intents, nil
}
