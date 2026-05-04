package k8s

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
)

type PodSource interface {
	ListPods(ctx context.Context) ([]Pod, error)
}

type KubectlSource struct {
	Binary string
}

func NewKubectlSource(binary string) *KubectlSource {
	if binary == "" {
		binary = "kubectl"
	}
	return &KubectlSource{Binary: binary}
}

func (s *KubectlSource) ListPods(ctx context.Context) ([]Pod, error) {
	cmd := exec.CommandContext(ctx, s.Binary, "get", "pods", "-A", "-o", "json")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("kubectl get pods: %w: %s", err, string(out))
	}

	var list PodList
	if err := json.Unmarshal(out, &list); err != nil {
		return nil, fmt.Errorf("parse kubectl pod JSON: %w", err)
	}

	return list.Items, nil
}
