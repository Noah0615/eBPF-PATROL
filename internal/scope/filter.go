package scope

import (
	"fmt"
	"os"
	"strings"

	"ebpf-patrol/internal/event"
)

const (
	ModeContainers = "containers"
	ModeAll        = "all"
)

type Filter struct {
	mode  string
	cache map[uint64]bool
}

func New(mode string) *Filter {
	if mode == "" {
		mode = ModeContainers
	}
	return &Filter{
		mode:  mode,
		cache: make(map[uint64]bool),
	}
}

func (f *Filter) ShouldAnalyze(e *event.Event) bool {
	if f == nil || f.mode == ModeAll {
		return true
	}

	if allowed, ok := f.cache[e.CgroupID]; ok {
		return allowed
	}

	allowed, ok := processLooksContainerized(processID(e))
	if ok {
		f.cache[e.CgroupID] = allowed
	}
	return allowed
}

func processID(e *event.Event) uint32 {
	if e.Tgid != 0 {
		return e.Tgid
	}
	return e.Pid
}

func processLooksContainerized(pid uint32) (bool, bool) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", pid))
	if err != nil {
		return false, false
	}

	cgroup := string(data)
	return containsAny(cgroup, []string{
		"kubepods",
		"cri-containerd",
		"crio",
		"docker",
		"libpod",
		"containerd",
	}), true
}

func containsAny(value string, patterns []string) bool {
	for _, pattern := range patterns {
		if strings.Contains(value, pattern) {
			return true
		}
	}
	return false
}
