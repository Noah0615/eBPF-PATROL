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
	// Scope Filter는 "이 이벤트를 우리가 봐야 하나?"를 먼저 고르는 문지기다.
	// containers 모드에서는 host 잡음과 컨테이너 런타임 준비 동작을 줄인다.
	if f == nil || f.mode == ModeAll {
		return true
	}

	if isRuntimeInfrastructure(e) {
		return false
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

func isRuntimeInfrastructure(e *event.Event) bool {
	// runc:[2:INIT] 같은 프로세스는 컨테이너 안 앱이 아니라 런타임이
	// 컨테이너를 만들거나 kubectl exec/cp를 준비하는 과정에서 생긴다.
	if strings.HasPrefix(e.Comm, "runc:") {
		return true
	}

	// comm이 exe로 보이는 /proc/self/exe mount는 runc 자기 자신을 준비하는
	// 정상 동작이라 공격 이벤트와 분리한다.
	if e.Comm == "exe" && isRuntimePath(e.Arg1, e.Arg2) {
		return true
	}

	switch e.Comm {
	case "containerd", "containerd-shim", "kubelet", "dockerd", "cri-o", "crio", "conmon", "runc":
		return true
	default:
		return false
	}
}

func isRuntimePath(values ...string) bool {
	for _, value := range values {
		if strings.Contains(value, "/run/containerd/runc/") ||
			strings.Contains(value, "/run/containerd/io.containerd.runtime.v2.task/") ||
			strings.Contains(value, "/var/lib/containerd/") ||
			strings.Contains(value, "/var/lib/kubelet/pods/") ||
			strings.Contains(value, "/proc/self/exe") {
			return true
		}
	}
	return false
}

func processID(e *event.Event) uint32 {
	if e.Tgid != 0 {
		return e.Tgid
	}
	return e.Pid
}

func processLooksContainerized(pid uint32) (bool, bool) {
	// /proc/<pid>/cgroup을 읽어서 Kubernetes/container cgroup인지 확인한다.
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
