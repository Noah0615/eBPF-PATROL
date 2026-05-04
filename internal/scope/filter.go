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
	// runc:[2:INIT]는 두 가지 상황에서 나온다:
	// 1. 컨테이너 최초 생성 시 → 런타임 노이즈 (mount, clone 등)
	// 2. kubectl exec 시 → 실제 워크로드 행위 (exec, shell 등)
	//
	// exec 타입의 runc:[2:INIT]는 분석 대상이다 (kubectl exec 탐지).
	// mount/clone 등은 런타임 준비 동작이므로 필터링한다.
	if strings.HasPrefix(e.Comm, "runc:") {
		// exec 이벤트는 통과시킴 — kubectl exec로 shell 실행 탐지에 필수
		if e.Type.String() == "exec" {
			return false
		}
		// mount, clone 등 다른 이벤트는 런타임 노이즈로 필터링
		return true
	}

	// comm이 exe로 보이는 /proc/self/exe mount는 runc 자기 자신을 준비하는
	// 정상 동작이라 공격 이벤트와 분리한다.
	if e.Comm == "exe" && isRuntimePath(e.Arg1, e.Arg2) {
		return true
	}

	switch e.Comm {
	case "containerd-shim", "kubelet", "dockerd", "cri-o", "crio", "conmon", "runc":
		return true
	case "containerd":
		// containerd가 exec 이벤트를 발생시키는 경우는 드물지만,
		// mount/clone은 런타임 노이즈로 필터링
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
