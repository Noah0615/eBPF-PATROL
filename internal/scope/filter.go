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
	// Scope Filter는 "우리가 지금 볼 대상인가?"를 먼저 거르는 문지기다.
	// 기본 모드(containers)에서는 host의 VS Code, kubelet 같은 잡음을 줄이고,
	// 컨테이너 안에서 나온 이벤트만 분석하려고 한다.
	if f == nil || f.mode == ModeAll {
		return true
	}

	if isRuntimeInfrastructure(e.Comm) {
		// containerd-shim 같은 런타임 프로세스는 컨테이너 안 앱이 아니다.
		// 이런 프로세스는 cgroup 파일을 많이 읽어서 오탐을 만들기 쉽다.
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

func isRuntimeInfrastructure(comm string) bool {
	// Kubernetes/Container runtime을 움직이는 도우미 프로세스들이다.
	// 공격자가 아니라 시스템 관리자가 일하는 소리인 경우가 대부분이다.
	switch comm {
	case "containerd", "containerd-shim", "kubelet", "dockerd", "cri-o", "crio", "conmon", "runc":
		return true
	default:
		return false
	}
}

func processID(e *event.Event) uint32 {
	if e.Tgid != 0 {
		return e.Tgid
	}
	return e.Pid
}

func processLooksContainerized(pid uint32) (bool, bool) {
	// /proc/<pid>/cgroup 파일을 보면 이 프로세스가 어느 cgroup에 있는지 알 수 있다.
	// kubepods, docker, containerd 같은 단어가 있으면 컨테이너 쪽 이벤트로 본다.
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
