package bpf

import (
	"fmt"

	"ebpf-patrol/internal/intent"

	"github.com/cilium/ebpf"
)

type IntentFlags struct {
	AllowShell        uint32
	AllowNamespaceOps uint32
	AllowPrivilegeOps uint32
	AllowDockerSock   uint32
}

type IntentFlagUpdater struct {
	m *ebpf.Map
}

func NewIntentFlagUpdater(m *ebpf.Map) *IntentFlagUpdater {
	return &IntentFlagUpdater{m: m}
}

func (u *IntentFlagUpdater) UpdateIntentFlags(materialized map[uint64]intent.MaterializedIntent) error {
	if u == nil || u.m == nil {
		return nil
	}

	if err := u.clear(); err != nil {
		return err
	}

	for cgroupID, materializedIntent := range materialized {
		flags := flagsFromSpec(materializedIntent.Intent.Spec)
		if err := u.m.Put(cgroupID, flags); err != nil {
			return fmt.Errorf("put intent flags for cgroup %d: %w", cgroupID, err)
		}
	}

	return nil
}

func (u *IntentFlagUpdater) clear() error {
	var key uint64
	var value IntentFlags
	iter := u.m.Iterate()
	for iter.Next(&key, &value) {
		if err := u.m.Delete(key); err != nil {
			return fmt.Errorf("delete old intent flags for cgroup %d: %w", key, err)
		}
	}
	if err := iter.Err(); err != nil {
		return fmt.Errorf("iterate intent flags: %w", err)
	}
	return nil
}

func flagsFromSpec(spec intent.IntentSpec) IntentFlags {
	return IntentFlags{
		AllowShell:        boolToU32(spec.AllowShell),
		AllowNamespaceOps: boolToU32(spec.AllowNamespaceOps),
		AllowPrivilegeOps: boolToU32(spec.AllowPrivilegeOps),
		AllowDockerSock:   boolToU32(spec.AllowDockerSock),
	}
}

func boolToU32(value bool) uint32 {
	if value {
		return 1
	}
	return 0
}
