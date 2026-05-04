package bpf

import (
	"fmt"

	"ebpf-patrol/internal/policy"

	"github.com/cilium/ebpf"
)

const hardDenyNameLen = 64

type HardDenyName struct {
	Parent [hardDenyNameLen]byte
	Name [hardDenyNameLen]byte
}

type PolicyMapUpdater struct {
	m *ebpf.Map
}

func NewPolicyMapUpdater(m *ebpf.Map) *PolicyMapUpdater {
	return &PolicyMapUpdater{m: m}
}

func (u *PolicyMapUpdater) ReplaceHardDenyTargets(targets []policy.HardDenyTarget) error {
	if u == nil || u.m == nil {
		return nil
	}

	if err := u.clear(); err != nil {
		return err
	}

	for _, target := range targets {
		key, err := hardDenyKey(target)
		if err != nil {
			return err
		}
		value := uint32(1)
		if err := u.m.Put(key, value); err != nil {
			return fmt.Errorf("put hard deny target %q/%q: %w", target.Parent, target.Name, err)
		}
	}

	return nil
}

func (u *PolicyMapUpdater) clear() error {
	var key HardDenyName
	var value uint32
	iter := u.m.Iterate()
	for iter.Next(&key, &value) {
		if err := u.m.Delete(key); err != nil {
			return fmt.Errorf("delete old hard deny name: %w", err)
		}
	}
	if err := iter.Err(); err != nil {
		return fmt.Errorf("iterate hard deny names: %w", err)
	}
	return nil
}

func hardDenyKey(target policy.HardDenyTarget) (HardDenyName, error) {
	var key HardDenyName
	if len(target.Name) == 0 {
		return key, fmt.Errorf("empty hard deny name")
	}
	if len(target.Name) >= hardDenyNameLen {
		return key, fmt.Errorf("hard deny name %q is too long", target.Name)
	}
	if len(target.Parent) >= hardDenyNameLen {
		return key, fmt.Errorf("hard deny parent %q is too long", target.Parent)
	}
	copy(key.Parent[:], target.Parent)
	copy(key.Name[:], target.Name)
	return key, nil
}
