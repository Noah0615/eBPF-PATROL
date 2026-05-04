package policy

import (
	"path"
	"strings"
)

type HardDenyTarget struct {
	Parent string
	Name   string
}

func (ps *PolicySet) HardDenyTargets() []HardDenyTarget {
	if ps == nil {
		return nil
	}

	seen := make(map[string]struct{})
	var targets []HardDenyTarget

	for _, pol := range ps.Policies {
		if !isDenyAction(pol.Action) {
			continue
		}
		if pol.Type != "open" {
			continue
		}

		for _, pattern := range pol.Match.PathContains {
			target := kernelTarget(pattern)
			if target.Name == "" {
				continue
			}
			seenKey := target.Parent + "/" + target.Name
			if _, ok := seen[seenKey]; ok {
				continue
			}
			seen[seenKey] = struct{}{}
			targets = append(targets, target)
		}
	}

	return targets
}

func isDenyAction(action string) bool {
	switch strings.ToLower(action) {
	case "deny", "block", "reject", "kill":
		return true
	default:
		return false
	}
}

func kernelTarget(pattern string) HardDenyTarget {
	pattern = strings.TrimSpace(pattern)
	if pattern == "" {
		return HardDenyTarget{}
	}

	name := path.Base(pattern)
	if name == "." || name == "/" {
		return HardDenyTarget{}
	}

	parentPath := path.Dir(pattern)
	parent := path.Base(parentPath)
	if parent == "." || parent == "/" {
		parent = ""
	}

	return HardDenyTarget{Parent: parent, Name: name}
}
