package k8s

import (
	"io/fs"
	"path/filepath"
	"strings"
	"syscall"
)

type CgroupMatch struct {
	CgroupID uint64
	Path     string
}

func ScanCgroups(root string, podUIDs []string) (map[string][]CgroupMatch, error) {
	if root == "" {
		root = "/sys/fs/cgroup"
	}

	needles := make(map[string][]string)
	for _, uid := range podUIDs {
		if uid == "" {
			continue
		}
		needles[uid] = []string{
			uid,
			strings.ReplaceAll(uid, "-", "_"),
		}
	}
	if len(needles) == 0 {
		return map[string][]CgroupMatch{}, nil
	}

	matches := make(map[string][]CgroupMatch)
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return nil
		}
		if !entry.IsDir() {
			return nil
		}

		for uid, variants := range needles {
			if !containsVariant(path, variants) {
				continue
			}

			var stat syscall.Stat_t
			if err := syscall.Stat(path, &stat); err != nil {
				continue
			}
			matches[uid] = append(matches[uid], CgroupMatch{
				CgroupID: uint64(stat.Ino),
				Path:     path,
			})
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	return matches, nil
}

func containsVariant(path string, variants []string) bool {
	for _, variant := range variants {
		if strings.Contains(path, variant) {
			return true
		}
	}
	return false
}
