package policy

import (
	"strings"

	"ebpf-patrol/internal/event"
)

func (p *Policy) Matches(e *event.Event) bool {
	// Type check
	if p.Type != e.Type.String() {
		return false
	}

	// File contains (for exec)
	if len(p.Match.FileContains) > 0 {
		matched := false
		for _, pattern := range p.Match.FileContains {
			if strings.Contains(e.Arg1, pattern) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	// Path contains (for open/mount)
	if len(p.Match.PathContains) > 0 {
		matched := false
		for _, pattern := range p.Match.PathContains {
			if strings.Contains(e.Arg1, pattern) || strings.Contains(e.Arg2, pattern) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	// Comm equals
	if p.Match.CommEquals != "" && e.Comm != p.Match.CommEquals {
		return false
	}

	// Comm contains
	if len(p.Match.CommContains) > 0 {
		matched := false
		for _, pattern := range p.Match.CommContains {
			if strings.Contains(e.Comm, pattern) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	// UID not
	if p.Match.UidNot != nil && e.Uid == *p.Match.UidNot {
		return false
	}

	// UID equals
	if p.Match.UidEquals != nil && e.Uid != *p.Match.UidEquals {
		return false
	}

	// Flags check
	if p.Match.FlagsAny != nil && (e.Flags&*p.Match.FlagsAny) == 0 {
		return false
	}

	return true
}