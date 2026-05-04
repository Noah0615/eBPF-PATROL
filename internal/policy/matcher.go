package policy

import "strings"

type ExecLike interface {
	GetComm() string
	GetFile() string
}
// 규칙 검사
func MatchExec(p Policy, comm, file string) bool {
	if p.Type != "exec" {
		return false
	}
	// 규칙에 커맨드 조건이 있으면 검사
	if len(p.Match.CommEquals) > 0 {
		ok := false
		for _, c := range p.Match.CommEquals {
			if comm == c {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	// 규칙에 파일 조건이 있으면 검사
	if len(p.Match.FileContains) > 0 {
		ok := false
		for _, s := range p.Match.FileContains {
			if strings.Contains(file, s) {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}

	return true
}