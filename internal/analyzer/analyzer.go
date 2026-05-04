// 모든 정책 다 검사함
package analyzer

import (
	"log"

	"ebpf-patrol/internal/event"
	"ebpf-patrol/internal/policy"
)

type Analyzer struct {
	policies []policy.Policy
}

func New(policies []policy.Policy) *Analyzer {
	return &Analyzer{policies: policies}
}

// 이벤트를 받아서 정책에 걸리는지 검사하고 결과를 출력하는 코드
func (a *Analyzer) HandleExec(ev event.ExecEvent) {
	log.Printf("[exec] pid=%d tgid=%d uid=%d comm=%s file=%s",
		ev.Pid, ev.Tgid, ev.Uid, ev.Comm, ev.File)

	for _, p := range a.policies {
		if policy.MatchExec(p, ev.Comm, ev.File) {
			log.Printf("[match] policy=%s action=%s pid=%d comm=%s file=%s",
				p.Name, p.Action, ev.Pid, ev.Comm, ev.File)
		}
	}
}