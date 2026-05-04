package analyzer

import (
	"fmt"
	"log"
	"time"

	"ebpf-patrol/internal/event"
	"ebpf-patrol/internal/policy"
)

type Analyzer struct {
	policies *policy.PolicySet
	stats    map[string]int
}

func New(policies *policy.PolicySet) *Analyzer {
	return &Analyzer{
		policies: policies,
		stats:    make(map[string]int),
	}
}

func (a *Analyzer) Analyze(e *event.Event) {
	for _, pol := range a.policies.Policies {
		if pol.Matches(e) {
			a.handleMatch(&pol, e)
		}
	}
}

func (a *Analyzer) handleMatch(pol *policy.Policy, e *event.Event) {
	a.stats[pol.Name]++
	
	timestamp := time.Now()
	severity := pol.Severity
	if severity == "" {
		severity = "INFO"
	}

	logMsg := fmt.Sprintf("[%s] [%s] Policy=%s Type=%s PID=%d PPID=%d UID=%d Comm=%s Arg1=%s Cgroup=%d Action=%s",
		timestamp.Format("2006-01-02 15:04:05"),
		severity,
		pol.Name,
		e.Type.String(),
		e.Pid,
		e.Ppid,
		e.Uid,
		e.Comm,
		e.Arg1,
		e.CgroupID,
		pol.Action,
	)

	switch pol.Action {
	case "log":
		log.Println(logMsg)
	case "alert":
		log.Println(logMsg)
		fmt.Printf("🚨 ALERT: %s - %s (PID=%d, Comm=%s, Arg=%s)\n",
			pol.Name, pol.Description, e.Pid, e.Comm, e.Arg1)
	default:
		log.Println(logMsg)
	}
}

func (a *Analyzer) PrintStats() {
	fmt.Println("\n=== Detection Statistics ===")
	for name, count := range a.stats {
		fmt.Printf("%s: %d detections\n", name, count)
	}
}