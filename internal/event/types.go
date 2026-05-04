package event

import "fmt"

type EventType uint32

const (
	EventExec EventType = 1
	EventOpen EventType = 2
	EventClone EventType = 3
	EventPtrace EventType = 4
	EventMount EventType = 5
	EventSocket EventType = 6
)

func (t EventType) String() string {
	switch t {
	case EventExec:
		return "exec"
	case EventOpen:
		return "open"
	case EventClone:
		return "clone"
	case EventPtrace:
		return "ptrace"
	case EventMount:
		return "mount"
	case EventSocket:
		return "socket"
	default:
		return "unknown"
	}
}

type Event struct {
	Type      EventType
	Pid       uint32
	Tgid      uint32
	Ppid      uint32
	Uid       uint32
	Gid       uint32
	CgroupID  uint64
	Timestamp uint64
	Comm      string
	Arg1      string
	Arg2      string
	Flags     uint32
}

func (e *Event) String() string {
	return fmt.Sprintf("type=%s pid=%d ppid=%d uid=%d comm=%s arg1=%s cgroup=%d",
		e.Type, e.Pid, e.Ppid, e.Uid, e.Comm, e.Arg1, e.CgroupID)
}