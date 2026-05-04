package bpf

import (
	"bytes"
	_ "embed"
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

//go:embed ../../gen/patrol_bpfel.o
var patrolObj []byte

type Objects struct {
	TraceExecve *ebpf.Program `ebpf:"trace_execve"`
	TraceOpenat *ebpf.Program `ebpf:"trace_openat"`
	Events      *ebpf.Map     `ebpf:"events"`

	execLink link.Link
	openLink link.Link
}

func (o *Objects) Close() {
	if o.execLink != nil {
		_ = o.execLink.Close()
	}
	if o.openLink != nil {
		_ = o.openLink.Close()
	}
	if o.TraceExecve != nil {
		_ = o.TraceExecve.Close()
	}
	if o.TraceOpenat != nil {
		_ = o.TraceOpenat.Close()
	}
	if o.Events != nil {
		_ = o.Events.Close()
	}
}

func LoadObjects() (*Objects, *ringbuf.Reader, error) {
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(patrolObj))
	if err != nil {
		return nil, nil, fmt.Errorf("load patrol spec: %w", err)
	}

	objs := &Objects{}
	if err := spec.LoadAndAssign(objs, nil); err != nil {
		return nil, nil, fmt.Errorf("load patrol objects: %w", err)
	}

	execLink, err := link.Tracepoint("syscalls", "sys_enter_execve", objs.TraceExecve, nil)
	if err != nil {
		objs.Close()
		return nil, nil, fmt.Errorf("attach execve: %w", err)
	}
	objs.execLink = execLink

	openLink, err := link.Tracepoint("syscalls", "sys_enter_openat", objs.TraceOpenat, nil)
	if err != nil {
		objs.Close()
		return nil, nil, fmt.Errorf("attach openat: %w", err)
	}
	objs.openLink = openLink

	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		objs.Close()
		return nil, nil, fmt.Errorf("ringbuf reader: %w", err)
	}

	return objs, rd, nil
}