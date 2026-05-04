package bpf

import (
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

type Objects struct {
	TraceExecve  *ebpf.Program `ebpf:"trace_execve"`
	TraceOpenat  *ebpf.Program `ebpf:"trace_openat"`
	TraceClone   *ebpf.Program `ebpf:"trace_clone"`
	TracePtrace  *ebpf.Program `ebpf:"trace_ptrace"`
	TraceMount   *ebpf.Program `ebpf:"trace_mount"`
	TraceSocket  *ebpf.Program `ebpf:"trace_socket"`
	TraceUnshare *ebpf.Program `ebpf:"trace_unshare"`
	Events       *ebpf.Map     `ebpf:"events"`

	links []link.Link
}

func (o *Objects) Close() {
	for _, l := range o.links {
		if l != nil {
			_ = l.Close()
		}
	}
	if o.TraceExecve != nil {
		_ = o.TraceExecve.Close()
	}
	if o.TraceOpenat != nil {
		_ = o.TraceOpenat.Close()
	}
	if o.TraceClone != nil {
		_ = o.TraceClone.Close()
	}
	if o.TracePtrace != nil {
		_ = o.TracePtrace.Close()
	}
	if o.TraceMount != nil {
		_ = o.TraceMount.Close()
	}
	if o.TraceSocket != nil {
		_ = o.TraceSocket.Close()
	}
	if o.TraceUnshare != nil {
		_ = o.TraceUnshare.Close()
	}
	if o.Events != nil {
		_ = o.Events.Close()
	}
}

func LoadObjects(objPath string) (*Objects, *ringbuf.Reader, error) {
	spec, err := ebpf.LoadCollectionSpec(objPath)
	if err != nil {
		return nil, nil, fmt.Errorf("load spec: %w", err)
	}

	objs := &Objects{}
	if err := spec.LoadAndAssign(objs, nil); err != nil {
		return nil, nil, fmt.Errorf("load and assign: %w", err)
	}

	attachments := []struct {
		name    string
		group   string
		event   string
		program *ebpf.Program
	}{
		{"execve", "syscalls", "sys_enter_execve", objs.TraceExecve},
		{"openat", "syscalls", "sys_enter_openat", objs.TraceOpenat},
		{"clone", "syscalls", "sys_enter_clone", objs.TraceClone},
		{"ptrace", "syscalls", "sys_enter_ptrace", objs.TracePtrace},
		{"mount", "syscalls", "sys_enter_mount", objs.TraceMount},
		{"socket", "syscalls", "sys_enter_socket", objs.TraceSocket},
		{"unshare", "syscalls", "sys_enter_unshare", objs.TraceUnshare},
	}

	for _, att := range attachments {
		l, err := link.Tracepoint(att.group, att.event, att.program, nil)
		if err != nil {
			objs.Close()
			return nil, nil, fmt.Errorf("attach %s: %w", att.name, err)
		}
		objs.links = append(objs.links, l)
	}

	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		objs.Close()
		return nil, nil, fmt.Errorf("ringbuf reader: %w", err)
	}

	return objs, rd, nil
}
