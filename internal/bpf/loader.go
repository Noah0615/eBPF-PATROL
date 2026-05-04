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
	LSMExec      *ebpf.Program `ebpf:"lsm_exec"`
	LSMFileOpen  *ebpf.Program `ebpf:"lsm_file_open"`
	Events       *ebpf.Map     `ebpf:"events"`
	IntentFlags  *ebpf.Map     `ebpf:"intent_flags"`

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
	if o.LSMExec != nil {
		_ = o.LSMExec.Close()
	}
	if o.LSMFileOpen != nil {
		_ = o.LSMFileOpen.Close()
	}
	if o.Events != nil {
		_ = o.Events.Close()
	}
	if o.IntentFlags != nil {
		_ = o.IntentFlags.Close()
	}
}

func LoadObjects(objPath string) (*Objects, *ringbuf.Reader, error) {
	spec, err := ebpf.LoadCollectionSpec(objPath)
	if err != nil {
		return nil, nil, fmt.Errorf("load spec: %w", err)
	}
	if err := validateSpec(spec); err != nil {
		return nil, nil, err
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

	lsmAttachments := []struct {
		name    string
		program *ebpf.Program
	}{
		{"lsm_exec", objs.LSMExec},
		{"lsm_file_open", objs.LSMFileOpen},
	}

	for _, att := range lsmAttachments {
		l, err := link.AttachLSM(link.LSMOptions{Program: att.program})
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

func validateSpec(spec *ebpf.CollectionSpec) error {
	requiredPrograms := []string{
		"trace_execve",
		"trace_openat",
		"trace_clone",
		"trace_ptrace",
		"trace_mount",
		"trace_socket",
		"trace_unshare",
		"lsm_exec",
		"lsm_file_open",
	}
	for _, name := range requiredPrograms {
		if _, ok := spec.Programs[name]; !ok {
			return fmt.Errorf("BPF object is missing program %q; rebuild it with `make clean && make bpf`", name)
		}
	}
	if _, ok := spec.Maps["events"]; !ok {
		return fmt.Errorf("BPF object is missing map %q; rebuild it with `make clean && make bpf`", "events")
	}
	if _, ok := spec.Maps["intent_flags"]; !ok {
		return fmt.Errorf("BPF object is missing map %q; rebuild it with `make clean && make bpf`", "intent_flags")
	}
	return nil
}
