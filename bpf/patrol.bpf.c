// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "common.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);  // 16MB
} events SEC(".maps");

static __always_inline void fill_common(struct event *e)
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 uid_gid = bpf_get_current_uid_gid();

    e->tgid = pid_tgid >> 32;
    e->pid = (__u32)pid_tgid;
    e->uid = (__u32)uid_gid;
    e->gid = uid_gid >> 32;
    e->timestamp = bpf_ktime_get_ns();
    e->cgroup_id = bpf_get_current_cgroup_id();
    
    BPF_CORE_READ_INTO(&e->ppid, task, real_parent, tgid);
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
}

SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve(struct trace_event_raw_sys_enter *ctx)
{
    struct event *e;
    const char *filename = (const char *)ctx->args[0];

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    __builtin_memset(e, 0, sizeof(*e));
    e->type = EVENT_EXEC;
    fill_common(e);
    bpf_probe_read_user_str(&e->arg1, sizeof(e->arg1), filename);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_openat")
int trace_openat(struct trace_event_raw_sys_enter *ctx)
{
    struct event *e;
    const char *filename = (const char *)ctx->args[1];
    int flags = (int)ctx->args[2];

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    __builtin_memset(e, 0, sizeof(*e));
    e->type = EVENT_OPEN;
    e->flags = flags;
    fill_common(e);
    bpf_probe_read_user_str(&e->arg1, sizeof(e->arg1), filename);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_clone")
int trace_clone(struct trace_event_raw_sys_enter *ctx)
{
    struct event *e;
    unsigned long flags = (unsigned long)ctx->args[0];

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    __builtin_memset(e, 0, sizeof(*e));
    e->type = EVENT_CLONE;
    e->flags = (__u32)flags;
    fill_common(e);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_unshare")
int trace_unshare(struct trace_event_raw_sys_enter *ctx)
{
    struct event *e;
    unsigned long flags = (unsigned long)ctx->args[0];

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    __builtin_memset(e, 0, sizeof(*e));
    e->type = EVENT_UNSHARE;
    e->flags = (__u32)flags;
    fill_common(e);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_ptrace")
int trace_ptrace(struct trace_event_raw_sys_enter *ctx)
{
    struct event *e;
    long request = (long)ctx->args[0];

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    __builtin_memset(e, 0, sizeof(*e));
    e->type = EVENT_PTRACE;
    e->flags = request;
    fill_common(e);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_mount")
int trace_mount(struct trace_event_raw_sys_enter *ctx)
{
    struct event *e;
    const char *source = (const char *)ctx->args[0];
    const char *target = (const char *)ctx->args[1];

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    __builtin_memset(e, 0, sizeof(*e));
    e->type = EVENT_MOUNT;
    fill_common(e);
    bpf_probe_read_user_str(&e->arg1, sizeof(e->arg1), source);
    bpf_probe_read_user_str(&e->arg2, sizeof(e->arg2), target);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_socket")
int trace_socket(struct trace_event_raw_sys_enter *ctx)
{
    struct event *e;
    int family = (int)ctx->args[0];
    int type = (int)ctx->args[1];

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    __builtin_memset(e, 0, sizeof(*e));
    e->type = EVENT_SOCKET;
    e->flags = (family << 16) | type;
    fill_common(e);

    bpf_ringbuf_submit(e, 0);
    return 0;
}
