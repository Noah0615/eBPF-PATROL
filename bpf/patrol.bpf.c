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

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, __u64);
    __type(value, struct intent_flags);
} intent_flags SEC(".maps");

static __always_inline int str_eq(const char *s, const char *lit, int max)
{
    int i;

    for (i = 0; i < max; i++) {
        if (s[i] != lit[i])
            return 0;
        if (lit[i] == '\0')
            return 1;
    }
    return 0;
}

static __always_inline int str_contains(const char *s, const char *needle, int max)
{
    int i;
    int j;

    for (i = 0; i < max; i++) {
        if (s[i] == '\0')
            return 0;

        for (j = 0; j < 32; j++) {
            if (needle[j] == '\0')
                return 1;
            if (i + j >= max || s[i + j] == '\0')
                return 0;
            if (s[i + j] != needle[j])
                break;
        }
    }
    return 0;
}

static __always_inline int is_shell_path(const char *path)
{
    return str_contains(path, "/bin/sh", ARG_LEN) ||
           str_contains(path, "/bin/bash", ARG_LEN) ||
           str_contains(path, "/usr/bin/sh", ARG_LEN) ||
           str_contains(path, "/usr/bin/bash", ARG_LEN);
}

static __always_inline int is_docker_sock_name(const char *name)
{
    return str_eq(name, "docker.sock", ARG_LEN);
}

static __always_inline int is_hard_deny_name(const char *name)
{
    return str_eq(name, "shadow", ARG_LEN) ||
           str_eq(name, "kcore", ARG_LEN);
}

static __always_inline void fill_common(struct event *e)
{
    /* 모든 이벤트에 공통으로 들어가는 기본 정보를 채운다.
     * 누가(PID/UID), 어느 컨테이너(cgroup_id), 언제(timestamp),
     * 어떤 이름의 프로세스(comm)인지 적는 과정이다.
     */
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

static __always_inline void emit_lsm_event(__u32 type, const char *arg1, __u32 flags)
{
    struct event *e;

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return;

    __builtin_memset(e, 0, sizeof(*e));
    e->type = type;
    e->flags = flags;
    fill_common(e);
    if (arg1)
        __builtin_memcpy(&e->arg1, arg1, sizeof(e->arg1));
    bpf_ringbuf_submit(e, 0);
}

SEC("lsm/bprm_check_security")
int BPF_PROG(lsm_exec, struct linux_binprm *bprm, int ret)
{
    const char *filename;
    char path[ARG_LEN];
    __u64 cgroup_id;
    struct intent_flags *flags;

    if (ret != 0)
        return ret;

    filename = BPF_CORE_READ(bprm, filename);
    if (!filename)
        return 0;

    __builtin_memset(path, 0, sizeof(path));
    bpf_probe_read_kernel_str(path, sizeof(path), filename);

    cgroup_id = bpf_get_current_cgroup_id();
    flags = bpf_map_lookup_elem(&intent_flags, &cgroup_id);
    if (!flags)
        return 0;

    if (!flags->allow_shell && is_shell_path(path)) {
        emit_lsm_event(EVENT_EXEC, path, 1);
        return -1;
    }

    return 0;
}

SEC("lsm/file_open")
int BPF_PROG(lsm_file_open, struct file *file, int ret)
{
    struct dentry *dentry;
    const unsigned char *name_ptr;
    char name[ARG_LEN];
    __u64 cgroup_id;
    struct intent_flags *flags;

    if (ret != 0)
        return ret;

    __builtin_memset(name, 0, sizeof(name));
    dentry = BPF_CORE_READ(file, f_path.dentry);
    if (!dentry)
        return 0;
    name_ptr = BPF_CORE_READ(dentry, d_name.name);
    if (!name_ptr)
        return 0;
    bpf_probe_read_kernel_str(name, sizeof(name), name_ptr);

    if (is_hard_deny_name(name)) {
        emit_lsm_event(EVENT_OPEN, name, 1);
        return -1;
    }

    cgroup_id = bpf_get_current_cgroup_id();
    flags = bpf_map_lookup_elem(&intent_flags, &cgroup_id);
    if (!flags)
        return 0;

    if (!flags->allow_docker_sock && is_docker_sock_name(name)) {
        emit_lsm_event(EVENT_OPEN, name, 1);
        return -1;
    }

    return 0;
}

SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve(struct trace_event_raw_sys_enter *ctx)
{
    /* execve는 새 프로그램을 실행할 때 들어오는 syscall이다.
     * /bin/bash, /usr/bin/python 같은 실행 파일 경로를 잡는다.
     */
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
    /* openat은 파일을 열 때 들어오는 syscall이다.
     * /etc/shadow, docker.sock, cgroup 파일 같은 경로를 확인할 수 있다.
     */
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
    /* clone은 새 프로세스/스레드를 만들 때 들어온다.
     * namespace 관련 flag가 있으면 컨테이너 경계 조작 단서가 될 수 있다.
     */
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
    /* unshare는 새 namespace를 만들 때 쓰인다.
     * 컨테이너 탈출 실험에서 자주 나오는 중요한 syscall이다.
     */
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
    /* ptrace는 다른 프로세스를 들여다보거나 제어할 때 쓰인다.
     * 디버깅에는 정상일 수 있지만 공격에도 쓰일 수 있다.
     */
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
    /* mount는 파일시스템을 붙일 때 쓰인다.
     * 일반 앱 컨테이너에서는 드물고, 탈출 공격 흐름에서는 중요하다.
     */
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
    /* socket은 네트워크 통신을 준비할 때 쓰인다.
     * 지금은 family/type만 기록하고, 이후 reverse shell 맥락 분석에 확장할 수 있다.
     */
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
