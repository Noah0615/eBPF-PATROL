// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
#ifndef __COMMON_H
#define __COMMON_H

#define TASK_COMM_LEN 16
#define MAX_PATH_LEN 256
#define MAX_ARGS 6
#define ARG_LEN 128

enum event_type {
    EVENT_EXEC = 1,
    EVENT_OPEN,
    EVENT_CLONE,
    EVENT_PTRACE,
    EVENT_MOUNT,
    EVENT_SOCKET,
};

struct event {
    __u32 type;
    __u32 pid;
    __u32 tgid;
    __u32 ppid;
    __u32 uid;
    __u32 gid;
    __u64 cgroup_id;
    __u64 timestamp;
    char comm[TASK_COMM_LEN];
    char arg1[ARG_LEN];
    char arg2[ARG_LEN];
    __u32 flags;
};

#endif /* __COMMON_H */