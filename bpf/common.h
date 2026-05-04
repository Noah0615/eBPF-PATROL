#ifndef __COMMON_H__
#define __COMMON_H__

#define TASK_COMM_LEN 16
#define ARG_LEN 256

enum event_type {
    EVENT_EXEC = 1,
    EVENT_OPEN = 2,
};

struct event {
    __u32 type;
    __u32 pid;
    __u32 tgid;
    __u32 uid;
    char comm[TASK_COMM_LEN];
    char arg1[ARG_LEN];
    char arg2[ARG_LEN];
};

#endif