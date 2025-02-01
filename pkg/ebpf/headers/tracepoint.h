#ifndef __TRACEPOINT_H
#define __TRACEPOINT_H

#include <linux/types.h>

// sys_enter tracepoint 结构
struct trace_event_raw_sys_enter {
    __u64 unused;
    long id;
    long args[6];
};

// sched_process_exec tracepoint 结构
struct trace_event_raw_sched_process_exec {
    __u64 unused;
    char comm[16];
    __u32 pid;
    __u32 old_pid;
    struct linux_binprm *bprm;
};

// bind syscall 参数结构
struct sockaddr_in {
    __u16 sin_family;
    __u16 sin_port;
    __u32 sin_addr;
    __u8  sin_zero[8];
};

#endif /* __TRACEPOINT_H */ 