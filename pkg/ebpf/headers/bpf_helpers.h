#ifndef __BPF_HELPERS_H
#define __BPF_HELPERS_H

// 帮助函数声明
static __always_inline __u64 get_current_pid_tgid(void) {
    return bpf_get_current_pid_tgid();
}

static __always_inline __u64 get_current_uid_gid(void) {
    return bpf_get_current_uid_gid();
}

#endif /* __BPF_HELPERS_H */ 