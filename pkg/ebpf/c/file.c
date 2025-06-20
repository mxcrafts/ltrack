#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

// Add AT_REMOVEDIR definition
#ifndef AT_REMOVEDIR
#define AT_REMOVEDIR 0x200
#endif

#define MAX_FILENAME_LEN 256
#define MAX_COMM_LEN 16

// Event type definition
#define EVENT_OPEN    1
#define EVENT_CREATE  2
#define EVENT_UNLINK  3
#define EVENT_MKDIR   4
#define EVENT_RMDIR   5

struct event {
    __u32 pid;           // Process ID
    __u32 ppid;          // Parent process ID
    __u32 uid;           // User ID
    __u32 event_type;    // Event type
    char filename[MAX_FILENAME_LEN];
    char comm[MAX_COMM_LEN];      // Process name
    char pcomm[MAX_COMM_LEN];     // Parent process name
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

static __always_inline int process_event(struct pt_regs *ctx, const char *filename, int event_type) {
    struct event *e;
    struct task_struct *task, *parent;
    
    // Debug: Print event type
    bpf_printk("Processing event type: %d for file: %s\n", event_type, filename);
    
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) 
        return 0;

    // Get current process information
    task = (struct task_struct *)bpf_get_current_task();
    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->uid = bpf_get_current_uid_gid() >> 32;
    
    // ensure comm field is correctly cleared and filled
    __builtin_memset(&e->comm, 0, sizeof(e->comm));
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    // Get parent process information
    parent = BPF_CORE_READ(task, real_parent);
    e->ppid = BPF_CORE_READ(parent, tgid);
    
    // ensure pcomm field is correctly cleared and filled
    __builtin_memset(&e->pcomm, 0, sizeof(e->pcomm));
    bpf_probe_read_kernel(&e->pcomm, sizeof(e->pcomm), &parent->comm);

    // ensure filename field is correctly cleared
    __builtin_memset(&e->filename, 0, sizeof(e->filename));
    // Read file name - check if filename is NULL
    if (filename) {
        bpf_probe_read_user_str(&e->filename, sizeof(e->filename), filename);
    }
    e->event_type = event_type;

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// Get dentry name
static __always_inline const char *get_dentry_name(struct dentry *dentry) {
    return BPF_CORE_READ(dentry, d_name.name);
}

// Monitor file open and creation
SEC("kprobe/do_sys_openat2")
int BPF_KPROBE(do_sys_openat2_enter) {
    const char *filename = (const char *)PT_REGS_PARM2_CORE(ctx);
    int flags = (int)PT_REGS_PARM3_CORE(ctx);
    
    // Debug: Print flags
    bpf_printk("openat2 flags: 0x%x\n", flags);
    
    return process_event(ctx, filename, (flags & 0100) ? EVENT_CREATE : EVENT_OPEN);
}

// Add direct kprobe monitoring for delete operations
SEC("kprobe/__x64_sys_unlink")
int BPF_KPROBE(x64_sys_unlink_enter) {
    const char *pathname = (const char *)PT_REGS_PARM1_CORE(ctx);
    bpf_printk("KPROBE_UNLINK: pathname=%s\n", pathname);
    return process_event(ctx, pathname, EVENT_UNLINK);
}

SEC("kprobe/__x64_sys_unlinkat")
int BPF_KPROBE(x64_sys_unlinkat_enter) {
    const char *pathname = (const char *)PT_REGS_PARM2_CORE(ctx);
    int flag = (int)PT_REGS_PARM3_CORE(ctx);
    int event_type = (flag & AT_REMOVEDIR) ? EVENT_RMDIR : EVENT_UNLINK;
    
    bpf_printk("KPROBE_UNLINKAT: pathname=%s, flag=0x%x\n", pathname, flag);
    return process_event(ctx, pathname, event_type);
}

SEC("kprobe/__x64_sys_rmdir")
int BPF_KPROBE(x64_sys_rmdir_enter) {
    const char *pathname = (const char *)PT_REGS_PARM1_CORE(ctx);
    bpf_printk("KPROBE_RMDIR: dirname=%s\n", pathname);
    return process_event(ctx, pathname, EVENT_RMDIR);
}

// use tracepoint to monitor unlink
SEC("tracepoint/syscalls/sys_enter_unlink")
int tracepoint__syscalls__sys_enter_unlink(struct trace_event_raw_sys_enter *ctx) {
    const char *pathname = (const char *)ctx->args[0];
    bpf_printk("SYSCALL_UNLINK: filename=%s\n", pathname);
    return process_event((struct pt_regs *)ctx, pathname, EVENT_UNLINK);
}

// use tracepoint to monitor unlinkat
SEC("tracepoint/syscalls/sys_enter_unlinkat")
int tracepoint__syscalls__sys_enter_unlinkat(struct trace_event_raw_sys_enter *ctx) {
    const char *pathname = (const char *)ctx->args[1];
    int flag = (int)ctx->args[2];
    int event_type = (flag & AT_REMOVEDIR) ? EVENT_RMDIR : EVENT_UNLINK;
    
    bpf_printk("SYSCALL_UNLINKAT: filename=%s, flag=0x%x\n", pathname, flag);
    return process_event((struct pt_regs *)ctx, pathname, event_type);
}

// use tracepoint to monitor rmdir
SEC("tracepoint/syscalls/sys_enter_rmdir")
int tracepoint__syscalls__sys_enter_rmdir(struct trace_event_raw_sys_enter *ctx) {
    const char *pathname = (const char *)ctx->args[0];
    bpf_printk("SYSCALL_RMDIR: dirname=%s\n", pathname);
    return process_event((struct pt_regs *)ctx, pathname, EVENT_RMDIR);
}

// use tracepoint to monitor rename
SEC("tracepoint/syscalls/sys_enter_rename")
int tracepoint__syscalls__sys_enter_rename(struct trace_event_raw_sys_enter *ctx) {
    const char *oldpath = (const char *)ctx->args[0];
    const char *newpath = (const char *)ctx->args[1];
    
    bpf_printk("SYSCALL_RENAME: %s -> %s\n", oldpath, newpath);
    process_event((struct pt_regs *)ctx, oldpath, EVENT_UNLINK);
    return process_event((struct pt_regs *)ctx, newpath, EVENT_CREATE);
}

// use tracepoint to monitor renameat
SEC("tracepoint/syscalls/sys_enter_renameat")
int tracepoint__syscalls__sys_enter_renameat(struct trace_event_raw_sys_enter *ctx) {
    const char *oldpath = (const char *)ctx->args[1];
    const char *newpath = (const char *)ctx->args[3];
    
    bpf_printk("SYSCALL_RENAMEAT: %s -> %s\n", oldpath, newpath);
    process_event((struct pt_regs *)ctx, oldpath, EVENT_UNLINK);
    return process_event((struct pt_regs *)ctx, newpath, EVENT_CREATE);
}

// use tracepoint to monitor renameat2
SEC("tracepoint/syscalls/sys_enter_renameat2")
int tracepoint__syscalls__sys_enter_renameat2(struct trace_event_raw_sys_enter *ctx) {
    const char *oldpath = (const char *)ctx->args[1];
    const char *newpath = (const char *)ctx->args[3];
    
    bpf_printk("SYSCALL_RENAMEAT2: %s -> %s\n", oldpath, newpath);
    process_event((struct pt_regs *)ctx, oldpath, EVENT_UNLINK);
    return process_event((struct pt_regs *)ctx, newpath, EVENT_CREATE);
}

// Monitor directory creation
SEC("kprobe/do_mkdirat")
int BPF_KPROBE(do_mkdirat_enter) {
    const char *pathname = (const char *)PT_REGS_PARM2_CORE(ctx);
    int mode = (int)PT_REGS_PARM3_CORE(ctx);
    
    bpf_printk("Directory creation: pathname=%s, mode=%d\n", pathname, mode);
    return process_event(ctx, pathname, EVENT_MKDIR);
}

char LICENSE[] SEC("license") = "GPL";