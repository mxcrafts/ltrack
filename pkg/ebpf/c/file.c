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
    bpf_printk("Processing event type: %d\n", event_type);
    
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) 
        return 0;

    // Get current process information
    task = (struct task_struct *)bpf_get_current_task();
    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->uid = bpf_get_current_uid_gid() >> 32;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    // Get parent process information
    parent = BPF_CORE_READ(task, real_parent);
    e->ppid = BPF_CORE_READ(parent, tgid);
    bpf_probe_read_kernel_str(&e->pcomm, sizeof(e->pcomm), &parent->comm);

    // Read file name
    bpf_probe_read_user_str(&e->filename, sizeof(e->filename), filename);
    e->event_type = event_type;

    bpf_ringbuf_submit(e, 0);
    return 0;
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

// Monitor file and directory deletion
SEC("kprobe/do_unlinkat")
int BPF_KPROBE(do_unlinkat_enter) {
    const struct filename *name = (const struct filename *)PT_REGS_PARM2_CORE(ctx);
    int flag = (int)PT_REGS_PARM3_CORE(ctx);
    pid_t pid;
    const char *filename;
    int event_type;

    // Get current process PID
    pid = bpf_get_current_pid_tgid() >> 32;
    
    // Directly use BPF_CORE_READ to read file name
    filename = BPF_CORE_READ(name, name);
    
    // Debug log
    bpf_printk("Delete operation: pid = %d, filename = %s\n", pid, filename);
    
    // Check if it is a directory deletion operation
    bpf_printk("Delete operation flag: flag = 0x%x\n", flag);
    event_type = (flag & AT_REMOVEDIR) ? EVENT_RMDIR : EVENT_UNLINK;
    
    return process_event(ctx, filename, event_type);
}

// Monitor return value of delete operation
SEC("kretprobe/do_unlinkat")
int BPF_KRETPROBE(do_unlinkat_exit) {
    pid_t pid = bpf_get_current_pid_tgid() >> 32;
    long ret = PT_REGS_RC(ctx);
    bpf_printk("Delete operation return: pid = %d, ret = %ld\n", pid, ret);
    return 0;
}

// Monitor directory creation
SEC("kprobe/do_mkdirat")
int BPF_KPROBE(do_mkdirat_enter) {
    const char *pathname = (const char *)PT_REGS_PARM2_CORE(ctx);
    int mode = (int)PT_REGS_PARM3_CORE(ctx);
    
    bpf_printk("Directory creation: pathname=%s, mode=%d\n", pathname, mode);
    return process_event(ctx, pathname, EVENT_MKDIR);
}

// Monitor file rename/move
SEC("kprobe/do_renameat2")
int BPF_KPROBE(do_renameat2_enter) {
    struct renamedata *rd = (struct renamedata *)PT_REGS_PARM1_CORE(ctx);
    const unsigned char *old_name_raw, *new_name_raw;
    const char *old_name, *new_name;
    
    // Correct type conversion handling
    old_name_raw = BPF_CORE_READ(rd, old_dentry, d_name.name);
    new_name_raw = BPF_CORE_READ(rd, new_dentry, d_name.name);
    
    // Explicit type conversion
    old_name = (const char *)old_name_raw;
    new_name = (const char *)new_name_raw;
    
    bpf_printk("Rename operation: %s -> %s\n", old_name, new_name);
    
    // Process event
    process_event(ctx, old_name, EVENT_UNLINK);
    return process_event(ctx, new_name, EVENT_CREATE);
}

char LICENSE[] SEC("license") = "GPL";