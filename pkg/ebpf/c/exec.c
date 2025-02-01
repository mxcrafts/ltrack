#include "../headers/vmlinux.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define ARGV_LEN    128  // Maximum length of command line arguments
#define COMM_SIZE   16   // Maximum length of process name
#define PATH_SIZE   256  // Maximum length of file path

struct event {
    __u32 pid;           // Process ID
    __u32 ppid;          // Parent process ID
    __u32 uid;           // User ID
    __u32 gid;           // Group ID
    char comm[COMM_SIZE];    // Process name
    char filename[PATH_SIZE]; // Executable file path
    char argv[ARGV_LEN];     // Command line arguments
    __u32 argv_size;         // Argument length
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

SEC("tracepoint/sched/sched_process_exec")
int trace_exec_entry(struct trace_event_raw_sched_process_exec *ctx) {
    struct event *e;
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        return 0;
    }

    // Get current task structure
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    
    // Basic process information
    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->ppid = BPF_CORE_READ(task, real_parent, tgid);
    e->uid = bpf_get_current_uid_gid() >> 32;
    e->gid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    
    // Clear buffer
    __builtin_memset(&e->filename, 0, sizeof(e->filename));
    __builtin_memset(&e->comm, 0, sizeof(e->comm));
    __builtin_memset(&e->argv, 0, sizeof(e->argv));

    // Get process name
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    // Get executable file path
    unsigned int filename_loc = ctx->__data_loc_filename & 0xFFFF;
    bpf_probe_read_str(&e->filename, sizeof(e->filename), (void *)ctx + filename_loc);

    // Get command line arguments
    void *arg_start = (void *)BPF_CORE_READ(task, mm, arg_start);
    void *arg_end = (void *)BPF_CORE_READ(task, mm, arg_end);
    unsigned long arg_length = arg_end - arg_start;
    
    // Limit argument length
    if (arg_length > ARGV_LEN - 1) {  // Reserve one byte for null terminator
        arg_length = ARGV_LEN - 1;
    }

    // Read command line arguments
    int arg_ret = bpf_probe_read(&e->argv, arg_length, arg_start);
    if (!arg_ret) {
        e->argv_size = arg_length;
        e->argv[arg_length] = '\0';  // Ensure string is correctly terminated
    } else {
        e->argv_size = 0;
        e->argv[0] = '\0';
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";