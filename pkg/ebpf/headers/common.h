/* File event structure */
struct event {
    __u64 pid;                    /* Process ID */
    __s64 ret;                    /* Return value */
    __u32 event_type;            /* Event type (open/create/unlink) */
    char comm[16];               /* Process name */
    char filename[256];          /* File path */
};

/* Path filter structure */
struct path_filter {
    bool enabled;                /* Is this filter enabled */
    char path[256];             /* Directory path to monitor */
};
