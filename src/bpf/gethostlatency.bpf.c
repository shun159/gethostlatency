// SPDX-License-Identifier: GPL-2.0
// Copyright: Brendan Gregg

#include "vmlinux.h"
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>

#define TASK_COMM_LEN   16
#define HOST_NAME_LEN   80

struct val_t {
    u32   pid;
    u8    comm[TASK_COMM_LEN];
    u8    host[HOST_NAME_LEN];
    u64   ts;
};

struct data_t {
    u32   pid;
    u64   delta;
    u8  comm[TASK_COMM_LEN];
    u8  host[HOST_NAME_LEN];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, u32);
    __type(value, struct val_t);
} start SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} events SEC(".maps");

static __always_inline
int handle__entry(struct pt_regs *ctx) {
    if (!PT_REGS_PARM1(ctx))
        return 0;

    struct val_t val = {};
    u32 pid = bpf_get_current_pid_tgid();

    if (bpf_get_current_comm(&val.comm, sizeof(val.comm)) == 0) {
        bpf_probe_read_user(&val.host, sizeof(val.host), (void *)PT_REGS_PARM1(ctx));
        val.pid = bpf_get_current_pid_tgid();
        val.ts = bpf_ktime_get_ns();
        bpf_map_update_elem(&start, &pid, &val, 0);
    }

    return 0;
}

static __always_inline
int handle__return(struct pt_regs *ctx) {
    struct val_t *valp;
    struct data_t data = {};
    u64 delta;
    u32 pid = bpf_get_current_pid_tgid();
    u64 tsp = bpf_ktime_get_ns();

    valp = bpf_map_lookup_elem(&start, &pid);
    if (!valp)
        return 0;     // missed start

    bpf_probe_read_kernel_str(&data.comm, sizeof(data.comm), valp->comm);
    bpf_probe_read_kernel_str(&data.host, sizeof(data.host), (void *)valp->host);
    data.pid = valp->pid;
    data.delta = tsp - valp->ts;

    // Emit event
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &data, sizeof(data));
    bpf_map_delete_elem(&start, &pid);

    return 0;
}

SEC("uprobe/getaddrinfo")
int handle__entry_getaddrinfo(struct pt_regs *ctx) {
    bpf_printk("uprobe: getaddrinfo");
    return handle__entry(ctx);
}

SEC("uprobe/gethostbyname")
int handle__entry_gethostbyname(struct pt_regs *ctx) {
    bpf_printk("uprobe: gethostbyname");
    return handle__entry(ctx);
    //return 0;
}

SEC("uprobe/gethostbyname2")
int handle__entry_gethostbyname2(struct pt_regs *ctx) {
    bpf_printk("uprobe: gethostbyname2");
    return handle__entry(ctx);
}

SEC("uretprobe/getaddrinfo")
int handle__return_getaddrinfo(struct pt_regs *ctx) {
    bpf_printk("uretprobe: getaddrinfo");
    return handle__return(ctx);
}

SEC("uretprobe/gethostbyname")
int handle__return_gethostbyname(struct pt_regs *ctx) {
    bpf_printk("uretprobe: gethostbyname");
    return handle__return(ctx);
    //return 0;
}

SEC("uretprobe/gethostbyname2")
int handle__return_gethostbyname2(struct pt_regs *ctx) {
    bpf_printk("uretprobe: gethostbyname2");
    return handle__return(ctx);
}

char LICENSE[] SEC("license") = "GPL";
