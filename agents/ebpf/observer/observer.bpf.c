// VulnReach eBPF observer — Tier A baseline.
//
// CO-RE programs, all filtered in-kernel by cgroup id, emitting fixed-layout
// `struct event` records to one ring buffer for the Go loader to marshal into
// NDJSON. The `kind` field discriminates event types.
//
//   P0: sched_process_exec  (kind=EXEC) — process-tree seed (→ P3)
//   P1: sys_enter_openat[2]  (kind=OPEN) — file-load baseline (→ P2 Package-Index)
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL"; // required for bpf_get_current_cgroup_id etc.

#define COMM_LEN 16
#define FN_LEN 128

#define EV_EXEC 0
#define EV_OPEN 1
#define EV_MMAP_EXEC 2

#define PROT_EXEC_BIT 0x4

struct event {
    __u64 ts_ns;
    __u64 cgroup_id;
    __u32 pid;
    __u32 ppid;
    __u32 kind;
    char  comm[COMM_LEN];
    char  filename[FN_LEN];
};
// Force bpf2go to emit the Go type for `struct event`.
struct event *_unused_event __attribute__((unused));

// Target cgroup ids, populated from userspace. Empty + filter_on=0 => pass all.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 64);
    __type(key, __u64);
    __type(value, __u8);
} targets SEC(".maps");

// filter_on[0] = 1 when the `targets` allow-list should be enforced.
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} filter_on SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24); // 16 MiB
} events SEC(".maps");

static __always_inline int cgroup_allowed(__u64 cg)
{
    __u32 k = 0;
    __u32 *on = bpf_map_lookup_elem(&filter_on, &k);
    if (on && *on)
        return bpf_map_lookup_elem(&targets, &cg) != 0;
    return 1;
}

static __always_inline void fill_common(struct event *e, __u64 cg, __u32 kind)
{
    e->ts_ns = bpf_ktime_get_ns();
    e->cgroup_id = cg;
    e->pid = bpf_get_current_pid_tgid() >> 32;
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    e->ppid = BPF_CORE_READ(t, real_parent, tgid);
    e->kind = kind;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    e->filename[0] = 0;
}

SEC("tracepoint/sched/sched_process_exec")
int handle_exec(struct trace_event_raw_sched_process_exec *ctx)
{
    __u64 cg = bpf_get_current_cgroup_id();
    if (!cgroup_allowed(cg))
        return 0;

    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    fill_common(e, cg, EV_EXEC);
    // exec filename lives in the tracepoint's variable data area (__data_loc).
    unsigned short off = (unsigned short)(ctx->__data_loc_filename & 0xFFFF);
    bpf_probe_read_kernel_str(&e->filename, sizeof(e->filename), (void *)ctx + off);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// openat(dfd, filename, flags, mode): args[1] is a userspace char*.
static __always_inline int emit_open(const char *fname)
{
    __u64 cg = bpf_get_current_cgroup_id();
    if (!cgroup_allowed(cg))
        return 0;

    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    fill_common(e, cg, EV_OPEN);
    bpf_probe_read_user_str(&e->filename, sizeof(e->filename), fname);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_openat")
int handle_openat(struct trace_event_raw_sys_enter *ctx)
{
    return emit_open((const char *)ctx->args[1]);
}

// openat2(dfd, filename, open_how*, size): args[1] is the userspace char* too.
SEC("tracepoint/syscalls/sys_enter_openat2")
int handle_openat2(struct trace_event_raw_sys_enter *ctx)
{
    return emit_open((const char *)ctx->args[1]);
}

// Rule R2 evidence: mmap(..., PROT_EXEC, ..., fd, ...) on a file-backed fd means
// code from that file was mapped for EXECUTION — the strongest syscall-level
// proof that a native extension is actually being run (not merely read).
//
// mmap(addr, len, prot, flags, fd, off): prot=args[2], fd=args[4].
// We resolve fd → file → dentry → d_name (basename only; a full path walk needs
// an unbounded dentry loop). Userspace joins the basename to the full path seen
// in the openat stream to attribute it to a package.
SEC("tracepoint/syscalls/sys_enter_mmap")
int handle_mmap(struct trace_event_raw_sys_enter *ctx)
{
    unsigned long prot = (unsigned long)ctx->args[2];
    int fd = (int)ctx->args[4];
    if (!(prot & PROT_EXEC_BIT) || fd < 0)
        return 0; // not executable, or anonymous mapping

    __u64 cg = bpf_get_current_cgroup_id();
    if (!cgroup_allowed(cg))
        return 0;

    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    struct file **fdarray = BPF_CORE_READ(t, files, fdt, fd);
    if (!fdarray)
        return 0;

    struct file *f = NULL;
    if (bpf_probe_read_kernel(&f, sizeof(f), &fdarray[fd]) || !f)
        return 0;

    const unsigned char *name = BPF_CORE_READ(f, f_path.dentry, d_name.name);
    if (!name)
        return 0;

    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    fill_common(e, cg, EV_MMAP_EXEC);
    bpf_probe_read_kernel_str(&e->filename, sizeof(e->filename), name);

    bpf_ringbuf_submit(e, 0);
    return 0;
}
