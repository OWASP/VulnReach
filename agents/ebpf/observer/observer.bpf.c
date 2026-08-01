// VulnReach eBPF observer — Tier A baseline.
//
// CO-RE programs, all filtered in-kernel by cgroup id, emitting fixed-layout
// `struct event` records to one ring buffer for the Go loader to marshal into
// NDJSON. The `kind` field discriminates event types.
//
//   P0: sched_process_exec  (kind=EXEC) — process-tree seed (→ P3)
//   P1: sys_enter_openat[2]  (kind=OPEN) — file-load baseline (→ P2 Package-Index)
//   P4: sys_enter_mmap       (kind=MMAP_EXEC) — native code mapped executable (R2)
//   P8: uprobe on CPython    (kind=PY_CALL) — Tier B enrichment, best-effort (R5)
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

// bpf_tracing.h's PT_REGS_PARM* macros need the target arch. The build passes
// -D__TARGET_ARCH_$GOARCH (see the go:generate line in main.go); Go spells
// x86-64 "amd64" while libbpf spells it "x86", so bridge the two names here.
#if defined(__TARGET_ARCH_amd64) && !defined(__TARGET_ARCH_x86)
#define __TARGET_ARCH_x86
#endif
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL"; // required for bpf_get_current_cgroup_id etc.

#define COMM_LEN 16
#define FN_LEN 128

#define EV_EXEC 0
#define EV_OPEN 1
#define EV_MMAP_EXEC 2
#define EV_PY_CALL 3
#define EV_JAVA_CLASS 4

#define PROT_EXEC_BIT 0x4

// py_cfg slots — CPython struct offsets, supplied by userspace per interpreter
// version (see main.go pyOffsets). Keeps the probe CO-RE-clean: no CPython
// headers, no per-version program variants.
#define PY_CFG_FRAME_ARG 0 // 1 => frame is arg1 (<=3.8), 2 => arg2 (3.9+)
#define PY_CFG_CODE_OFF  1 // offset of f_code within the frame struct
#define PY_CFG_FNAME_OFF 2 // offset of co_filename within PyCodeObject
#define PY_CFG_PAYLOAD   3 // offset of the char data within the str object
#define PY_CFG_EPOCH     4 // bumped by userspace when real traffic begins
#define PY_CFG_N         5
#define PY_OFF_MAX       512 // sanity bound; also keeps the verifier happy

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

// CPython struct offsets for the Tier B uprobe (see PY_CFG_* above).
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, PY_CFG_N);
    __type(key, __u32);
    __type(value, __u32);
} py_cfg SEC(".maps");

// jvm_cfg slots. USDT arguments live in whatever register the compiler happened
// to use, described by the probe's arg descriptor (e.g. "8@x3 -4@x2 ..."), so
// userspace resolves the register names to parameter indices and passes them in.
#define JVM_CFG_NAME_REG 0 // param index (1-6) holding the class-name char*
#define JVM_CFG_LEN_REG  1 // param index holding its length (0 => read to NUL)
#define JVM_CFG_N        2

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, JVM_CFG_N);
    __type(key, __u32);
    __type(value, __u32);
} jvm_cfg SEC(".maps");

// "<module>" as a little-endian u64 — conveniently exactly 8 bytes. A frame
// whose co_name is this is a module *body* (i.e. an import), not a call into
// the package's API. Skipping those is what keeps R5 stricter than R1.
#define PY_MODULE_NAME_LE 0x3E656C75646F6D3CULL

// Dedupe key. The epoch is what lets a file be reported *again* once traffic
// starts: nearly every package's files execute during import, so a plain
// per-file dedupe would permanently suppress the request-handling frames that
// are the interesting ones. Userspace bumps the epoch at the boot->traffic
// boundary, which re-opens every file for one more report.
struct py_key {
    __u64 fname;
    __u64 epoch;
};

// Dedupe by co_filename pointer. The uprobe fires on EVERY Python call, but we
// only care *which files* ran — CPython interns one co_filename str per module,
// shared by all its code objects, so one entry per source file collapses
// millions of calls into a few thousand events. LRU so a long-lived process
// can never wedge on a full map.
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 16384);
    __type(key, struct py_key);
    __type(value, __u8);
} py_seen SEC(".maps");

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

static __always_inline __u32 py_cfg_get(__u32 slot)
{
    __u32 *v = bpf_map_lookup_elem(&py_cfg, &slot);
    return v ? *v : 0;
}

// Rule R5 evidence (Tier B): a uprobe on CPython's eval loop tells us which
// *source file* is actually being executed — not merely opened (R1) or mapped
// (R2). That is the function-level proof a pure-Python package needs to reach
// CONFIRMED on its own runtime evidence. Module-body frames are excluded (see
// PY_MODULE_NAME_LE below) so "imported" alone never counts as "executed".
//
// We hook `_PyEval_EvalFrameDefault`, which is exported in .dynsym on stock
// python:*-slim images. The USDT probes the old probe_router.py relied on are
// NOT available there — official CPython builds are not --with-dtrace.
//
// The frame argument's struct layout changes across versions (PyFrameObject
// pre-3.11, _PyInterpreterFrame after), so every offset comes from py_cfg
// rather than being compiled in. Chain: frame -> f_code -> co_filename -> chars.
// All reads are userspace and failure-tolerant: this tier may never break the
// Tier A baseline.
SEC("uprobe/py_eval_frame")
int handle_py_frame(struct pt_regs *ctx)
{
    __u32 arg = py_cfg_get(PY_CFG_FRAME_ARG);
    if (!arg)
        return 0; // not configured => Tier B disabled

    // _CORE variants: reading the arg registers via BPF_CORE_READ instead of a
    // direct deref. Casting ctx and dereferencing at an offset is rejected by
    // the verifier ("dereference of modified ctx ptr") on arm64.
    __u64 frame = (arg == 1) ? (__u64)PT_REGS_PARM1_CORE(ctx) : (__u64)PT_REGS_PARM2_CORE(ctx);
    if (!frame)
        return 0;

    __u64 cg = bpf_get_current_cgroup_id();
    if (!cgroup_allowed(cg))
        return 0;

    __u32 code_off = py_cfg_get(PY_CFG_CODE_OFF);
    __u32 fname_off = py_cfg_get(PY_CFG_FNAME_OFF);
    __u32 payload = py_cfg_get(PY_CFG_PAYLOAD);
    if (code_off > PY_OFF_MAX || fname_off > PY_OFF_MAX || payload > PY_OFF_MAX)
        return 0;

    __u64 code = 0;
    if (bpf_probe_read_user(&code, sizeof(code), (void *)(frame + code_off)) || !code)
        return 0;

    __u64 fname = 0;
    if (bpf_probe_read_user(&fname, sizeof(fname), (void *)(code + fname_off)) || !fname)
        return 0;

    // One event per distinct source file per epoch, not per call. Checked first
    // because it is the overwhelmingly common case and exits the hot path early.
    struct py_key key = {.fname = fname, .epoch = py_cfg_get(PY_CFG_EPOCH)};
    if (bpf_map_lookup_elem(&py_seen, &key))
        return 0;

    // Importing a module evaluates its body, so a frame alone would make R5 no
    // stricter than R1 (openat) and would mark every *imported* package as
    // executed. Require a real function frame: co_name != "<module>".
    // co_name always sits immediately after co_filename in PyCodeObject —
    // verified on 3.9/3.11/3.13.
    __u64 nameptr = 0;
    if (bpf_probe_read_user(&nameptr, sizeof(nameptr), (void *)(code + fname_off + 8)) || !nameptr)
        return 0;
    struct { __u64 w; __u8 nul; } __attribute__((packed)) nm = {};
    if (bpf_probe_read_user(&nm, sizeof(nm), (void *)(nameptr + payload)) == 0 &&
        nm.w == PY_MODULE_NAME_LE && nm.nul == 0)
        return 0; // module body — an import, not a call

    __u8 one = 1;
    bpf_map_update_elem(&py_seen, &key, &one, BPF_ANY);

    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    fill_common(e, cg, EV_PY_CALL);
    bpf_probe_read_user_str(&e->filename, sizeof(e->filename), (void *)(fname + payload));

    bpf_ringbuf_submit(e, 0);
    return 0;
}

static __always_inline __u64 pt_parm(struct pt_regs *ctx, __u32 idx)
{
    switch (idx) {
    case 1: return (__u64)PT_REGS_PARM1_CORE(ctx);
    case 2: return (__u64)PT_REGS_PARM2_CORE(ctx);
    case 3: return (__u64)PT_REGS_PARM3_CORE(ctx);
    case 4: return (__u64)PT_REGS_PARM4_CORE(ctx);
    case 5: return (__u64)PT_REGS_PARM5_CORE(ctx);
    }
    // PARM6 has no _CORE variant on all arches; 5 covers every probe we use.
    return 0;
}

// Rule R6 evidence (Tier B, Java): the `hotspot:class__loaded` USDT probe, which
// stock JDK images ship enabled (567 probes in libjvm.so; no -XX flag needed,
// DTraceMethodProbes stays off). The JVM loads a class on *first active use*, so
// unlike a Python import this is already a use signal — and paired with the
// traffic boundary it means "this class was needed to serve a request".
//
// The name is a HotSpot Symbol body: NOT NUL-terminated, so we use the length
// argument the probe provides rather than reading to a NUL.
SEC("uprobe/jvm_class_loaded")
int handle_java_class(struct pt_regs *ctx)
{
    __u32 name_idx = 0, len_idx = 0;
    __u32 k = JVM_CFG_NAME_REG;
    __u32 *v = bpf_map_lookup_elem(&jvm_cfg, &k);
    if (!v || !*v)
        return 0; // not configured => Java Tier B disabled
    name_idx = *v;
    k = JVM_CFG_LEN_REG;
    v = bpf_map_lookup_elem(&jvm_cfg, &k);
    len_idx = v ? *v : 0;

    __u64 name = pt_parm(ctx, name_idx);
    if (!name)
        return 0;

    __u64 cg = bpf_get_current_cgroup_id();
    if (!cgroup_allowed(cg))
        return 0;

    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;
    fill_common(e, cg, EV_JAVA_CLASS);

    if (len_idx) {
        // Bound the length so the verifier can prove the write stays in bounds.
        __u32 n = (__u32)pt_parm(ctx, len_idx) & (FN_LEN - 1);
        bpf_probe_read_user(&e->filename, n, (void *)name);
        e->filename[n] = 0;
    } else {
        bpf_probe_read_user_str(&e->filename, sizeof(e->filename), (void *)name);
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}
