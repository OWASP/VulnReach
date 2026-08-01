# eBPF Layer Redesign — Language-Agnostic Runtime Reachability

**Baseline:** `docs/ebpf-audit.md` (current state — three divergent probe paths, only Python/Java
produce real signal, everything else silently degrades to `openat`).
**Goal:** attach to and observe **any** container regardless of the runtime inside it, deriving
dynamic reachability from **kernel-level, language-agnostic** signals; keep language-specific
probes as optional enrichment only.
**Status:** design + phased plan. No implementation in this pass. **Decisions needing your input
are collected in §9 and flagged inline as `⚑ DECISION`.**

---

## 1. Design principles

1. **Kernel-first, language-last.** The baseline reachability signal comes from syscall
   tracepoints and cgroup/namespace tracking — never from knowing what interpreter is inside the
   image. Language probes (USDT/uprobe) are a *secondary* enrichment that can only *raise*
   confidence, never gate it.
2. **Attach from the outside.** No agent, library, or cooperation baked into the workload image.
   The observer runs at host/node level and attaches into the target's namespaces post-start,
   discovered by container ID → cgroup.
3. **cgroup-scoped, not PID-walked.** Replace the current `real_parent`-walk hack with
   `bpf_get_current_cgroup_id()` filtering. Attach one set of programs globally; filter events to
   the target container's cgroup id in-kernel. Automatically covers forks/execs/worker pools.
4. **Deterministic-first.** All event→package correlation is rule/prefix/regex based. LLM
   escalation only for genuinely ambiguous behavioral correlation (§5.4), consistent with the
   rest of VulnReach.
5. **Reuse the rich logic.** The dormant `agents/ebpf/probe_router.py` / `runtime_detector.py` /
   `coverage_normaliser.py` become the *enrichment tier* (Phase 7), not dead code — this is the
   "align with the rich logic" ask.

---

## 2. Architecture overview

```
                    ┌─────────────────────────── Host / Node (privileged observer) ──────────────────────────┐
                    │                                                                                          │
 container discovery│   ┌──────────────┐   cgroup_id    ┌────────────────────────┐   ring buffer             │
 (Docker/containerd)├──▶│ Target Resolver│──────────────▶│  eBPF programs (CO-RE) │──────────────┐            │
                    │   │  id→cgroup→ino │               │  tp: execve/openat/    │              │            │
                    │   └──────────────┘                │  connect/sendto/recv/  │              ▼            │
                    │           │                        │  read/write(net fd)    │   ┌────────────────────┐  │
                    │           │  /proc/<pid>/root       │  + cgroup_id filter    │   │ Userspace collector│  │
                    │           ▼  (mount ns entry)       └────────────────────────┘   │ (deterministic)    │  │
                    │   ┌──────────────┐                                                │  rules + aggregation│ │
                    │   │ Package Index │◀──── SBOM (Trivy) + FS layout enumeration ───▶│                    │  │
                    │   │ path→package  │                                                └─────────┬──────────┘  │
                    │   └──────────────┘         [optional] USDT/uprobe enrichment ───────────────┤            │
                    │                             (probe_router, best-effort, cgroup-scoped)       │            │
                    └────────────────────────────────────────────────────────────────────────────┼────────────┘
                                                                                                   ▼
                                                          NormalisedReachability → correlate_coverage() → verdict
```

Two observer layers, strictly ordered by dependency:

- **Tier A — Baseline (mandatory, language-agnostic):** syscall tracepoints scoped by cgroup id,
  loaded by a standalone **Go/cilium-ebpf observer binary** (D8) that emits NDJSON to the Python
  collector. Produces *load-level* and *behavioral* reachability. Works on distroless/musl/static/unknown.
- **Tier B — Enrichment (optional, best-effort):** USDT/uprobe on `libpython`/`libjvm`/`node`
  when a runtime is detected. Produces *call-level* reachability. Reuses `probe_router.py`. If it
  fails to attach, the verdict still stands on Tier A.

---

## 3. Attachment mechanism (host/node → container)

### 3.1 Discovery
1. Enumerate target container via the runtime API. **v1 = Docker** (`docker inspect`, already used)
   behind a `TargetResolver` interface (D1 resolved); containerd/CRI (`ctr`/CRI `ContainerStatus`)
   is a second impl added at P9.
2. Resolve `container ID → cgroup path → cgroup id`. On cgroup v2 the id is the **inode of the
   cgroup directory** (`/sys/fs/cgroup/<...>/<container>`); read via `stat` or `name_to_handle_at`.
   This id is what `bpf_get_current_cgroup_id()` returns in-kernel.
3. Resolve `container ID → init PID` (host ns) for FS access via `/proc/<pid>/root` (mount-ns entry
   for path resolution and Package-Index building).

### 3.2 Attach
- Programs are loaded **once** on the host and attached to global tracepoints. No per-container
  bpftrace process, no PID-namespace sharing, no injected sidecar image required for Tier A.
- In-kernel filter: `if (bpf_get_current_cgroup_id() != TARGET_CGID) return 0;`. The target set is
  a BPF map of allowed cgroup ids (supports multiple containers / a whole pod).
- Events flow to userspace via a **ring buffer** (`BPF_MAP_TYPE_RINGBUF`), replacing the current
  parse-bpftrace-stdout approach.

### 3.3 Deployment shape (D2 resolved: host observer now, DaemonSet later)
- **v1 — per-scan host observer** (fits today's Docker-compose flow): the observer runs on the same
  host as the target, for the duration of the scan. Minimal change from current model.
- **Later — node-level DaemonSet** (for K8s / customer clusters): one privileged observer pod per
  node, watches CRI events, attaches to scanned workloads. Added at P9.
- The eBPF programs are **identical** across both; only the loader/lifecycle/`TargetResolver` impl
  differs, so the DaemonSet drops in without touching the probes.

---

## 4. eBPF programs (Tier A — the baseline)

All are cgroup-filtered and emit fixed-layout structs to the ring buffer. Kernel: raw tracepoints
via **CO-RE (libbpf/BTF)** — resolved in D3. bpftrace is retained only for Tier B (Phase 8).

| Prog | Hook | Emits | Purpose / reachability meaning |
|------|------|-------|-------------------------------|
| P1 `exec` | `tracepoint:sched:sched_process_exec` (or `syscalls:sys_enter_execve`/`execveat`) | cgid, pid, ppid, filename, argv[0] | Process-tree formation; which binaries/interpreters actually ran. Seeds the process set. |
| P2 `file_open` | `tracepoint:syscalls:sys_enter_openat`/`openat2` | cgid, pid, path | File loads. Path-prefix → **package file loaded** (import-level reach). |
| P3 `lib_load` | `tracepoint:syscalls:sys_enter_mmap` filtered to `PROT_EXEC` file-backed, or `openat` of `*.so/.node/.jar/.dylib/.class` | cgid, pid, path | Distinguishes *code loaded* (executable mapping) from *config read*. Native ext `.so` under a package path = **native code loaded** (stronger). |
| P4 `net_connect` | `tracepoint:syscalls:sys_enter_connect` | cgid, pid, af, daddr, dport | Outbound connections; behavioral evidence (DB/HTTP egress) for correlating protocol-owning packages. |
| P5 `net_io` | `tracepoint:syscalls:sys_enter_sendto`/`recvfrom` + `write`/`read` on socket fds | cgid, pid, fd, dir, len | Confirms the connection carried data (not just a dangling socket). Corroborates P4. |

Deliberately **not** in Tier A baseline: language uprobes (→ Tier B), `ptrace`, per-line USDT.

Ordering rationale: P1/P2 give the load-level baseline that already maps to packages the way the
current correlator does (`/site-packages/<pkg>/`). P3 sharpens load vs execute. P4/P5 add
behavioral evidence last (weakest mapping — see §5.4).

---

## 5. Mapping syscall events → "package X was reached"

This is the crux. Syscalls say "some code executed"; we need "package P executed." Four rules,
strongest first. All deterministic.

### 5.1 Package Index (the enabling data structure)
Build once per scan, from two sources already available:
- **SBOM (Trivy):** installed packages + versions (`vuln.get("package")`, `import_map` dist→module).
- **FS layout enumeration** via `/proc/<pid>/root`: walk the ecosystem install roots to get the
  authoritative on-disk paths — `site-packages/<pkg>/`, `node_modules/<pkg>/`,
  `.../pkg/mod/<module>@<ver>/` (Go), jar coordinates on the classpath, `gems/<name>-<ver>/`.

Output: a **longest-prefix trie**: `path prefix → {package, version, kind: pure|native}`. This
generalizes the existing hardcoded `/site-packages/{import_name}/` match in
`agent_dynamic_reachability.py:1334` to every ecosystem. ⚑ DECISION D4 (which ecosystems in v1).

### 5.2 Rule R1 — file-load → package loaded (from P2)
`openat` path resolves under a package prefix in the index → that package's code was **loaded**.
Maps to today's `import_hit`. Confidence: import-level.

### 5.3 Rule R2 — native-code load → package executed (from P3)
`mmap PROT_EXEC` (or open of `.so/.node/JNI .so`) under a package prefix → the package's **native
code was mapped for execution**. For packages whose vulnerable code is native (lxml, pillow,
cryptography, many npm native addons), this is strong "executed" evidence — stronger than R1.

### 5.4 Rule R3 — behavioral correlation → package used (from P4/P5)
A `connect`/`sendto` from the target process tree maps to *behavior*, not a file. Correlate only
when **both** hold: (a) the package is loaded (R1/R2), and (b) the observed behavior matches a
**protocol/port rule** the package is known to perform (e.g. psycopg2↔5432/postgres,
redis-py↔6379, requests/urllib3↔outbound 80/443). Deterministic rule table first; **LLM escalation
only** to judge an unusual/ambiguous egress against the package's expected behavior. R3 corroborates
but does not by itself prove the vulnerable code path ran.

### 5.5 Rule R4 — static-taint cross-reference (existing mechanism, extended)
Reuse `correlate_coverage`'s existing cross-ref: if static taint says `app_fn F → package P` and
Tier A shows F's **source file was opened** (P2) or F's process reached the relevant sink behavior
(P4/P5), elevate P. This is how a coarse syscall signal borrows precision from static analysis —
and it's already half-built (`static_findings` path in `coverage_correlator.py`).

---

## 6. Verdict contribution

**D6 resolved:** reuse the product's **canonical `Verdict`** — `CONFIRMED` / `LIKELY` / `POSSIBLE` /
`NOT_OBSERVED` (`correlation/engine.py`, wired into `risk_score`, confidence, policy, storage,
dashboard). **No parallel `*_REACHABLE` enum** — inventing one would break the risk multipliers and
every consumer. The redesign's earlier two-tier vocabulary is dropped. eBPF findings are emitted as
`core/models.py:ReachabilityFinding` with these verdicts and `evidence_type="dynamic"`, so they are
indistinguishable downstream from coverage-derived findings.

**D5 resolved:** a pure openat file-load (R1) maps to **`LIKELY` (import-hit)** — matching exactly how
`coverage_correlator` already treats an import-only hit (`LIKELY`, 0.65, `import_time_hit=True`).

| Evidence | Rule | Verdict | Confidence | Phase |
|----------|------|---------|-----------|-------|
| Language uprobe/USDT: package function entry observed (Tier B) | — | **CONFIRMED** | 0.95 | P8 |
| Native `.so` of package mapped PROT_EXEC | R2 | **CONFIRMED** | 0.8 | P4 |
| Package file loaded **+** static taint chain's app fn executed | R1+R4 | **CONFIRMED** | 0.9 | P7 |
| Package file loaded (import-level), no call evidence | R1 | **LIKELY** | 0.65 | **P5 (done)** |
| Behavioral corroboration (connect+loaded, protocol match) | R3 | **LIKELY/POSSIBLE** | 0.6 | P6 |
| Package in SBOM, never observed loaded | — | **NOT_OBSERVED** | 0.1 | **P5 (done)** |

Key rule (unchanged in substance): **a pure-interpreted package cannot reach `CONFIRMED` from Tier A
alone** — the syscall layer proves it was *loaded* (→ `LIKELY`), not that a specific function *ran*.
`CONFIRMED` requires R2-native (P4), Tier B enrichment (P8), or R4 static cross-ref (P7). Implemented
in `agents/ebpf/verdict_integration.py:to_reachability_findings`.

---

## 7. Privilege model

| Capability | Why | Kernel |
|-----------|-----|--------|
| `CAP_BPF` | load programs, create maps | ≥5.8 |
| `CAP_PERFMON` | attach to tracepoints, `bpf_probe_read_*` | ≥5.8 |
| `CAP_SYS_PTRACE` (or matching uid) | read `/proc/<pid>/root` for Package-Index + path resolution | — |
| ~~`privileged: true`~~ | **avoid** — current sidecar hardcodes it | — |

- **Target: `CAP_BPF + CAP_PERFMON + CAP_SYS_PTRACE`**, not full privileged. Replaces the audit's
  finding that the CAP alternative exists only as a comment.
- Ring buffer needs no extra caps. `/sys/kernel/debug` bind-mount is **not** required with CO-RE/BTF
  ring buffers (removes another current assumption).
- **Restricted clusters:** PSA `restricted`/many customer policies forbid `CAP_BPF` on workload
  pods. Mitigation: run the observer as a **dedicated privileged node agent** (its own namespace,
  not the workload's), so customer workloads stay unprivileged — the observer, not the app, holds
  the caps. Where even that is disallowed, Tier A must **degrade gracefully to "eBPF unavailable"**
  and fall back to the existing Dockerfile-patch coverage mode (already present). ⚑ DECISION D2/D7.

---

## 8. Phased implementation plan

Each phase is independently testable and lands value without the next. Phases 1–5 need **no
LLM**. Enrichment (Phase 8) is where the old rich logic returns.

| Phase | Deliverable | Independently testable by |
|-------|-------------|---------------------------|
| **P0 — Go/cilium-ebpf observer skeleton + cgroup filter** | `bpf2go` CO-RE build → static Go observer binary; `DockerTargetResolver` behind the `TargetResolver` protocol; cgroup-id→BPF-map plumbing; NDJSON-over-socket emitter + Python collector reader; one no-op CO-RE program. | Attach to a known container; confirm only its cgroup's events arrive as NDJSON; another container's are filtered out. |
| **P1 — `file_open` observer (P2)** | The baseline. cgroup-scoped `openat` → ring buffer → path list. | Run any container, hit an endpoint, assert its source/site-packages opens are captured; distroless image still yields file opens. |
| **P2 — Package Index + Rule R1** | SBOM+FS trie builder; matcher emits `package loaded` events → `POTENTIALLY_REACHABLE`. | Offline: feed recorded P1 trace + a fixture SBOM, assert correct package attribution; regression-test against current Python `/site-packages/` behavior. |
| **P3 — `exec` observer (P1)** | Process-tree seeding; interpreter/binary identification; scopes worker forks. | Container with gunicorn workers → assert full process tree attributed to one cgroup. |
| **P4 — `lib_load` + Rule R2** | PROT_EXEC/`.so` discrimination → native `package executed` → `CONFIRMED_REACHABLE` for native pkgs. | Trace a container importing a native ext (e.g. lxml); assert R2 fires and pure-Python import does not. |
| **P5 — Verdict integration** | New enum, mapping table (§6), wire into `correlate_coverage`; legacy-alias shim. | Unit-test each evidence combo → expected verdict/confidence; dashboard consumes without breaking. |
| **P6 — `net_connect`/`net_io` + Rule R3** | Behavioral corroboration with deterministic port/protocol table. | Container making a DB connect; assert R3 corroborates the driver package only when loaded. |
| **P7 — Static-taint cross-ref (R4)** | Extend existing `static_findings` path to consume Tier A load/behavior events for elevation. | Fixture: taint chain + P1 file-open of the app fn → assert elevation to CONFIRMED. |
| **P8 — Tier B enrichment (rich logic returns)** | cgroup-scoped USDT/uprobe via refactored `probe_router.py`; best-effort attach; elevates verdicts; **baseline unaffected if it fails**. | Kill enrichment mid-run → assert Tier A verdict unchanged; enable on `--with-dtrace` Python → assert elevation to CONFIRMED via call-level hit. |
| **P9 — containerd/CRI resolver + node DaemonSet** (if D2 says in-scope) | Second `TargetResolver` impl; DaemonSet lifecycle. | K8s kind cluster: DaemonSet attaches to a scanned pod, same programs, same output. |

Sequencing note: **P1→P2 is the MVP** — a language-agnostic baseline that already beats today's
openat-only degradation for every non-Python/Java runtime. Everything after sharpens confidence.

---

## 9. Decisions

### 9a. Resolved (2026-07-31)

- **✅ D1 — Container runtime scope: Docker only, interface-ready.** `TargetResolver` is built as
  an interface with a **Docker implementation** for v1; the containerd/CRI implementation is
  deferred until the DaemonSet path (D2/P9) needs it. Consequence: P0 ships a `DockerTargetResolver`
  behind a `TargetResolver` protocol — no containerd code until P9.
- **✅ D2 — Deployment shape: host observer now, DaemonSet later behind the same interface.** The
  eBPF programs and correlation are identical across shapes; only loader/lifecycle/discovery differ.
  Consequence: P0–P8 run as a **per-scan host observer** on the current Docker flow; P9 adds the
  node-level DaemonSet without touching the probes.
- **✅ D3 — Tracer technology: CO-RE (libbpf/BTF) for Tier A, bpftrace for Tier B.** Tier A baseline
  is compiled CO-RE programs with `BPF_MAP_TYPE_RINGBUF` and in-kernel cgroup filtering; bpftrace is
  retained only for Tier B enrichment prototyping. Consequence: a **compiled eBPF component +
  libbpf/BTF toolchain** enters the build (new for the current pure-Python-orchestrating-bpftrace
  stack); P0 must stand up that toolchain and the userspace ring-buffer consumer (see D8).
- **✅ D5 — R1 openat load → `LIKELY` (import-hit).** Matches `coverage_correlator`'s import-only-hit
  treatment (0.65, `import_time_hit=True`). Pure-interpreted packages reach `CONFIRMED` only via
  R2-native (P4) / Tier B (P8) / R4 static cross-ref (P7). Implemented in P5.
- **✅ D6 — Reuse the canonical `Verdict`** (`CONFIRMED`/`LIKELY`/`POSSIBLE`/`NOT_OBSERVED`) — no
  parallel `*_REACHABLE` enum; eBPF findings are canonical `ReachabilityFinding`s. Implemented in P5.
- **✅ D8 — Observer component: Go + cilium/ebpf, subprocess boundary, NDJSON.** The CO-RE observer
  is a **standalone Go binary** (cilium/ebpf; `bpf2go` embeds the compiled CO-RE objects → one
  static binary, no runtime libbpf/clang/kernel-headers). It emits **NDJSON over a unix socket/stdout**
  that the Python collector consumes; Python stays the orchestrator/correlator and never holds a BPF
  fd. Rationale: (1) the NDJSON stream is the record/replay seam P2/P5/P7 assume for offline testing;
  (2) it decouples eBPF lifecycle from the orchestrator; (3) the **same static binary is the P9
  DaemonSet payload** — host-observer-now and DaemonSet-later share one artifact. Python-in-process
  (BCC) was rejected: runtime clang+headers would undo D3 and bloat the DaemonSet image.

### 9b. Still open (needed before their phase, not before P0)

- **⚑ D4 — Ecosystem coverage for the Package Index v1.** Python + Node first? Add Go/Java/Ruby in
  which order? (Ties to which CVEs your users actually hit.) *(P2 shipped Python + Node builders.)*
- **⚑ D7 — Restricted-cluster fallback behavior.** When caps are denied: hard-fail the eBPF stage,
  or silently fall back to Dockerfile-patch mode (and how loudly to surface the downgrade in the
  verdict/report)?

---

## Appendix — what carries over vs. what's replaced

| Current (audit) | Redesign |
|-----------------|----------|
| PID `real_parent` 10-level walk | cgroup-id in-kernel filter (P0) |
| `pid: "service:<target>"` sidecar sharing PID ns | host/node observer into namespaces via cgroup discovery |
| bpftrace stdout parsing | ring-buffer structs |
| `privileged: true` hardcoded | `CAP_BPF + CAP_PERFMON + CAP_SYS_PTRACE` |
| Python/Java only produce signal | any runtime via syscalls; Python/Java/native sharpen it |
| `probe_router.py` dead | becomes Tier B enrichment (P8) |
| `/site-packages/{import_name}/` hardcoded match | general ecosystem Package-Index trie (P2) |
| `CONFIRMED`/`LIKELY` | `CONFIRMED_REACHABLE`/`POTENTIALLY_REACHABLE`/`NOT_OBSERVED` (D6) |
| Go `addr:` parser (dead) | dropped; Go handled by Package-Index path match + optional DWARF uprobe in Tier B |
