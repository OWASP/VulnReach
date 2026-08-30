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

### 5.4b Rule R5 — interpreted code executed *(implemented, P8 — Tier B)*
A uprobe on CPython's `_PyEval_EvalFrameDefault` reports which *source file* the
interpreter actually evaluated a frame from. This is what gets a **pure-interpreted**
package to CONFIRMED on its own runtime evidence instead of borrowing it from R4.

Two findings changed the plan from what §8/P8 originally assumed:

1. **USDT is unavailable on the images we scan.** Stock `python:*-slim` is not built
   `--with-dtrace` — `readelf -n` reports **0 `stapsdt` notes**. The
   `python:line` / `hotspot:method__entry` probes `probe_router.py` was written
   against simply do not exist there. `_PyEval_EvalFrameDefault` *is* exported in
   `.dynsym`, so a uprobe attaches with no debug symbols and no rebuild. Reviving
   `probe_router.py` as-is would have produced nothing.
2. **"A frame executed" is not much stricter than "a file was opened."** Importing a
   package runs its module bodies, class bodies and decorators, so R5 fired for every
   *imported* package and would have marked them all CONFIRMED — collapsing the LIKELY
   tier and over-claiming reachability. Filtering module-body frames (`co_name ==
   "<module>"`) is not sufficient either, since class bodies and decorator calls
   remain.

   The rule that does hold: **code that runs after the app is serving traffic** is
   request-handling, not startup. `TrafficWindow.mark()` records that boundary
   (CLOCK_MONOTONIC, directly comparable to `bpf_ktime_get_ns`); pre-boundary frames
   degrade to R1. On `labs/python_vuln_app` this separates the 10 packages that
   execute per request from the 6 that merely load at boot.

3. **The probe is expensive, and the dedupe does not make it cheap.** The in-kernel
   dedupe suppresses ringbuf *writes*, not the trap — while attached, every eligible
   call pays ~2µs against a ~40ns Python call. Measured (`e2e/bench_uprobe.py`):

   | CPython | micro (ns/call, C→Python) | real Flask request latency | throughput |
   |---------|--------------------------|----------------------------|------------|
   | 3.8–3.10 | 51 → 2100–2960 | **11.4×** (3.9: 2.0ms → 22.8ms) | 437 → 41 rps |
   | 3.11–3.13 | 39 → 2030–2070 | **2.6×** (3.11: 1.25ms → 3.2ms) | 700 → 287 rps |

   The split is CPython's 3.11 frame inlining: `CALL` pushes the new frame inside the
   *same* eval-loop invocation, so Python→Python calls stop trapping (measured
   +1.4–3.2ns, i.e. nothing) and only C→Python transitions remain. Below 3.11 every
   call re-enters `_PyEval_EvalFrameDefault` and traps.

   An 11× latency hit on the target would change what the DAST fuzzer explores and
   could trip its timeouts — it breaks the "Tier B may only ever *add* signal"
   constraint. **Mitigation: bound the exposure in time, not by sampling.** R5 needs
   each source file to execute *once* while we listen, and a served request path
   repeats constantly, so `--tier-b-window` attaches at `mark` and detaches after N
   seconds. Validated on Flask 3.9 and 3.11: the R5 package set is **identical** with
   a 5s window, post-detach latency returns to 1.0×, and the cost over a 20s window
   drops from 90% to 17% of throughput. Sampling was rejected as the alternative: it
   would bias recall against exactly the rarely-executed code R5 is most useful for.

Implementation notes: struct offsets are version-keyed and pushed into a BPF map at
attach (the frame arg changed type in 3.11, moved in 3.12, and `PyASCIIObject` shrank
in 3.12), so one program covers 3.8–3.13 — **all six branches validated live**
(attach + `co_filename` decoded on 3.8/3.9/3.10/3.11/3.12/3.13). The probe fires on
every Python call, so the kernel side dedupes by `co_filename` pointer; an epoch in the
dedupe key (bumped over the observer's stdin at `mark`) lets a file be reported once
more during traffic.

### 5.4c Rule R6 — JVM class loaded *(implemented, P8 — Tier B, Java)*
Java is where the redesign's original USDT plan actually holds. Stock JDK images ship
`libjvm.so` with ~567 **active** USDT probes; `hotspot:class__loaded` carries no
semaphore and is not gated by `DTraceMethodProbes`, so it needs no `-XX` flag and no
image change — the opposite of the CPython situation in §5.4b.

It is also a **stronger signal than R5 by construction**: the JVM resolves a class on
*first active use*, so a class load already means the code was needed. The traffic
boundary still applies (classes resolved while wiring up the app at boot are startup
work), and it is cheap — a few thousand class loads per run rather than a probe on
every call.

Implementation notes: cilium/ebpf has no USDT support, so `usdt.go` parses
`.note.stapsdt` directly — converting the probe address to a file offset (`.stapsdt.base`
prelink fixup + PT_LOAD mapping) and resolving argument registers. USDT arguments are
**not** in calling-convention order (the class name is in `x3`, its length in `x2`), so
registers are resolved at attach and passed in via a map. The name is a HotSpot `Symbol`
body and is **not NUL-terminated**, so the read is length-bounded.

Java packages are indexed by **class-name prefix**, not file path (`build_java`): jar
entries give the prefixes, `META-INF/maven/*/pom.properties` gives the coordinates, and
Spring Boot `BOOT-INF/lib/` nested jars are unpacked so a fat jar's dependencies are
attributed individually.

**Node was assessed and deliberately descoped.** `node:20-slim` has **0 USDT notes**, is
a static binary, and V8 JIT-compiles JS, so there is no stable per-call entry point.
Extracting a script name means walking `SharedFunctionInfo → Script` through pointer
compression with no stable ABI across Node minors — a fragile offset table of exactly the
kind §5.4b already had to be careful about. Node keeps the Tier A R1 baseline, which is
honest, rather than a manufactured CONFIRMED.

### 5.5 Rule R4 — static-taint cross-reference *(implemented, P7)*
If static taint says `app_fn F → package P` **and** Tier A observed P loaded (R1), elevate P to
`CONFIRMED`. This is how a coarse syscall signal borrows precision from static analysis: the
syscall layer proves the package was *there*, the taint graph proves a path *to* it exists.

Implementation (`agents/ebpf/verdict_integration.py`):
- `taint_modules(taint_flows)` reads `sink.definition.module` from the tainter's flow records and
  normalises to top-level import names (`yaml.load` → `yaml`).
- The verdict is **not hand-rolled**: it is exactly
  `correlation.engine.dynamic_reachability_verdict(has_taint_flow, has_coverage_hit)`, the
  product's canonical rule. R4/R1/POSSIBLE/NOT_OBSERVED all fall out of that one call.
- `taint_flows` threads `ScanContext.taint_flows` → `run_observer_reachability` →
  `to_reachability_findings`.

R2 and R4 compose: native code demonstrably executing **and** a static path reaching it is the
strongest Tier A evidence available (0.95) and outranks either alone.

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
| Code executed during traffic **+** static taint path reaches it | R2/R5+R4 | **CONFIRMED** | 0.95 | **P7/P8 (done)** |
| Interpreter evaluated a frame from the package while serving traffic | R5 | **CONFIRMED** | 0.85 | **P8 (done)** |
| JVM resolved a class from the package while serving traffic | R6 | **CONFIRMED** | 0.85 | **P8 (done)** |
| Package file loaded **+** static taint path reaches it | R1+R4 | **CONFIRMED** | 0.9 | **P7 (done)** |
| Native `.so` of package mapped PROT_EXEC | R2 | **CONFIRMED** | 0.8 | **P4 (done)** |
| Package file loaded (import-level), no call evidence | R1 | **LIKELY** | 0.65 | **P5 (done)** |
| Behavioral corroboration (connect+loaded, protocol match) | R3 | **LIKELY/POSSIBLE** | 0.6 | P6 |
| Static taint path exists but package never loaded | R4 only | **POSSIBLE** | 0.4 | **P7 (done)** |
| Package in SBOM, never observed loaded | — | **NOT_OBSERVED** | 0.1 | **P5 (done)** |

Key rule (unchanged in substance): **a pure-interpreted package cannot reach `CONFIRMED` from Tier A
alone** — the syscall layer proves it was *loaded* (→ `LIKELY`), not that a specific function *ran*.
`CONFIRMED` requires R2-native (P4), Tier B enrichment (P8), or R4 static cross-ref (P7). Implemented
in `agents/ebpf/verdict_integration.py:to_reachability_findings`.

Note the asymmetry that survives P8: R5 raises a package to CONFIRMED only when its code ran **while
the app was serving traffic**. A package that is imported at startup and never touched again stays
`LIKELY`, which is the honest reading of the evidence.

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
| **P7 — Static-taint cross-ref (R4)** ✅ | `taint_modules()` + canonical `dynamic_reachability_verdict()` in `verdict_integration.py`; `taint_flows` threaded from `ScanContext`. | `test_taint_crossref_r4_confirmed` (LIKELY→CONFIRMED 0.9 with taint), `test_taint_only_is_possible`; full-scan e2e on `labs/python_vuln_app` with real `findings.json` flows. |
| **P8 — Tier B enrichment (Rules R5 Python / R6 Java)** ✅ | cgroup-scoped **uprobe** on `_PyEval_EvalFrameDefault` (not USDT — see §5.4b), version-keyed offsets, in-kernel dedupe + traffic epoch; best-effort attach; **baseline unaffected if it fails**; **time-boxed** (`--tier-b-window`, default 5s from `mark`) because the probe costs 2.6x-11.4x request latency while attached (§5.4b). | `test_interpreted_exec_r5_confirmed` (A/B: same workload is LIKELY without Tier B, CONFIRMED with it), `test_tier_b_failure_preserves_baseline` (bogus lib → observer still ready, Tier A intact), `test_r5_traffic_boundary_separates_import_from_use` (import-only stays LIKELY), `test_java_class_load_r6_confirmed` (two jars on the classpath, only the used one reaches CONFIRMED), `test_tier_b_uprobe_window_detaches` (no py_call events after the window, with an unbounded control run so it cannot pass vacuously). Perf + all six version branches validated by `e2e/bench_uprobe.py`. |
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
