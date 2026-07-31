# eBPF Runtime Coverage — Audit Findings

**Scope:** current state of VulnReach's eBPF-based dynamic reachability coverage.
**Date:** 2026-07-31
**Method:** static read of `agents/ebpf/`, `agents/agent_dynamic_reachability.py`, `config/schema.py`, `agents/utils/coverage_correlator.py`.
**Status:** findings only — no code changed in this pass.

> **Headline:** eBPF coverage exists in three *separate, partly divergent* code paths. The
> code the running system actually executes (the sidecar and the host-tracer) is a strict
> subset of the richer probe library in `agents/ebpf/probe_router.py` — which, apart from one
> helper, is **not wired into any production call path** and is exercised only by tests.

---

## 0. Executive summary

| Area | State |
|------|-------|
| Probe types in use | USDT (Python `line`, Java `hotspot:method__entry`) + one syscall tracepoint (`openat`). No kprobes. |
| Languages with *real* runtime signal | Python (line-level, only on `--with-dtrace` builds), Java (method-level, only with `-XX:+ExtendedDTraceProbes`). |
| Languages that silently degrade to file-open evidence | Node, Go, Ruby, and any unknown runtime → `openat` only. |
| Richer probes (`probe_router.py`: Python uprobe fallback, Ruby USDT, Go addr2line) | **Defined but dead** in production — imported only by tests. |
| Attach mechanism | (a) host bpftrace into container PID ns, or (b) privileged compose sidecar sharing the target PID ns. |
| Privilege required | `privileged: true` container (sidecar) or host-level bpftrace as root. Documented CAP-based alternative is a *comment*, not code. |
| Portability | Breaks on Docker Desktop/LinuxKit (detected & skipped); assumes glibc + `/proc/{pid}/exe` USDT notes; distroless/musl/static images degrade to openat or fail detection. |

---

## 1. Inventory — every probe currently defined

There are **three** places that emit bpftrace programs. They do not share code (except one
host-side formatter). Probe coverage differs between them.

### 1a. Production sidecar — `agents/ebpf/sidecar/sidecar_entrypoint.py`
This is the script that actually runs inside the injected container (`build_probe_script`).

| # | Probe (bpftrace) | Type | Attachment point | Target | Signal emitted | Lang-specific? |
|---|------------------|------|------------------|--------|----------------|----------------|
| 1 | `usdt:/proc/{pid}/exe:python:line` | USDT | CPython `python:line` marker | Python interpreter (`--with-dtrace`) | `line:<file>:<lineno>` — line-level | **Python** |
| 2 | `usdt:{libjvm}:hotspot:method__entry` | USDT | JVM `hotspot:method__entry` in `libjvm.so` | OpenJDK w/ `-XX:+ExtendedDTraceProbes` | `method:<class>:<method>` — method-level | **Java** |
| 3 | `tracepoint:syscalls:sys_enter_openat` | Syscall tracepoint | `sys_enter_openat`, filtered by walking `curtask->real_parent` 10 levels to match `tgid` | Any process tree | `open:<filename>` — file-open only | Language-agnostic |

Selection logic (`build_probe_script`): Python→USDT line if present else openat; Java→hotspot
USDT if present else openat; **everything else → openat directly**. No Ruby USDT, no Go
resolution, no Python function-entry or uprobe fallback here.

### 1b. Host-level tracer — `agent_dynamic_reachability._build_bpftrace_script`
Used by `_run_ebpf_mode` (non-sidecar path). Selected by `runtime.ebpf.mode`.

| # | Probe | Type | Attachment point | Signal | Lang-specific? |
|---|-------|------|------------------|--------|----------------|
| 4 | `usdt:/proc/{pid}/exe:python:line` (`mode="line"`) | USDT | CPython `python:line` | `line:<file>:<lineno>` | Python |
| 5 | `usdt:/proc/{pid}/exe:python:function__entry` (`mode="usdt"`) | USDT | CPython `python:function__entry` | `func:<file>:<func>` | Python |
| 6 | `tracepoint:syscalls:sys_enter_openat` (`mode="openat"`, default) | Syscall tracepoint | `sys_enter_openat`, same `real_parent` walk | `open:<filename>` | Language-agnostic |

Note: this path's output is **not** run through the normaliser. `_collect_ebpf_hits` does raw
substring matching of vulnerable-package import names against tracer stdout (Python-centric,
package-granularity only).

### 1c. Probe library — `agents/ebpf/probe_router.py` (the rich set, mostly dormant)
`select_probe(runtime, pid)` builds these, with per-runtime degradation chains. **Only
`coverage_normaliser.to_coverage_py_format` from this package is imported by production**
(`agent_dynamic_reachability.py:69`); `select_probe`, `detect_runtime`, and every parser are
referenced only from `tests/`.

| # | Probe | Type | Attachment point | Target | Signal | Lang-specific? |
|---|-------|------|------------------|--------|--------|----------------|
| 7 | `usdt:…:python:line` | USDT | `python:line` | CPython | `line:f:n` | Python |
| 8 | `usdt:…:python:function__entry` | USDT | `python:function__entry` | CPython | `func:f:fn` | Python |
| 9 | `uprobe:{binary}:PyEval_EvalFrameEx` | **uprobe** | CPython eval loop symbol | CPython | `func:unknown:frame_entry` (no file/line) | Python |
| 10 | `usdt:{libjvm}:hotspot:method__entry` | USDT | `hotspot:method__entry` | libjvm | `method:c:m` | Java |
| 11 | `usdt:…:ruby:method__entry` | USDT | `ruby:method__entry` | Ruby `--enable-dtrace` | `ruby_method:c:m` | **Ruby** |
| 12 | `tracepoint:syscalls:sys_enter_openat` | Syscall tracepoint | `sys_enter_openat` (`/pid==N/`) | any | `open:path` | Language-agnostic |

`coverage_normaliser` additionally has a **Go** parser (`_parse_go_uprobe` + `addr2line`
resolution, `output_parser="go_uprobe"`), but **no probe anywhere emits `addr:<hex>` output** —
so the Go line-resolution path is unreachable. `probe_router._probe_go` and `_probe_node`
both return `openat`.

### Probe-type summary
- **USDT:** Python (`line`, `function__entry`), Java (`hotspot:method__entry`), Ruby (`ruby:method__entry`, dormant).
- **uprobe:** one — `PyEval_EvalFrameEx` (dormant, sidecar never uses it).
- **Syscall tracepoint:** `sys_enter_openat` (the universal fallback, language-agnostic).
- **kprobes:** none.
- **Other tracepoints:** none (no `execve`, `connect`, `execveat`, etc.).

---

## 2. Coverage gaps

### 2a. Language support matrix (as actually shipped by the sidecar)

| Runtime | Detected? | Probe used | Fidelity | Requires |
|---------|-----------|------------|----------|----------|
| Python | yes | `python:line` USDT → else openat | line-level *or* file-open | CPython built `--with-dtrace` (ubuntu:22.04 yes; `python:3.x-slim` **no**) |
| Java | yes | `hotspot:method__entry` USDT → else openat | method-level (no line #s at runtime) | OpenJDK + `-XX:+ExtendedDTraceProbes` |
| Node | yes (detected) | **openat only** | file-open / package-level | — (V8 USDT deemed unavailable; uprobe "future") |
| Go | partial (heuristic) | **openat only** | file-open / package-level | — (DWARF uprobe "not yet implemented") |
| Ruby | yes (detected) | **openat in sidecar** (USDT only in dormant router) | file-open in prod | router path needs Ruby `--enable-dtrace` |
| Unknown/other | falls back to `generic` | openat only | file-open | — |

**Net:** only **Python and Java** produce function/line reachability signal in production.
Everything else collapses to "a source-looking file was opened," which is coarse
package-level evidence, not true reachability.

### 2b. Hardcoded assumptions that break on arbitrary images

1. **`/proc/{pid}/exe` is an ELF with readable USDT notes.** `readelf -n` on `/proc/{pid}/exe`
   is the whole USDT-detection strategy (`runtime_detector.has_usdt_probe`,
   `sidecar._has_python_usdt`). On **distroless/static/musl** images or where the interpreter is
   a wrapper, this yields no notes → silent degrade to openat.
2. **glibc / dynamic linking assumed.** `_MAPS_SIGNATURES` looks for `libjvm.so`, `libnode.so`,
   `libruby`, `libpython`. **Alpine musl** and **fully static** binaries (typical Go) won't show
   these — detection falls through to cmdline/heuristics.
3. **Go detection is a guess.** `runtime_detector._strategy_cmdline` returns `"go"` for *any*
   standalone ELF that matched no known interpreter — a false-positive magnet for any compiled
   binary (Rust, C, etc.), which then gets openat anyway.
4. **Interpreter naming assumed.** `_CMDLINE_SIGNATURES` matches basenames `python3/python/java/
   node/nodejs/ruby`. Renamed entrypoints, `exec`-into-app, or busybox shims defeat it.
5. **Toolchain present in the *target* image for post-processing.** Java line resolution shells
   out to `javap` and walks `/proc/{pid}/root` for `.class` files; Go resolution needs
   `addr2line`. The sidecar image installs `binutils` but **not a JDK** → Java stays
   method-level; distroless targets have neither.
6. **Sidecar base is `python:3.11-slim` (Debian glibc).** bpftrace + BTF are assumed available
   from the *host* kernel; there is no musl/host-kernel-mismatch handling.
7. **`/sys/kernel/debug` bind-mount + BTF assumed.** Required for tracepoints; not verified at
   attach time beyond the 1.5 s crash check.
8. **Container `WORKDIR` / path layout.** Coverage correlation depends on
   `runtime.container_workdir` (auto-detected from Dockerfile `WORKDIR`); paths emitted by
   probes are absolute container paths that must later map back to repo-relative files.
9. **Primary-service heuristic.** `compose_injector.detect_primary_service` guesses the app
   service by name/port/healthcheck; a non-standard compose layout can attach the sidecar to the
   wrong service, and `_run_ebpf_sidecar_mode` falls back to a literal `"app"` on failure.

---

## 3. Attachment mechanism

Two distinct mechanisms, chosen by config (`runtime.ebpf.sidecar_mode`).

### 3a. Sidecar mode (`sidecar_mode: true`) — the non-invasive path
- **How attached:** `compose_injector.inject_sidecar` writes a *separate*
  `docker-compose.vulnreach-sidecar.yml` override (user's compose is never modified) adding one
  `vulnreach-sidecar` service. `docker compose -f orig -f override up --abort-on-container-exit
  --exit-code-from vulnreach-sidecar`. The sidecar builds from a Dockerfile staged into
  `VULNREACH_WORK_DIR`.
- **PID-namespace sharing:** `pid: "service:<target>"` — the sidecar sees the target's processes
  directly. bpftrace attaches to the target PID **from inside** the sidecar.
- **Target discovery:** `find_target_pid()` scans `/proc/[0-9]*` in the shared ns and scores by
  exe/cmdline against an app-name allow-list, penalizes shells/init, and boosts direct children
  of PID 1. Highest score wins.
- **Sync:** `depends_on: { <target>: condition: service_healthy }`; then a fixed
  `TRAFFIC_WAIT`/`coverage_wait` sleep during Schemathesis traffic; writes
  `/coverage/ebpf_coverage.json`; exits 0.
- **Privilege:** `privileged: true` (hardcoded). The override header + `compose_injector`
  docstring describe a `cap_add: [CAP_BPF, CAP_PERFMON, SYS_PTRACE]` +
  `security_opt: [no-new-privileges:false]` alternative for kernel ≥ 5.8, **but this is only a
  comment — never emitted as actual config.** Also mounts `/sys/kernel/debug:ro`.

### 3b. Host-tracer mode (`sidecar_mode: false`, `ebpf.enabled: true`) — `_run_ebpf_mode`
- **How attached:** VulnReach builds a *plain* (uninstrumented) image, `docker run -d`, then runs
  **host-level bpftrace** (not in a container) against the container's process.
- **Target discovery:** `_get_container_pid` = `docker inspect --format '{{.State.Pid}}'` → the
  container init's **host-namespace PID**. The openat script then walks `real_parent` up to 10
  levels to include gunicorn/uWSGI worker forks.
- **Privilege:** bpftrace runs on the host (effectively root / `CAP_BPF`+`CAP_PERFMON`); no
  container caps involved because tracing happens host-side into the container's PID.

### 3c. Availability gate (both modes) — `_ebpf_available`
1. Must be Linux (`platform.system()`).
2. **Docker Desktop / LinuxKit is detected via `/proc/version` and hard-skipped** — LinuxKit
   doesn't expose syscall tracepoints. This means eBPF is effectively **macOS/Windows-dev-hostile
   and Linux-CI-only**.
3. `tracer` binary in `PATH`.
4. Live dry-run: `bpftrace -e 'tracepoint:syscalls:sys_enter_openat { exit(); }'` must exit 0.

Kernel expectations (documented in the Dockerfile / override header, advisory only):
`≥4.9` uprobes, `≥5.2` BTF/modern bpftrace, `≥5.8` CAP_BPF alternative. `ebpf.kernel_check`
only toggles warning verbosity — it never blocks.

---

## 4. Data model

### 4a. Event schema out of the eBPF layer
Raw bpftrace stdout is line-oriented text (parser-specific):
- `line:<filepath>:<lineno>` (Python USDT line)
- `func:<filepath>:<funcname>` (Python USDT function-entry)
- `method:<class_slash>:<method>` (Java hotspot)
- `ruby_method:<class>:<method>` (Ruby, dormant)
- `addr:<0xhex>` (Go — **no probe emits this**)
- `open:<filepath>` (openat, filtered to source-looking paths)

Normalised into **NormalisedCoverage** (`coverage_normaliser` / sidecar `parse_output`):
```json
{
  "runtime": "python",
  "files": {
    "/app/views.py": { "executed_lines": [10, 11, 15], "executed_functions": ["index"] }
  }
}
```
Failure sentinel: `{"skip": true, "skip_reason": "<reason>", "runtime": "<detected>"}`.

### 4b. Mapping into the reachability verdict pipeline
1. Sidecar writes `ebpf_coverage.json` (NormalisedCoverage) to the shared `/coverage` volume.
2. `_run_ebpf_sidecar_mode` reads it back after compose exits. If `skip` → `AgentResult`
   `status="skipped"`. Otherwise:
3. `to_coverage_py_format(normalised)` reshapes it into the **coverage.py JSON schema**
   (`{"files": {path: {"executed_lines": [...], "functions": {name: {"executed_lines": [1]}}}}}`).
   The synthetic `executed_lines: [1]` per function is a deliberate marker so
   `build_hit_sets()` classifies it as a **call hit** (function actually invoked) rather than a
   mere import-time hit.
4. `self._correlate(...)` → `agents/utils/coverage_correlator.correlate_coverage(coverage_data,
   context.vulnerabilities, import_map=…, static_findings=context.taint_flows)`.
5. Verdicts per CVE:
   - **CONFIRMED** — `call_hit`: a function within the vulnerable package was executed (or a
     static taint chain's app-side function was observed at runtime).
   - **LIKELY** — `import_hit`: package loaded but no call observed.
   - **LIKELY** — no observation at all.

**Consequence of the fidelity gap:** for the openat-only runtimes (Node/Go/Ruby/generic),
`executed_lines`/`executed_functions` are empty — only file paths register. That yields at best
import-level/package-level evidence, so those runtimes structurally **cannot reach a CONFIRMED
call-hit verdict** through eBPF. The host-tracer path (`_collect_ebpf_hits`) is even coarser:
it never builds NormalisedCoverage and only substring-matches package import names.

---

## 5. Notable risks / cleanup candidates (for the fix pass)

1. **Three divergent probe implementations.** `probe_router.py` (rich, dormant),
   `sidecar_entrypoint.py` (production, narrower), and `_build_bpftrace_script` (host-mode,
   Python-only). The richest one isn't wired in. Consolidate to one source of truth.
2. **Dead Go path:** `coverage_normaliser._parse_go_uprobe` + `_go_addrs_to_lines` have no probe
   feeding them; `select_probe` gives Go only openat.
3. **Ruby regression:** router supports Ruby USDT; the sidecar that actually runs does not.
4. **CAP-based hardening is documentation, not code** — production always runs `privileged: true`.
5. **Go false-positive detection** (`_strategy_cmdline` returns `go` for any unknown ELF).
6. **Distroless/musl/static** images are effectively unsupported (USDT-note + `.so`-name
   assumptions) and degrade silently to openat with no surfaced warning to the user-facing verdict.
7. **`ebpf_coverage.json` `[1]` line marker** is a schema hack shared implicitly between
   `to_coverage_py_format` and `build_hit_sets` — fragile coupling worth documenting/typing.

---

## Appendix — source map

| Concern | File |
|---------|------|
| Runtime detection | `agents/ebpf/runtime_detector.py` |
| Probe selection (rich, dormant) | `agents/ebpf/probe_router.py` |
| Output normalisation + coverage.py conversion | `agents/ebpf/coverage_normaliser.py` |
| Compose override / sidecar injection | `agents/ebpf/compose_injector.py` |
| Production sidecar entrypoint (probes actually run) | `agents/ebpf/sidecar/sidecar_entrypoint.py` |
| Sidecar image | `agents/ebpf/sidecar/Dockerfile` |
| Orchestration (both modes), host-tracer, correlate | `agents/agent_dynamic_reachability.py` (`_run_ebpf_sidecar_mode` ~2304, `_run_ebpf_mode` ~2191, `_build_bpftrace_script` ~2022, `_ebpf_available` ~1945) |
| Config knobs | `config/schema.py` (`EbpfSettings`, `RuntimeSettings`) |
| Verdict correlation | `agents/utils/coverage_correlator.py` (`correlate_coverage`) |
| Reference implementation | `labs/ebpf-verify/agent/ebpf_line_collector.py` |
