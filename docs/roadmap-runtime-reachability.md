# Runtime Reachability — Roadmap (v1 → v2 → eBPF observer)

Delivery roadmap for the **runtime reachability** line of work: how VulnReach went
from "here are your CVEs" to "here is which code actually ran", and what is left.

Scope note: [`ROADMAP.md`](../ROADMAP.md) (repo root) is the product-wide roadmap —
languages, API surface, AI endpoints. **This document covers the runtime/eBPF
track only**, in delivery order, and is the place to look for what is shipped
versus claimed. Where the two disagree, see [Corrections](#corrections) below.

Legend: `●` shipped & validated · `◐` in progress · `○` queued · `⊘` descoped (with reason)

---

## The through-line

Each major version answered a strictly harder question about the same CVE list:

| | Question | Evidence used |
|---|---|---|
| **v1** | *Which vulnerable packages are present?* | SBOM / Trivy |
| **v2** | *Which of them can be reached in code?* | AST call graph + taint flow |
| **v2 + eBPF** | *Which of them actually executed?* | Kernel syscalls + runtime probes |

Each layer narrows the previous one. The eBPF layer is the first that cannot be
argued with — it reports what the kernel observed, not what a model inferred.

---

## Release track

```
  v1.0.1        v1.0.2         v2.0.1          eBPF observer      hardening       scale-out       static
  2025-09-12    2025-11-20     2026-04-03      P0–P8              + CI            P6 / P9         binaries
     ●─────────────●──────────────●──────────────────●───────────────◐───────────────○───────────────○────▶
  SCA + Python  multi-language  OWASP project    language-agnostic   perf-bounded    containerd/     Go / Rust
  taint flow    (Java, JS)      + Intelligent    syscall baseline,   probes, amd64   CRI, DaemonSet, research
  reachability  call graphs     DAST, dashboard  Rules R1–R6        CI, inventory   network rules
                                                  ══ shipped ══     ══ now ══       ══ queued ══
```

---

## v1 → v2 — what was achieved

`v1.0.1` (2025-09-12) → `v2.0.1` (2026-04-03), 23 commits between tags.

| | Capability | Status |
|---|---|---|
| ● | **Multi-language reachability** — Java and JavaScript call graphs alongside Python | shipped |
| ● | **Parallel runner pipeline** — dependency-aware scheduling | shipped |
| ● | **Scan lifecycle API** — `POST /scan`, cancel, delete, raw inspection, PDF export | shipped |
| ● | **Evidence graph + AI next-steps** — `POST /findings/{id}/next-steps`; deterministic verdict is read-only to the LLM | shipped |
| ● | **Secure-by-default runtime boundary** — no Docker socket in base compose; dynamic scans opt-in via restricted socket proxy | shipped |
| ● | **Intelligent DAST** + dashboard | shipped |
| ● | **Accepted as an official OWASP Project** | 2026-04 |

v2's reachability was **static-first**: call graph plus taint flow, with runtime
evidence available only through coverage.py injection and a bpftrace sidecar.
That runtime path had two structural limits — it required cooperation from the
target image (injected coverage, JVM flags), and it only ever worked for Python
and Java. Everything else silently degraded to `openat` guessing.

---

## v2 → eBPF observer — the current track

Rebuilt as a **language-agnostic, attach-from-outside** observer.
Design: [`ebpf-redesign.md`](ebpf-redesign.md) · Baseline audit: [`ebpf-audit.md`](ebpf-audit.md)

```
 P0    P1    P2    P4    P5    P7    P8   perf   inventory   CI     P6    P9   static
  ●─────●─────●─────●─────●─────●─────●─────●───────●─────────◐──────○─────○──────○
 cgroup open  pkg  native verdict taint TierB bounded  Juice/   amd64  net   K8s   Go/
 skeleton at  index exec  mapping xref  R5/R6 uprobe   crAPI    matrix R3  Daemon Rust
                                                                             Set
        └────────────── Tier A (mandatory) ──────────┘ └── Tier B (optional) ──┘
```

### Shipped ●

| Phase | What | Evidence it works |
|---|---|---|
| **P0/P1** | Go/cilium-ebpf observer, CO-RE, cgroup-filtered ring buffer; `exec` + `openat` | cgroup isolation test: target's events captured, control container's never |
| **P2** | Package-Index (path → package) + **Rule R1** (file load ⇒ loaded) | `requests` reached, installed-but-unimported `tabulate` not |
| **P4** | `mmap(PROT_EXEC)` + **Rule R2** (native code executed) | first `CONFIRMED` derived purely from syscalls |
| **P5** | Mapping onto the canonical `Verdict` enum — no parallel vocabulary | eBPF findings are indistinguishable downstream from coverage-derived ones |
| **P7** | **Rule R4** — static-taint cross-reference | delegates to `correlation.engine.dynamic_reachability_verdict`, the product's existing rule |
| **P8** | **Tier B** — CPython uprobe (**R5**) and JVM `class__loaded` USDT (**R6**) | pure-interpreted packages reach `CONFIRMED` on their own runtime evidence |
| — | **Perf hardening** — time-boxed uprobe (`--tier-b-window`) | measured 2.6×–11.4× request latency while attached; bounded to a 5s window, identical R5 output |
| — | **Runtime package inventory** — installed vs loaded, independent of CVEs | Juice Shop, crAPI (below) |

### In progress ◐

| Item | State |
|---|---|
| **CI on amd64** (`.github/workflows/ebpf-observer.yml`) | Written and committed; **not yet executed on GitHub** — needs a push to validate. Every result to date was produced by hand on arm64. |
| **Coverage gate repair** | `--cov-omit` was never a valid pytest-cov flag, so the gate never ran; moved to `[tool.coverage.run]`, threshold ratcheted to 20% (real: 21.93%) |

### Queued ○

| Item | Why it is not done |
|---|---|
| **P6 — network rules (R3)** | Lowest value: R3 can only ever yield `LIKELY`/`POSSIBLE`, which R1 already gives for loaded packages |
| **P9 — containerd/CRI + node DaemonSet** | `TargetResolver` interface exists; Docker is the only implementation. Needed for Kubernetes. |
| **D7 — restricted-cluster fallback** | How loudly to degrade when `CAP_BPF` is unavailable (PSA `restricted`). Due with P9. |
| **`_run_observer_mode` test** | The 117-line seam wiring all this into a real scan has no automated test; only driver scripts |
| **Inventory as a product surface** | Today it is an e2e script. To answer "what is the status of this project" it must flow into `AgentResult` → storage → dashboard. |
| **Go / Rust** | See [ceilings](#known-ceilings) — needs a different technique entirely, not more of this one |

### Descoped ⊘

| Item | Reason (evidence-based) |
|---|---|
| **Node.js Tier B** | `node:20-slim` has **0 USDT probes**, is statically linked, and V8 JIT has no stable per-call entry point. Getting a script name means walking `SharedFunctionInfo → Script` through pointer compression with no stable ABI across minors. Node keeps the honest Tier A R1 baseline. |
| **P3 — process-tree tracking** | cgroup filtering already covers forks/worker pools (e.g. gunicorn), which was P3's purpose |
| **Reviving `probe_router.py` as designed** | Its USDT probes do not exist on the images we scan — see [Corrections](#corrections) |

---

## Validated against

Not synthetic fixtures — real applications, with the result cross-checked where possible.

| Target | Shape | Result |
|---|---|---|
| `labs/python_vuln_app` | Flask/gunicorn, Python 3.9 | 3 evidence tiers; R5+R4 → `CONFIRMED` 0.95 |
| **OWASP Juice Shop** | Node, **distroless** (no shell) | **335 / 651** packages loaded (51.5%) — cross-checked against node's own `require.cache`: **335/335 exact, 0 missed, 0 extra** |
| **OWASP crAPI** | multi-service: Java + Python + Go, bearer-auth, OpenAPI | workshop **47/74**, chatbot **104/188**, identity **71/112** (16,919 JVM class loads) |
| CPython 3.8 – 3.13 | six interpreter versions | all six offset branches attach and decode `co_filename` |

Distroless matters: `docker exec sh` fails on Juice Shop, so the coverage-injection
path cannot run there **at all**. The observer reads the package tree via
`/proc/<pid>/root` and loads via syscalls, both from outside.

---

## Known ceilings

Confirmed by inspection, not assumed:

- **Statically-linked binaries are invisible.** Go (`crapi-community`) and Rust
  (`chromadb`) report **0 packages** — neither has `site-packages`, `node_modules`,
  or any equivalent, because dependencies are compiled in. No amount of traffic
  changes this. The honest claim is *language-agnostic for anything that loads
  dependencies from files at runtime* (Python, Node, Java, Ruby, PHP), and blind
  to static binaries.
- **Java has no Tier A coverage at all.** The Java index is keyed by class-name
  prefix because the JVM probe reports class names, never paths — so R1's `openat`
  stream has nothing to match. A Tier-A-only run reports 0% for a JVM service no
  matter how much of it ran. Java depends entirely on Tier B.
- **Loaded sets are a lower bound.** They reflect the traffic driven. More traffic
  can only move packages from "never loaded" to "loaded", never the reverse.
- **Attach ordering is load-bearing.** `openat` fires once per file and a JVM class
  resolves once, so the observer must attach *before* the target starts.

---

## Corrections

This track's audit disproved several claims still present in [`ROADMAP.md`](../ROADMAP.md)
and older changelog entries. Recording them here so they are not re-derived:

| Claim | Finding |
|---|---|
| "Python … runtime coverage (coverage.py + **eBPF USDT**)" | Stock `python:*-slim` is **not** built `--with-dtrace`: `readelf -n` reports **0 stapsdt notes**. `python:line` / `python:function__entry` cannot attach there. Replaced by a uprobe on `_PyEval_EvalFrameDefault`, which *is* exported in `.dynsym`. |
| "Java … eBPF runtime coverage (`hotspot:method__entry`)" | `method__entry` is gated behind `-XX:+ExtendedDTraceProbes` and is prohibitively expensive. **`hotspot:class__loaded` is ungated** — no JVM flag, no image change — and is stronger evidence, since the JVM resolves a class on first *active use*. |
| "Java USDT probes require `-XX:+ExtendedDTraceProbes`" | Not for `class__loaded`. Verified on stock `eclipse-temurin` and on crAPI's identity service. |
| "JavaScript eBPF coverage — wire Node.js USDT probes (`node:method__entry`)" | Those probes do not exist: `node:20-slim` has 0 USDT notes. Plan is not viable as written — see Descoped. |
| "eBPF tracing requires … `bpftrace` or BCC" | The observer requires neither. It is a static Go binary using CO-RE/BTF. |
| "LinuxKit cannot do eBPF" (audit note) | Stale. Docker Desktop's LinuxKit kernel 6.12.76 arm64 has cgroup v2 + BTF and loads CO-RE programs fine. |

---

## Immediate next step

**Validate the CI workflow on GitHub.** It is the only queued item that protects
everything already shipped: 14 live tests currently run only when a human runs
them, on one architecture. Wiring them into `ubuntu-latest` closes the amd64 gap
and the regression gap in one move.

After that, in order of value: `_run_observer_mode` test (the untested seam into
the product) → inventory as a real scan output → P9 for Kubernetes.
