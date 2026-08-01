# VulnReach eBPF Observer (Tier A baseline)

Language-agnostic, cgroup-scoped syscall observer. Standalone Go/cilium-ebpf binary
(D8) that loads a CO-RE program, filters events in-kernel by cgroup id, and streams
NDJSON. See `docs/ebpf-redesign.md` and `docs/ebpf-p0-spec.md`.

**Programs:** `sched_process_exec` (P0, `exec`), `sys_enter_openat`/`openat2` (P1, `open`),
`sys_enter_mmap` filtered to `PROT_EXEC` + file-backed (P4, `mmap_exec`), and two
best-effort Tier B probes: a uprobe on CPython's eval loop (`py_call`) and the
JVM's `hotspot:class__loaded` USDT probe (`java_class`). All are cgroup-filtered
in-kernel and share one ring buffer; a `kind` field discriminates them.
Control lines: `ready` / `warn` / `marked` / `error` / `summary`.

**Rules** (`reachability.py`): R1 open under a package prefix ⇒ loaded ⇒
POTENTIALLY_REACHABLE→`LIKELY`; R2 native `.so` mapped PROT_EXEC ⇒ compiled code
executing ⇒ CONFIRMED_REACHABLE→`CONFIRMED` (0.8). mmap gives only a basename, so
R2 joins it to the full path seen in the open stream for package attribution.

R5 (Tier B, Python) is the CPython uprobe: which *source file* the interpreter
evaluated a frame from. R6 (Tier B, Java) is the JVM class__loaded probe: which
*class* was resolved. Both ⇒ `CONFIRMED` (0.85). See "Tier B" below.

R4 (`verdict_integration.py`) cross-references the static tainter: a package that is
loaded (R1) **and** sits at the end of a taint flow ⇒ `CONFIRMED` (0.9); a taint flow
to a package that never loaded ⇒ `POSSIBLE` (0.4). R2+R4 together ⇒ 0.95. The verdict
itself is `correlation.engine.dynamic_reachability_verdict()` — the product's canonical
rule, not a parallel one.

## Tier B — CPython uprobe (P8, optional)

Pass `--python-lib <host-visible path to libpython>` to attach a uprobe on
`_PyEval_EvalFrameDefault`. **This is best-effort by design: every failure is a
`warn`, never an `error`, and the Tier A baseline is unaffected.**

- **Not USDT.** Stock `python:*-slim` images are not built `--with-dtrace`, so the
  `python:line` / `python:function__entry` probes the old `probe_router.py`
  targeted do not exist there (verified: `readelf -n` reports 0 `stapsdt` notes).
  `_PyEval_EvalFrameDefault` *is* in `.dynsym`, so a uprobe needs no debug info.
- **Version-keyed struct offsets** (`pyOffsets` in `main.go`) walk
  `frame -> f_code -> co_filename`. The frame argument changed type in 3.11
  (`PyFrameObject*` -> `_PyInterpreterFrame*`), moved in 3.12, and
  `PyASCIIObject` shrank 48->40 in 3.12. Offsets are pushed into a BPF map at
  attach time, so there is one program for all versions. An unknown version
  warns and skips.
- **Volume control.** The probe fires on every Python call. The kernel side
  dedupes by `co_filename` pointer, so a run emits a few hundred events instead
  of millions.
- **Boot vs traffic.** Importing a package runs plenty of its own code, so "a
  frame executed" alone is barely stricter than R1. `TrafficWindow.mark()`
  (called once the target is healthy) writes `mark` to the observer's stdin,
  which bumps the dedupe epoch so files reported during startup can be reported
  once more while serving requests. Only post-mark frames count as R5; earlier
  ones fall back to load-level R1.

## Tier B — JVM class loads (Rule R6, optional)

Pass `--jvm-lib <host-visible path to libjvm.so>`. Same best-effort contract as
the Python probe.

- **USDT, and it actually exists here.** Unlike CPython, stock JDK images ship
  `libjvm.so` with ~567 active USDT probes. `class__loaded` has no semaphore and
  is *not* gated by `DTraceMethodProbes` (which stays off by default), so no
  `-XX` flag and no image change are needed.
- **A stronger signal than Python's by construction.** The JVM resolves a class
  on *first active use*, so a class load already means the code was needed — not
  merely that a file was on disk. The traffic boundary still applies: classes
  resolved while wiring up the app at boot are startup work.
- **cilium/ebpf has no USDT support**, so `usdt.go` parses `.note.stapsdt`
  itself: it converts the probe's recorded address to a file offset (applying the
  `.stapsdt.base` prelink fixup and mapping through PT_LOAD) and resolves which
  register each argument lives in. USDT arguments are **not** in
  calling-convention order — for `class__loaded` the name is in `x3` and its
  length in `x2` — so registers are resolved at attach time and passed via a map.
  Arguments in memory operands are unsupported and warn out.
- **The class name is a HotSpot `Symbol` body and is not NUL-terminated.** The
  read is length-bounded; reading to a NUL yields trailing garbage.

Java packages are indexed by **class-name prefix** (`com/fasterxml/jackson/`),
not file path — the probe never reports a path. `build_java` reads each jar's
entries, takes coordinates from `META-INF/maven/*/pom.properties` (falling back
to the filename), and unpacks Spring Boot `BOOT-INF/lib/` nested jars so a fat
jar's dependencies are attributed individually.

## Build (in Docker — everything runs in Linux containers)

```bash
# 1. toolchain image (once)
docker build -f Dockerfile.build -t vulnreach-observer-build .

# 2. generate vmlinux.h + bpf2go + compile static binary -> bin/vulnreach-observer
docker run --rm --privileged -v "$PWD":/src -v vulnreach-observer-gocache:/go \
  vulnreach-observer-build make all
```

Generated files (`vmlinux.h`, `observer_bpfel.{go,o}`, `bin/`) are gitignored and
rebuilt by `make all`. Runtime needs BTF at `/sys/kernel/btf/vmlinux` (kernel ≥5.8),
cgroup v2, and tracefs mounted.

## Run

```
vulnreach-observer --cgroup-id <u64> [--cgroup-id ...] [--duration <secs>]
```

No `--cgroup-id` ⇒ observe all cgroups. Must run privileged (or CAP_BPF+CAP_PERFMON)
with `mount -t tracefs nodev /sys/kernel/tracing`.

## Acceptance test (P0)

```bash
docker build -f Dockerfile.test -t vulnreach-observer-test .   # adds python3 + docker CLI

REPO=$(git rev-parse --show-toplevel)
docker run --rm --privileged --pid=host --cgroupns=host \
  -v /var/run/docker.sock:/var/run/docker.sock -v "$REPO":/repo \
  -e PYTHONPATH=/repo -e DOCKER_API_VERSION=1.44 \
  -e VULNREACH_OBSERVER_BIN=/repo/agents/ebpf/observer/bin/vulnreach-observer \
  vulnreach-observer-test \
  bash -c 'mount -t tracefs nodev /sys/kernel/tracing 2>/dev/null; cd /repo && python3 -m pytest tests/test_ebpf_observer_p0.py -v'
```

Asserts: observer filtered to a target container captures its execs; a control
container's execs never appear (cgroup isolation). `DOCKER_API_VERSION=1.44` pins the
old Debian docker CLI to the Docker Desktop daemon's minimum API.

## Python integration

- `agents/ebpf/target_resolver.py` — `DockerTargetResolver`: container ref → cgroup id.
- `agents/ebpf/observer_client.py` — `ObserverClient`: async spawn + NDJSON stream.
- `agents/ebpf/package_index.py` / `reachability.py` — Package-Index + Rule R1.
- `agents/ebpf/verdict_integration.py` — R1 → canonical `ReachabilityFinding`.
- `agents/ebpf/observer_runner.py` — `run_observer_reachability`: the agent entrypoint.
- Enable in a scan: `runtime.ebpf.enabled=true`, `runtime.ebpf.engine="observer"`,
  and `VULNREACH_ALLOW_EBPF=1`.

## Full-scan e2e (drives DynamicReachabilityAgent._run_observer_mode)

Heavy (builds the target image, needs host networking). Runs the whole agent path
against `labs/python_vuln_app`.

```bash
docker build -f Dockerfile.build    -t vulnreach-observer-build .
docker run --rm --privileged -v "$PWD":/src vulnreach-observer-build make all   # build binary
docker build -f Dockerfile.test     -t vulnreach-observer-test .
docker build -f Dockerfile.scanrunner -t vulnreach-scan-runner .

REPO=$(git rev-parse --show-toplevel)
docker run --rm --privileged --network host --pid=host --cgroupns=host \
  -v /var/run/docker.sock:/var/run/docker.sock -v "$REPO":/repo \
  -e PYTHONPATH=/repo -e DOCKER_API_VERSION=1.44 \
  -e VULNREACH_OBSERVER_BIN=/repo/agents/ebpf/observer/bin/vulnreach-observer \
  vulnreach-scan-runner \
  bash -c 'mount -t tracefs nodev /sys/kernel/tracing 2>/dev/null; python3 /repo/agents/ebpf/observer/e2e/scan_driver.py'
```

Validated result (R2 + R4 + R5 active, real taint flows from
`labs/python_vuln_app/findings.json`):

| Verdict | Conf | Packages | Why |
|---------|------|----------|-----|
| CONFIRMED | 0.95 | Flask, requests, PyYAML | executed during traffic (R5) + taint path (R4) |
| CONFIRMED | 0.85 | Jinja2, Werkzeug, urllib3 | executed during traffic (R5) |
| NOT_OBSERVED | 0.10 | lxml, cryptography, SQLAlchemy, PyJWT, Pillow | installed, never loaded |

Of the 16 packages seen loaded, only 10 execute while serving traffic —
certifi/idna/click/itsdangerous load at boot and are never exercised. Each rule
adds a distinct axis: R1 "was loaded", R5 "ran while serving a request",
R4 "a static taint path reaches it".

**Note:** the scan-runner must install `schemathesis==4.11.0` (same pin as
`requirements.txt`). The agent's `--url`/`--max-examples` are 4.x flags; installing
`schemathesis<4` yields the 3.x CLI (`--base-url`/`--hypothesis-max-examples`) and
every run fails with rc=2 — a harness misconfiguration, not a product bug.
