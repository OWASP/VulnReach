# VulnReach eBPF Observer (Tier A baseline)

Language-agnostic, cgroup-scoped syscall observer. Standalone Go/cilium-ebpf binary
(D8) that loads a CO-RE program, filters events in-kernel by cgroup id, and streams
NDJSON. See `docs/ebpf-redesign.md` and `docs/ebpf-p0-spec.md`.

**Programs:** `sched_process_exec` (P0, `exec`), `sys_enter_openat`/`openat2` (P1, `open`),
`sys_enter_mmap` filtered to `PROT_EXEC` + file-backed (P4, `mmap_exec`). All are
cgroup-filtered in-kernel and share one ring buffer; a `kind` field discriminates
them. Control lines: `ready` / `warn` / `error` / `summary`.

**Rules** (`reachability.py`): R1 open under a package prefix ⇒ loaded ⇒
POTENTIALLY_REACHABLE→`LIKELY`; R2 native `.so` mapped PROT_EXEC ⇒ compiled code
executing ⇒ CONFIRMED_REACHABLE→`CONFIRMED` (0.8). mmap gives only a basename, so
R2 joins it to the full path seen in the open stream for package attribution.

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

Validated result (with R2 active): **1 CONFIRMED** (PyYAML — its `_yaml` C extension
was mapped PROT_EXEC), **5 LIKELY** (Flask, requests, Jinja2, Werkzeug, urllib3 —
pure-Python loads), **5 NOT_OBSERVED** (lxml, cryptography, SQLAlchemy, PyJWT,
Pillow — installed but never loaded).

**Note:** the scan-runner must install `schemathesis==4.11.0` (same pin as
`requirements.txt`). The agent's `--url`/`--max-examples` are 4.x flags; installing
`schemathesis<4` yields the 3.x CLI (`--base-url`/`--hypothesis-max-examples`) and
every run fails with rc=2 — a harness misconfiguration, not a product bug.
