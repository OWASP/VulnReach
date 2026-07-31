# VulnReach eBPF Observer (Tier A baseline)

Language-agnostic, cgroup-scoped syscall observer. Standalone Go/cilium-ebpf binary
(D8) that loads a CO-RE program, filters events in-kernel by cgroup id, and streams
NDJSON. See `docs/ebpf-redesign.md` and `docs/ebpf-p0-spec.md`.

**P0 scope:** one program — `sched_process_exec` — proving the pipeline + cgroup
isolation. Seed of P3. Emits `ready`/`error`/`summary` control lines and `exec` events.

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
