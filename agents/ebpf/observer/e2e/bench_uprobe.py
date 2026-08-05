#!/usr/bin/env python3
"""Measure what the Tier B CPython uprobe (Rule R5) actually costs, per version.

Answers the two questions P8 shipped without answering:

  1. How much does attaching a uprobe to `_PyEval_EvalFrameDefault` slow the
     target down? The in-kernel dedupe suppresses ringbuf *writes*, not the
     trap, so every eligible call still pays the full trap + map-lookup cost for
     the whole observation window.
  2. Do the per-version offset branches in main.go's pyOffsetTable actually
     work? P8 only ever attached live against 3.11; wrong offsets on another
     version read garbage rather than failing loudly, so "it attached" is not
     evidence it is correct.

Both are answered by the same run: for each interpreter we time a workload with
the probe off and on, and assert the events name the workload's own source file
(which only happens if frame -> f_code -> co_filename -> chars all resolved).

Run inside the privileged node-agent container (see observer/README.md):

  docker run --rm --privileged --pid=host --cgroupns=host \
    -v /var/run/docker.sock:/var/run/docker.sock -v "$REPO":/repo \
    -e PYTHONPATH=/repo -e DOCKER_API_VERSION=1.44 \
    -e VULNREACH_OBSERVER_BIN=/repo/agents/ebpf/observer/bin/vulnreach-observer \
    vulnreach-observer-test \
    bash -c 'mount -t tracefs nodev /sys/kernel/tracing 2>/dev/null;
             python3 /repo/agents/ebpf/observer/e2e/bench_uprobe.py'
"""
from __future__ import annotations

import asyncio
import json
import os
import subprocess
import sys
import time
import uuid

sys.path.insert(0, "/repo")

from agents.ebpf.observer_client import ObserverClient, _DEFAULT_BIN  # noqa: E402
from agents.ebpf.observer_runner import find_libpython  # noqa: E402
from agents.ebpf.package_index import build_index  # noqa: E402
from agents.ebpf.reachability import correlate_opens  # noqa: E402
from agents.ebpf.target_resolver import DockerTargetResolver  # noqa: E402

BIN = os.environ.get("VULNREACH_OBSERVER_BIN", _DEFAULT_BIN)
WORKLOAD = "/repo/tests/fixtures/ebpf/bench_workload.py"
GUEST_WORKLOAD = "/tmp/bench_workload.py"
VERSIONS = ("3.8", "3.9", "3.10", "3.11", "3.12", "3.13")
N = int(os.environ.get("BENCH_N", "200000"))
REPS = int(os.environ.get("BENCH_REPS", "7"))


def _run(*args: str) -> str:
    return subprocess.run(list(args), capture_output=True, text=True,
                          check=True).stdout.strip()


def _workload(container: str) -> dict:
    return json.loads(_run("docker", "exec", container, "python",
                           GUEST_WORKLOAD, str(N), str(REPS)))


async def _measure(container: str, cgroup_id: int, python_lib):
    """Run the workload once; with the observer attached unless python_lib is False.

    python_lib=False  => no observer at all (baseline)
    python_lib=None   => observer attached, Tier A only
    python_lib=<path> => observer attached, Tier B uprobe live
    """
    if python_lib is False:
        loop = asyncio.get_event_loop()
        return {}, await loop.run_in_executor(None, _workload, container), []

    client = ObserverClient(BIN)
    ready = await client.start([cgroup_id], duration=300, python_lib=python_lib)
    # Drain concurrently: a blocking read here would stall the collector and
    # truncate the stream once the stdout pipe fills.
    collector = asyncio.create_task(client.collect())
    try:
        await asyncio.sleep(1.0)  # let the probes settle
        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(None, _workload, container)
    finally:
        await client.stop()
    return ready, result, await collector


async def bench_version(version: str) -> dict:
    image = f"python:{version}-slim"
    name = f"vr_bench_{version.replace('.', '')}_{uuid.uuid4().hex[:6]}"
    _run("docker", "run", "-d", "--name", name, image, "sleep", "600")
    try:
        _run("docker", "cp", WORKLOAD, f"{name}:{GUEST_WORKLOAD}")
        rt = DockerTargetResolver().resolve(name)
        lib = find_libpython(f"/proc/{rt.init_pid}/root")

        _, off, _ = await _measure(name, rt.cgroup_id, False)
        _, tier_a, _ = await _measure(name, rt.cgroup_id, None)
        ready, tier_b, events = await _measure(name, rt.cgroup_id, lib)

        calls = [e for e in events if e.get("type") == "py_call"]
        return {
            "version": version,
            "reported": off.get("python"),
            "libpython": lib,
            "attached": "uprobe:py_eval_frame" in (ready.get("progs") or []),
            "warnings": ready.get("warnings") or [],
            "off": off,
            "tier_a": tier_a,
            "tier_b": tier_b,
            "py_call_events": len(calls),
            # The correctness check: did we decode this workload's own filename?
            "saw_workload_file": any(e.get("filename") == GUEST_WORKLOAD for e in calls),
            "filenames": sorted({e.get("filename") for e in calls})[:8],
        }
    finally:
        subprocess.run(["docker", "rm", "-f", name], capture_output=True)


def _row(r: dict) -> str:
    def per(cond, shape):
        return r[cond][shape]["ns_per_call"] if r.get(cond) else float("nan")

    def slow(shape):
        base = per("off", shape)
        return (per("tier_b", shape) - base) if base == base else float("nan")

    return (f"{r['version']:<5} {str(r['attached']):<5} "
            f"{per('off', 'py_to_py'):>8.1f} {per('tier_a', 'py_to_py'):>8.1f} "
            f"{per('tier_b', 'py_to_py'):>8.1f} {slow('py_to_py'):>+9.1f}   "
            f"{per('off', 'c_to_py'):>8.1f} {per('tier_a', 'c_to_py'):>8.1f} "
            f"{per('tier_b', 'c_to_py'):>8.1f} {slow('c_to_py'):>+9.1f}  "
            f"{str(r['saw_workload_file']):<5} {r['py_call_events']:>4}")


APP_IMAGE = os.environ.get("VULNREACH_APP_IMAGE", "python_vuln_app:plain")
APP_PORT = 3000
APP_SECONDS = float(os.environ.get("BENCH_SECONDS", "20"))
WINDOW = int(os.environ.get("BENCH_WINDOW", "5"))


def _app_ip(name: str) -> str:
    return _run("docker", "inspect", "-f",
                "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", name)


def _hammer(url: str, seconds: float) -> dict:
    """Drive sequential requests for `seconds` from *outside* the traced cgroup.

    The client runs here, in the runner container, so only the server's
    interpreter carries the uprobe — the latency delta is all target-side.

    Driven by wall time rather than a request count so that a run always spans
    the detach boundary: with a fixed count, a fast condition finishes before
    the Tier B window even elapses and the comparison proves nothing.
    Latencies are kept with their offset from t0 so we can show the app speeding
    back up the moment the probe detaches.
    """
    import urllib.request

    t0 = time.perf_counter_ns()
    deadline = t0 + int(seconds * 1e9)
    samples = []  # (offset_ns, latency_ns)
    while time.perf_counter_ns() < deadline:
        s = time.perf_counter_ns()
        with urllib.request.urlopen(url, timeout=60) as resp:
            resp.read()
        e = time.perf_counter_ns()
        samples.append((s - t0, e - s))

    def med(vals):
        vals = sorted(vals)
        return round(vals[len(vals) // 2] / 1000, 1) if vals else None

    lat = [l for _, l in samples]
    early = [l for off, l in samples if off < WINDOW * 1e9]
    late = [l for off, l in samples if off >= WINDOW * 1e9]
    return {
        "requests": len(samples),
        "seconds": round(seconds, 1),
        "rps": round(len(samples) / seconds, 1),
        "median_us": med(lat),
        "p95_us": round(sorted(lat)[int(len(lat) * 0.95)] / 1000, 1) if lat else None,
        f"median_first_{WINDOW}s_us": med(early),
        f"median_after_{WINDOW}s_us": med(late),
    }


async def bench_app(path: str = "/yaml-test") -> dict:
    """Macro-benchmark: real Flask/gunicorn request latency with the probe on/off.

    The micro numbers only bound the cost *per trap*; what decides whether R5 is
    safe to ship is how many traps a real request path actually incurs.
    """
    import urllib.request

    name = f"vr_bench_app_{uuid.uuid4().hex[:6]}"
    _run("docker", "run", "-d", "--name", name, APP_IMAGE)
    try:
        ip = _app_ip(name)
        url = f"http://{ip}:{APP_PORT}{path}"
        for _ in range(60):  # wait for gunicorn
            try:
                urllib.request.urlopen(f"http://{ip}:{APP_PORT}/health", timeout=2).read()
                break
            except Exception:
                await asyncio.sleep(1.0)
        else:
            raise RuntimeError(f"app never became healthy at {url}")

        rt = DockerTargetResolver().resolve(name)
        root = f"/proc/{rt.init_pid}/root"
        lib = find_libpython(root)
        index = build_index(root, ecosystems=("python",))
        loop = asyncio.get_event_loop()

        async def measure(python_lib, tier_b_window=0):
            if python_lib is False:
                return {}, await loop.run_in_executor(None, _hammer, url, APP_SECONDS), []
            client = ObserverClient(BIN)
            ready = await client.start([rt.cgroup_id], duration=600,
                                       python_lib=python_lib,
                                       tier_b_window=tier_b_window)
            collector = asyncio.create_task(client.collect())
            try:
                await asyncio.sleep(1.0)
                start_ns = time.monotonic_ns()
                client.mark()  # same epoch bump the agent does when traffic starts
                res = await loop.run_in_executor(None, _hammer, url, APP_SECONDS)
                res["traffic_start_ns"] = start_ns
            finally:
                await client.stop()
            return ready, res, await collector

        def r5_packages(events, start_ns):
            """The evidence that actually matters: which packages reach R5."""
            reach = correlate_opens(events, index, traffic_start_ns=start_ns)
            return sorted(pr.name for pr in reach.values() if "R5" in pr.rule)

        await loop.run_in_executor(None, _hammer, url, 3.0)  # warm the app
        _, off, _ = await measure(False)
        _, tier_a, _ = await measure(None)
        ready, tier_b, ev_full = await measure(lib)
        _, tier_b_win, ev_win = await measure(lib, tier_b_window=WINDOW)

        full_pkgs = r5_packages(ev_full, tier_b["traffic_start_ns"])
        win_pkgs = r5_packages(ev_win, tier_b_win["traffic_start_ns"])
        return {
            "image": APP_IMAGE, "path": path, "seconds": APP_SECONDS,
            "libpython": lib, "window_s": WINDOW,
            "attached": "uprobe:py_eval_frame" in (ready.get("progs") or []),
            "off": off, "tier_a": tier_a,
            "tier_b_unbounded": tier_b, "tier_b_windowed": tier_b_win,
            "r5_packages_unbounded": full_pkgs,
            "r5_packages_windowed": win_pkgs,
            "r5_lost_by_window": sorted(set(full_pkgs) - set(win_pkgs)),
            "r5_gained_by_window": sorted(set(win_pkgs) - set(full_pkgs)),
            "py_call_events": sum(1 for e in ev_full if e.get("type") == "py_call"),
        }
    finally:
        subprocess.run(["docker", "rm", "-f", name], capture_output=True)


async def main_app() -> int:
    r = await bench_app()
    print(json.dumps(r, indent=2))
    base = r["off"]["median_us"]
    full = r["tier_b_unbounded"]["median_us"]
    win = r["tier_b_windowed"]["median_us"]
    print(f"\nmedian request latency ({r['image']}):")
    print(f"  observer off        {base:>9.1f} us")
    print(f"  tier A only         {r['tier_a']['median_us']:>9.1f} us  "
          f"({r['tier_a']['median_us'] / base:.2f}x)")
    print(f"  tier B unbounded    {full:>9.1f} us  ({full / base:.1f}x)")
    print(f"  tier B {r['window_s']}s window   {win:>9.1f} us  ({win / base:.1f}x)")
    # The whole-run median flatters the window (most of the run is unprobed).
    # Split it so the cost that is actually still paid stays visible.
    w = r["window_s"]
    early = r["tier_b_windowed"].get(f"median_first_{w}s_us")
    late = r["tier_b_windowed"].get(f"median_after_{w}s_us")
    if early and late:
        print(f"    within window     {early:>9.1f} us  ({early / base:.1f}x)  <- cost is real, just bounded")
        print(f"    after detach      {late:>9.1f} us  ({late / base:.1f}x)")
    print(f"  requests served: off={r['off']['rps']}/s  "
          f"unbounded={r['tier_b_unbounded']['rps']}/s  windowed={r['tier_b_windowed']['rps']}/s")
    print(f"\nR5 packages: unbounded={r['r5_packages_unbounded']}")
    print(f"             windowed ={r['r5_packages_windowed']}")
    print(f"  lost by windowing: {r['r5_lost_by_window'] or 'none'}")
    return 0


async def main() -> int:
    if sys.argv[1:2] == ["app"]:
        return await main_app()
    versions = sys.argv[1:] or list(VERSIONS)
    results = []
    for v in versions:
        print(f"[bench] python {v} ...", flush=True)
        try:
            r = await bench_version(v)
        except Exception as exc:  # one bad version must not lose the rest
            print(f"[bench] python {v} FAILED: {exc}", flush=True)
            continue
        results.append(r)
        print(f"        attached={r['attached']} events={r['py_call_events']} "
              f"decoded_own_file={r['saw_workload_file']}", flush=True)

    print("\n" + "=" * 108)
    print("ns per call (min of %d reps, n=%d)" % (REPS, N))
    print(f"{'ver':<5} {'att':<5} {'--- py_to_py (inlined on 3.11+) ---':^38}   "
          f"{'--- c_to_py (always traps) ---':^38}")
    print(f"{'':<5} {'':<5} {'off':>8} {'tierA':>8} {'tierB':>8} {'delta':>9}   "
          f"{'off':>8} {'tierA':>8} {'tierB':>8} {'delta':>9}  {'ok':<5} {'evts':>4}")
    print("-" * 108)
    for r in results:
        print(_row(r))
    print("=" * 108)

    out = os.environ.get("BENCH_OUT")
    if out:
        with open(out, "w") as fh:
            json.dump(results, fh, indent=2)
        print(f"[bench] wrote {out}")

    bad = [r["version"] for r in results if r["attached"] and not r["saw_workload_file"]]
    if bad:
        print(f"\nOFFSETS WRONG (attached but could not decode co_filename): {bad}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
