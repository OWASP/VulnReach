#!/usr/bin/env python3
"""Runtime package inventory — which of an app's installed packages actually load.

Independent of any CVE list: the question is "what does this project actually
use at runtime", so the answer is a full installed-vs-loaded breakdown, not a
per-vulnerability verdict. That makes it a project-health signal (how much of
your dependency tree is dead weight) rather than a security finding.

Two things make this work on images nothing else can touch:

  * The target needs no shell, no package manager, and no cooperation. Juice
    Shop's official image is *distroless* — `docker exec sh` fails — so the
    coverage-injection path cannot run there at all. The observer reads the
    package tree through /proc/<pid>/root and the loads through syscalls, both
    from outside the container.
  * We attach BEFORE the app starts. Node resolves almost its whole dependency
    graph during startup `require()`s, and an openat fires once per file, so
    attaching after the app is healthy sees essentially nothing. A container's
    cgroup id does not exist until it starts, so we capture unfiltered and
    filter by cgroup id in userspace — nothing is missed.

Usage (inside the privileged node-agent container, see observer/README.md):

  python3 /repo/agents/ebpf/observer/e2e/inventory.py \
      --image bkimminich/juice-shop:latest --port 3000 --ecosystem node
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import subprocess
import sys
import time
import urllib.request
import uuid

sys.path.insert(0, "/repo")

from agents.ebpf.observer_client import ObserverClient, _DEFAULT_BIN  # noqa: E402
from agents.ebpf.package_index import build_index  # noqa: E402
from agents.ebpf.reachability import (  # noqa: E402
    correlate_opens, CONFIRMED_REACHABLE,
)
from agents.ebpf.target_resolver import DockerTargetResolver  # noqa: E402

BIN = os.environ.get("VULNREACH_OBSERVER_BIN", _DEFAULT_BIN)


def _run(*args: str) -> str:
    return subprocess.run(list(args), capture_output=True, text=True,
                          check=True).stdout.strip()


def _ip(name: str) -> str:
    return _run("docker", "inspect", "-f",
                "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", name)


# Ground truth for the Node case: ask the runtime itself which packages it
# loaded, via require.cache, and compare against what we derived from syscalls.
# Loaded through NODE_OPTIONS so the target image needs no shell and no rebuild.
# Caveat: require.cache covers CommonJS only — ESM-only packages (Juice Shop has
# several under @ai-sdk/) will be missing from the truth set but legitimately
# present in ours, so treat "we saw it, node didn't" as needing a look, not as a
# automatic false positive.
_NODE_HOOK = r"""
const fs = require('fs');
function pkgOf(p) {
  const i = p.lastIndexOf('/node_modules/');
  if (i < 0) return null;
  const parts = p.slice(i + '/node_modules/'.length).split('/');
  return parts[0].startsWith('@') ? parts[0] + '/' + parts[1] : parts[0];
}
function dump() {
  const s = new Set();
  for (const p of Object.keys(require.cache)) {
    const n = pkgOf(p);
    if (n) s.add(n);
  }
  try { fs.writeFileSync('/tmp/vr_loaded.json', JSON.stringify([...s].sort())); }
  catch (e) {}
}
setInterval(dump, 2000);
process.on('exit', dump);
"""


def _start_target(name: str, image: str, ground_truth: bool) -> None:
    """Start the target, optionally with the require.cache probe injected."""
    if not ground_truth:
        _run("docker", "run", "-d", "--name", name, image)
        return
    hook = f"/tmp/vr_hook_{name}.js"
    with open(hook, "w") as fh:
        fh.write(_NODE_HOOK)
    _run("docker", "create", "--name", name,
         "-e", "NODE_OPTIONS=--require /tmp/vr_hook.js", image)
    _run("docker", "cp", hook, f"{name}:/tmp/vr_hook.js")
    _run("docker", "start", name)


def _read_ground_truth(name: str) -> list[str] | None:
    dest = f"/tmp/vr_truth_{name}.json"
    try:
        _run("docker", "cp", f"{name}:/tmp/vr_loaded.json", dest)
        with open(dest) as fh:
            return json.load(fh)
    except Exception:
        return None


def _get(url: str, timeout: float = 10.0) -> int:
    try:
        with urllib.request.urlopen(url, timeout=timeout) as r:
            r.read()
            return r.status
    except Exception:
        return 0


async def inventory(image: str, port: int, ecosystem: str, paths: list[str],
                    boot_timeout: float, settle: float,
                    ground_truth: bool = False) -> dict:
    name = f"vr_inv_{uuid.uuid4().hex[:8]}"

    # 1. Attach FIRST, unfiltered — the container does not exist yet, so there is
    #    no cgroup id to filter on and no way to miss the startup require storm.
    client = ObserverClient(BIN)
    ready = await client.start([], duration=900)
    collector = asyncio.create_task(client.collect())
    print(f"[inv] observer ready: {ready.get('progs')}", flush=True)
    await asyncio.sleep(1.0)

    cgroup_id = None
    try:
        # 2. Start the target.
        t_start = time.time()
        _start_target(name, image, ground_truth)
        rt = DockerTargetResolver().resolve(name)
        cgroup_id = rt.cgroup_id
        root = f"/proc/{rt.init_pid}/root"
        print(f"[inv] {name} cgroup={cgroup_id} pid={rt.init_pid}", flush=True)

        # 3. Wait for the app to serve, then drive a little traffic.
        url = f"http://{_ip(name)}:{port}"
        loop = asyncio.get_event_loop()
        healthy = False
        while time.time() - t_start < boot_timeout:
            if await loop.run_in_executor(None, _get, url + "/") == 200:
                healthy = True
                break
            await asyncio.sleep(1.0)
        boot_s = round(time.time() - t_start, 1)
        print(f"[inv] healthy={healthy} after {boot_s}s", flush=True)

        for p in paths:
            code = await loop.run_in_executor(None, _get, url + p)
            print(f"[inv]   GET {p} -> {code}", flush=True)
        await asyncio.sleep(settle)

        # 4. Index the tree from outside (no shell needed in the target).
        t0 = time.time()
        index = build_index(root, ecosystems=(ecosystem,))
        index_s = round(time.time() - t0, 1)
        print(f"[inv] indexed {len(index)} packages in {index_s}s", flush=True)
    finally:
        await client.stop()
        events = await collector

    truth = _read_ground_truth(name) if ground_truth else None
    mine = [e for e in events if e.get("cgroup_id") == cgroup_id]
    t0 = time.time()
    reach = correlate_opens(mine, index)
    corr_s = round(time.time() - t0, 1)

    installed = {}
    for e in index.entries():
        installed.setdefault(e.name, e.version)
    loaded = {pr.name: pr for pr in reach.values()}
    executed = sorted(n for n, pr in loaded.items()
                      if pr.verdict == CONFIRMED_REACHABLE)

    try:
        subprocess.run(["docker", "rm", "-f", name], capture_output=True)
    except Exception:
        pass

    cross = {}
    if truth is not None:
        t, o = set(truth), set(loaded)
        cross = {"truth_count": len(t),
                 "agree": len(t & o),
                 "missed_by_us": sorted(t - o),      # node loaded it, we did not see it
                 "extra_vs_truth": sorted(o - t)}    # we saw it, require.cache lacks it (ESM)

    return {
        "ground_truth": cross,
        "image": image, "ecosystem": ecosystem,
        "healthy": healthy, "boot_seconds": boot_s,
        "index_seconds": index_s, "correlate_seconds": corr_s,
        "events_total": len(events), "events_target": len(mine),
        "opens_target": sum(1 for e in mine if e.get("type") == "open"),
        "installed_count": len(installed),
        "loaded_count": len(loaded),
        "executed_count": len(executed),
        "loaded": sorted(loaded),
        "never_loaded": sorted(set(installed) - set(loaded)),
        "executed": executed,
        "versions": {n: installed.get(n) for n in sorted(loaded)},
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--image", default="bkimminich/juice-shop:latest")
    ap.add_argument("--port", type=int, default=3000)
    ap.add_argument("--ecosystem", default="node")
    ap.add_argument("--path", action="append", default=[])
    ap.add_argument("--boot-timeout", type=float, default=180.0)
    ap.add_argument("--settle", type=float, default=3.0)
    ap.add_argument("--out", default="")
    ap.add_argument("--ground-truth", action="store_true",
                    help="inject a require.cache probe via NODE_OPTIONS and cross-check")
    args = ap.parse_args()

    paths = args.path or ["/", "/rest/products/search?q=apple",
                          "/api/Challenges/", "/rest/admin/application-version",
                          "/api/Quantitys/", "/rest/basket/1"]
    r = asyncio.run(inventory(args.image, args.port, args.ecosystem, paths,
                              args.boot_timeout, args.settle, args.ground_truth))

    pct = 100.0 * r["loaded_count"] / r["installed_count"] if r["installed_count"] else 0
    print("\n" + "=" * 72)
    print(f"RUNTIME PACKAGE INVENTORY — {r['image']}")
    print("=" * 72)
    print(f"  installed ({r['ecosystem']}) : {r['installed_count']}")
    print(f"  loaded at runtime  : {r['loaded_count']}  ({pct:.1f}%)")
    print(f"  never loaded       : {len(r['never_loaded'])}")
    print(f"  native code exec'd : {r['executed_count']}  {r['executed'][:8]}")
    print(f"  target open events : {r['opens_target']} (of {r['events_total']} host-wide)")
    print(f"  timings: boot {r['boot_seconds']}s | index {r['index_seconds']}s "
          f"| correlate {r['correlate_seconds']}s")
    print("-" * 72)
    print("loaded:      " + ", ".join(r["loaded"][:60]) +
          (" ..." if r["loaded_count"] > 60 else ""))
    print("never loaded:" + ", ".join(r["never_loaded"][:40]) +
          (" ..." if len(r["never_loaded"]) > 40 else ""))
    gt = r.get("ground_truth") or {}
    if gt:
        print(f"CROSS-CHECK vs node require.cache ({gt['truth_count']} pkgs):")
        print(f"  agree                : {gt['agree']}/{gt['truth_count']}")
        print(f"  node loaded, we missed: {len(gt['missed_by_us'])}  {gt['missed_by_us'][:12]}")
        print(f"  we saw, cache lacks   : {len(gt['extra_vs_truth'])} (ESM is invisible to require.cache)")
        print(f"    {gt['extra_vs_truth'][:12]}")
        print("=" * 72)

    if args.out:
        with open(args.out, "w") as fh:
            json.dump(r, fh, indent=2)
        print(f"[inv] wrote {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
