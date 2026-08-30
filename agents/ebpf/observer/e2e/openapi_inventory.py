#!/usr/bin/env python3
"""Runtime package inventory for a multi-container, auth-gated OpenAPI app.

Generalises e2e/inventory.py from "one container, drive a few URLs" to what a
real target looks like: a compose stack of several services in several
languages, behind bearer auth, described by an OpenAPI document.

Built for OWASP crAPI, which is a good stress test precisely because it is
heterogeneous — a Java identity service, a Python workshop service and a Go
community service behind one gateway. One observer covers all of them: it
filters by cgroup id, so each container's events are separated afterwards and
each gets its own Package-Index in its own ecosystem.

Auth matters here. Almost every crAPI operation requires a bearer token, and an
unauthenticated sweep would spend 44 requests in the 401 handler — exercising
the auth filter and nothing else, then reporting a comfortingly small "loaded"
set that reflects only how far requests got. So we sign up, log in, and carry
the JWT through every call, and we report per-endpoint status codes so the
inventory can be read against how much of the API actually executed.

Usage (inside the privileged node-agent container):

  python3 openapi_inventory.py --spec /tmp/crapi-spec.json \
      --base-url http://localhost:8888 --compose /tmp/crapi/docker-compose.yml
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import random
import re
import string
import subprocess
import sys
import time
import urllib.error
import urllib.request

sys.path.insert(0, "/repo")

from agents.ebpf.observer_client import ObserverClient, _DEFAULT_BIN  # noqa: E402
from agents.ebpf.package_index import build_index  # noqa: E402
from agents.ebpf.reachability import (  # noqa: E402
    correlate_opens, CONFIRMED_REACHABLE,
)
from agents.ebpf.target_resolver import DockerTargetResolver  # noqa: E402

BIN = os.environ.get("VULNREACH_OBSERVER_BIN", _DEFAULT_BIN)
_METHODS = ("get", "post", "put", "delete", "patch")


def _run(*args: str, check: bool = True) -> str:
    return subprocess.run(list(args), capture_output=True, text=True,
                          check=check).stdout.strip()


# ── HTTP ──────────────────────────────────────────────────────────────────────

def _http(method: str, url: str, body=None, token=None, timeout=20.0):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method.upper())
    req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read()[:20000]
    except urllib.error.HTTPError as e:
        return e.code, e.read()[:2000]
    except Exception as e:
        return 0, str(e).encode()[:200]


# ── OpenAPI → concrete requests ───────────────────────────────────────────────

def _resolve(spec: dict, node):
    """Follow a $ref one level at a time until it is a real schema."""
    seen = 0
    while isinstance(node, dict) and "$ref" in node and seen < 10:
        parts = node["$ref"].lstrip("#/").split("/")
        node = spec
        for p in parts:
            node = (node or {}).get(p, {})
        seen += 1
    return node or {}


def _sample(spec: dict, schema: dict, depth: int = 0):
    """Smallest plausible instance of *schema*, preferring declared examples."""
    schema = _resolve(spec, schema)
    if depth > 5:
        return "x"
    for key in ("example", "default"):
        if key in schema:
            return schema[key]
    if "enum" in schema and schema["enum"]:
        return schema["enum"][0]
    t = schema.get("type")
    if t == "object" or "properties" in schema:
        props = schema.get("properties") or {}
        required = schema.get("required") or list(props)[:4]
        return {k: _sample(spec, props[k], depth + 1) for k in required if k in props}
    if t == "array":
        return [_sample(spec, schema.get("items") or {}, depth + 1)]
    if t == "integer":
        return 1
    if t == "number":
        return 1.0
    if t == "boolean":
        return True
    fmt = schema.get("format")
    if fmt == "email":
        return "vr_probe@example.com"
    if fmt in ("date-time", "date"):
        return "2020-01-01T00:00:00.000Z"
    return "1"


def _fill_path(path: str, ctx: dict) -> str:
    def sub(m):
        return str(ctx.get(m.group(1), 1))
    return re.sub(r"\{([^}]+)\}", sub, path)


def operations(spec: dict) -> list[dict]:
    out = []
    for path, item in (spec.get("paths") or {}).items():
        for method, op in (item or {}).items():
            if method not in _METHODS:
                continue
            body = None
            rb = _resolve(spec, op.get("requestBody") or {})
            content = (rb.get("content") or {})
            for ct in ("application/json", "*/*"):
                if ct in content:
                    body = _sample(spec, content[ct].get("schema") or {})
                    break
            out.append({"method": method, "path": path, "body": body,
                        "auth": bool(op.get("security", spec.get("security")))})
    return out


# ── crAPI auth ────────────────────────────────────────────────────────────────

def authenticate(base: str) -> tuple[str | None, list[str]]:
    """Sign up a fresh user and log in. Returns (token, log)."""
    log: list[str] = []
    tag = "".join(random.choices(string.ascii_lowercase + string.digits, k=8))
    email = f"vr{tag}@example.com"
    pw = "Vr!probe123"
    number = "9" + "".join(random.choices(string.digits, k=9))

    code, raw = _http("POST", f"{base}/identity/api/auth/signup",
                      {"name": f"vr{tag}", "email": email, "number": number,
                       "password": pw})
    log.append(f"signup -> {code}")

    code, raw = _http("POST", f"{base}/identity/api/auth/login",
                      {"email": email, "password": pw})
    log.append(f"login -> {code}")
    token = None
    if code == 200:
        try:
            token = json.loads(raw).get("token")
        except Exception:
            pass
    if not token:
        log.append(f"login body: {raw[:200]!r}")
    return token, log


# ── main flow ─────────────────────────────────────────────────────────────────

async def run(spec_path: str, base: str, compose: str, settle: float,
              boot_timeout: float, ecosystems: tuple[str, ...]) -> dict:
    spec = json.load(open(spec_path))
    ops = operations(spec)

    # Attach BEFORE anything starts: startup is when interpreters and JVMs load
    # the bulk of their dependency graph, and an openat fires once per file.
    client = ObserverClient(BIN)
    ready = await client.start([], duration=1800)
    collector = asyncio.create_task(client.collect())
    print(f"[inv] observer ready: {ready.get('progs')}", flush=True)
    await asyncio.sleep(1.0)

    loop = asyncio.get_event_loop()
    results: dict = {}
    try:
        print("[inv] docker compose up ...", flush=True)
        await loop.run_in_executor(
            None, lambda: _run("docker", "compose", "-f", compose, "up", "-d"))

        # Wait for the gateway to answer at all.
        t0 = time.time()
        healthy = False
        while time.time() - t0 < boot_timeout:
            code, _ = await loop.run_in_executor(
                None, _http, "GET", f"{base}/identity/api/auth/login")
            if code:                       # any HTTP response means it is up
                healthy = True
                break
            await asyncio.sleep(2.0)
        boot_s = round(time.time() - t0, 1)
        print(f"[inv] gateway responding={healthy} after {boot_s}s", flush=True)

        # Readiness must be "auth actually works", not "the gateway answered".
        # nginx is up long before the Spring Boot identity service behind it, and
        # it answers 404 meanwhile — authenticating then yields no token, every
        # subsequent request 401s, and the inventory silently measures nothing
        # but the auth filter. (Observed: 4 x 2xx and no token, versus 23 x 2xx
        # once this retry loop was added.)
        token, auth_log = None, []
        t_auth = time.time()
        while time.time() - t_auth < boot_timeout:
            token, auth_log = await loop.run_in_executor(None, authenticate, base)
            if token:
                break
            await asyncio.sleep(5.0)
        for line in auth_log:
            print(f"[auth] {line}", flush=True)
        print(f"[auth] token={'yes' if token else 'NO'} "
              f"after {round(time.time() - t_auth, 1)}s", flush=True)
        if not token:
            print("[auth] WARNING: no token — results measure the auth filter, "
                  "not the application", flush=True)

        # Drive every operation, authenticated where the spec says so.
        ctx = {"postId": 1, "vehicleId": 1, "order_id": 1, "video_id": 1}
        codes: dict[str, int] = {}
        for op in ops:
            url = base + _fill_path(op["path"], ctx)
            code, _ = await loop.run_in_executor(
                None, _http, op["method"], url, op["body"],
                token if op["auth"] else None)
            codes[f"{op['method'].upper()} {op['path']}"] = code
        ok = sum(1 for c in codes.values() if 200 <= c < 300)
        print(f"[inv] drove {len(codes)} operations: {ok} 2xx, "
              f"{sum(1 for c in codes.values() if c in (401, 403))} auth-rejected, "
              f"{sum(1 for c in codes.values() if c == 0)} unreachable", flush=True)
        await asyncio.sleep(settle)

        # Snapshot each service while the stack is still up.
        names = _run("docker", "compose", "-f", compose, "ps",
                     "--format", "{{.Name}}").splitlines()
        targets = {}
        for n in [x.strip() for x in names if x.strip()]:
            try:
                rt = DockerTargetResolver().resolve(n)
                targets[n] = (rt.cgroup_id, f"/proc/{rt.init_pid}/root")
            except Exception as exc:
                print(f"[inv] skip {n}: {exc}", flush=True)
        print(f"[inv] resolved {len(targets)} containers", flush=True)

        indexes = {}
        for n, (_cg, root) in targets.items():
            t = time.time()
            idx = build_index(root, ecosystems=ecosystems)
            indexes[n] = idx
            print(f"[inv]   {n:42s} {len(idx):5d} pkgs "
                  f"({round(time.time()-t,1)}s)", flush=True)
    finally:
        await client.stop()
        events = await collector

    print(f"[inv] {len(events)} events captured", flush=True)
    for n, (cg, _root) in targets.items():
        mine = [e for e in events if e.get("cgroup_id") == cg]
        idx = indexes[n]
        reach = correlate_opens(mine, idx)
        installed = {}
        for e in idx.entries():
            installed.setdefault((e.ecosystem, e.name), e.version)
        loaded = {(pr.ecosystem, pr.name): pr for pr in reach.values()}
        results[n] = {
            "events": len(mine),
            "opens": sum(1 for e in mine if e.get("type") == "open"),
            "installed": len(installed),
            "loaded": len(loaded),
            "executed": sorted(nm for (_e, nm), pr in loaded.items()
                               if pr.verdict == CONFIRMED_REACHABLE),
            "by_ecosystem": {
                eco: {
                    "installed": sum(1 for (e, _n) in installed if e == eco),
                    "loaded": sum(1 for (e, _n) in loaded if e == eco),
                }
                for eco in sorted({e for (e, _n) in installed})
            },
            "loaded_names": sorted(nm for (_e, nm) in loaded),
            "never_loaded": sorted(nm for (_e, nm) in set(installed) - set(loaded)),
        }
    return {"results": results, "codes": codes, "token": bool(token),
            "boot_seconds": boot_s, "operations": len(ops)}


async def java_pass(service: str, spec_path: str, base: str, settle: float) -> dict:
    """Second pass: Java packages, which Tier A alone can never report.

    The Java index is keyed by *class-name* prefix ("com/example/") because the
    JVM probe reports class names, never paths — so Rule R1's openat stream has
    nothing to match against and a Tier-A-only run shows 0% loaded for a JVM
    service no matter how much of it ran. Java depends entirely on Tier B.

    The probe therefore has to be live before the JVM starts, since a class is
    resolved exactly once. We restart just this service with the uprobe already
    attached. The observer runs unfiltered because a restart recreates the
    container's cgroup directory, giving it a NEW cgroup id that cannot be known
    in advance; events are filtered by cgroup id afterwards.
    """
    from agents.ebpf.observer_runner import find_libjvm

    rt = DockerTargetResolver().resolve(service)
    libjvm = find_libjvm(f"/proc/{rt.init_pid}/root")
    print(f"[java] libjvm={libjvm}", flush=True)
    if not libjvm:
        return {"error": "no libjvm found"}

    client = ObserverClient(BIN)
    ready = await client.start([], duration=900, jvm_lib=libjvm)
    progs = ready.get("progs") or []
    print(f"[java] progs={progs}", flush=True)
    if "uprobe:jvm_class_loaded" not in progs:
        await client.stop()
        return {"error": "jvm probe did not attach", "warnings": ready.get("warnings")}

    collector = asyncio.create_task(client.collect())
    loop = asyncio.get_event_loop()
    try:
        await asyncio.sleep(1.0)
        print(f"[java] restarting {service} with the probe live ...", flush=True)
        await loop.run_in_executor(None, lambda: _run("docker", "restart", service))

        # New PID and new cgroup after the restart.
        rt2 = None
        for _ in range(60):
            await asyncio.sleep(2.0)
            try:
                rt2 = DockerTargetResolver().resolve(service)
                if rt2.init_pid:
                    break
            except Exception:
                pass
        root = f"/proc/{rt2.init_pid}/root"
        print(f"[java] restarted cgroup={rt2.cgroup_id} pid={rt2.init_pid}", flush=True)

        # Give Spring Boot time to come up, then exercise the API again so that
        # request-handling classes resolve too, not just the boot graph.
        await asyncio.sleep(25.0)
        token, log = await loop.run_in_executor(None, authenticate, base)
        print(f"[java] re-auth: {log} token={'yes' if token else 'NO'}", flush=True)
        spec = json.load(open(spec_path))
        ctx = {"postId": 1, "vehicleId": 1, "order_id": 1, "video_id": 1}
        for op in operations(spec):
            if not op["path"].startswith("/identity"):
                continue
            await loop.run_in_executor(
                None, _http, op["method"], base + _fill_path(op["path"], ctx),
                op["body"], token if op["auth"] else None)
        await asyncio.sleep(settle)
        idx = build_index(root, ecosystems=("java",))
    finally:
        await client.stop()
        events = await collector

    mine = [e for e in events if e.get("cgroup_id") == rt2.cgroup_id]
    cls = [e for e in mine if e.get("type") == "java_class"]
    reach = correlate_opens(mine, idx)
    loaded = sorted({pr.name for pr in reach.values()})
    installed = sorted({e.name for e in idx.entries()})
    print(f"[java] {len(cls)} class-load events, {len(loaded)}/{len(installed)} packages",
          flush=True)
    return {
        "service": service, "libjvm": libjvm,
        "class_events": len(cls),
        "installed": len(installed), "loaded": len(loaded),
        "loaded_names": loaded,
        "never_loaded": sorted(set(installed) - set(loaded)),
        "sample_classes": sorted({e.get("filename") for e in cls})[:15],
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--spec", required=True)
    ap.add_argument("--base-url", default="http://localhost:8888")
    ap.add_argument("--compose", required=True)
    ap.add_argument("--settle", type=float, default=5.0)
    ap.add_argument("--boot-timeout", type=float, default=300.0)
    ap.add_argument("--ecosystems", default="python,node,java")
    ap.add_argument("--out", default="")
    ap.add_argument("--jvm-service", default="",
                    help="restart this service with the JVM probe live (Java needs Tier B)")
    a = ap.parse_args()

    r = asyncio.run(run(a.spec, a.base_url.rstrip("/"), a.compose, a.settle,
                        a.boot_timeout, tuple(a.ecosystems.split(","))))

    if a.jvm_service:
        print(f"\n[java] --- second pass for {a.jvm_service} ---", flush=True)
        r["java"] = asyncio.run(java_pass(a.jvm_service, a.spec,
                                          a.base_url.rstrip("/"), a.settle))

    print("\n" + "=" * 88)
    print("RUNTIME PACKAGE INVENTORY — OpenAPI-driven, authenticated")
    print("=" * 88)
    print(f"  operations driven : {r['operations']}   authenticated: {r['token']}")
    by = {}
    for k, c in r["codes"].items():
        by.setdefault(c // 100 if c else 0, []).append(k)
    for group in sorted(by):
        label = {0: "no response", 2: "2xx", 4: "4xx", 5: "5xx", 3: "3xx"}.get(group, group)
        print(f"    {str(label):12s} {len(by[group])}")
    print("-" * 88)
    print(f"  {'container':44s} {'pkgs':>6s} {'loaded':>7s} {'%':>6s}  ecosystems")
    for n, d in sorted(r["results"].items()):
        pct = (100.0 * d["loaded"] / d["installed"]) if d["installed"] else 0.0
        eco = ",".join(f"{k}:{v['loaded']}/{v['installed']}"
                       for k, v in d["by_ecosystem"].items()) or "-"
        print(f"  {n:44s} {d['installed']:6d} {d['loaded']:7d} {pct:5.1f}%  {eco}")
    print("=" * 88)
    for n, d in sorted(r["results"].items()):
        if not d["loaded"]:
            continue
        print(f"\n### {n}  ({d['loaded']}/{d['installed']} loaded, {d['opens']} opens)")
        print("loaded: " + ", ".join(d["loaded_names"][:45]) +
              (" ..." if d["loaded"] > 45 else ""))
        if d["executed"]:
            print("executed (R2/R5/R6): " + ", ".join(d["executed"][:25]))

    j = r.get("java") or {}
    if j and not j.get("error"):
        pct = 100.0 * j["loaded"] / j["installed"] if j["installed"] else 0
        print(f"\n### {j['service']} (JAVA, Tier B / Rule R6)")
        print(f"  {j['class_events']} class-load events -> "
              f"{j['loaded']}/{j['installed']} packages ({pct:.1f}%)")
        print("  loaded: " + ", ".join(j["loaded_names"][:40]) +
              (" ..." if j["loaded"] > 40 else ""))
        print("  never loaded: " + ", ".join(j["never_loaded"][:25]))
    elif j:
        print(f"\n### java pass failed: {j}")

    if a.out:
        with open(a.out, "w") as fh:
            json.dump(r, fh, indent=2)
        print(f"\n[inv] wrote {a.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
