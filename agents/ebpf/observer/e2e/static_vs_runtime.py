#!/usr/bin/env python3
"""Tier 3 — score STATIC reachability against RUNTIME (eBPF) ground truth.

Static reachability predicts which dependencies are reachable without running the
app. The eBPF observer records which packages actually loaded/executed. Until now
every "static recall went from 33% to 100%" claim rested on one hand-built app;
this harness makes the claim *measurable* on real applications, and — more
importantly — surfaces static FALSE NEGATIVES (a package that ran but static
called unreachable), the PyYAML-class error that tells a user to ignore a live
CVE.

Ground truth is the observer's runtime inventory (`inventory.inventory`), which
was itself cross-checked 335/335 against Node's require.cache on Juice Shop — so
it is a trustworthy oracle, not a second guess.

The comparison is deliberately scoped to the app's **declared dependencies that
are actually installed** in the image. That is the fair universe: static scans
app source, so transitive packages the app never imports directly are neither a
static win nor a static failure, and scoring them would just measure the
static/dynamic gap rather than static quality.

Alignment is on the *import* name (PyYAML→yaml, Pillow→PIL) via import_resolver,
because static speaks distribution names and the runtime index speaks import
names.

Usage:
  # static half only (no Docker) — for development / the source side
  python3 static_vs_runtime.py --app labs/python_vuln_app --static-only

  # full run (needs the privileged observer container + Docker)
  python3 static_vs_runtime.py --app labs/python_vuln_app \
      --image python_vuln_app:plain --port 3000 --ecosystem python
"""
from __future__ import annotations

import argparse
import asyncio
import io
import json
import os
import re
import subprocess
import sys
from contextlib import redirect_stdout
from pathlib import Path

sys.path.insert(0, "/repo")
sys.path.insert(0, str(Path(__file__).resolve().parents[4]))

from agents.utils.import_resolver import resolve_import_name  # noqa: E402
from agents.reachability.taint_match import sink_modules  # noqa: E402

_NOT_REACHABLE = "NOT_OBSERVED"


def _norm_import(dist: str, import_map: dict | None = None) -> str:
    try:
        return resolve_import_name(dist, import_map or {}).strip().lower()
    except Exception:
        return dist.strip().lower()


def declared_dependencies(app: Path) -> list[str]:
    """Distribution names from requirements.txt (the fair universe)."""
    reqs = app / "requirements.txt"
    deps: list[str] = []
    if reqs.exists():
        for line in reqs.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith(("#", "-")):
                continue
            m = re.match(r"^([A-Za-z0-9_.\-]+)", line)
            if m:
                deps.append(m.group(1))
    return deps


def run_tainter(app: Path) -> list[dict]:
    """Real tainter flows for the app (best-effort; empty if tainter absent)."""
    try:
        out = subprocess.run(
            ["tainter", "scan", str(app), "--format", "json"],
            capture_output=True, text=True, timeout=120)
        return json.loads(out.stdout).get("flows", []) if out.stdout else []
    except Exception:
        return []


def static_python(app: Path) -> dict[str, dict]:
    """Run the REAL Python static reachability path over the declared deps.

    Returns {import_name: {dist, verdict, import_detected}}.
    """
    from agents.reachability.python_reachability_analyzer import PythonReachabilityAnalyzer
    from agents.agent_python_reachability import PythonReachabilityAgent

    deps = declared_dependencies(app)
    vulns = [{"package_name": d, "cve_ids": [f"CVE-{d}"]} for d in deps]

    buf = io.StringIO()
    with redirect_stdout(buf):
        analyzer = PythonReachabilityAnalyzer(str(app))
        analyses = analyzer.analyze_vulnerability_reachability(vulns)
        tainted = sink_modules(run_tainter(app))
        mapped = PythonReachabilityAgent()._map_findings(
            analyses, [{"package_name": d, "cve_ids": [f"CVE-{d}"]} for d in deps],
            tainted, {})

    out: dict[str, dict] = {}
    for f in mapped:
        imp = _norm_import(f["package"])
        # keep the strongest verdict if a name collides
        prev = out.get(imp)
        if prev is None or _verdict_rank(f["verdict"]) > _verdict_rank(prev["verdict"]):
            out[imp] = {"dist": f["package"], "verdict": f["verdict"],
                        "import_detected": f["import_detected"]}
    return out


_VERDICT_ORDER = {"CONFIRMED": 3, "LIKELY": 2, "POSSIBLE": 1, "NOT_OBSERVED": 0}


def _verdict_rank(v: str) -> int:
    return _VERDICT_ORDER.get(v, 0)


def compare(static: dict[str, dict], loaded: set[str], executed: set[str],
            installed: set[str], declared_imports: set[str]) -> dict:
    """Confusion matrix of static-reachable vs runtime-loaded over the fair universe."""
    # Universe: declared deps that are actually installed in the image. A declared
    # dep absent from the image can neither load nor be a fair static failure.
    universe = sorted(declared_imports & installed) if installed else sorted(declared_imports)

    rows = []
    tp = fp = fn = tn = 0
    for imp in universe:
        st = static.get(imp)
        static_reachable = bool(st and st["verdict"] != _NOT_REACHABLE)
        ran = imp in loaded
        if static_reachable and ran:
            tp += 1; cell = "TP"
        elif static_reachable and not ran:
            fp += 1; cell = "FP"
        elif not static_reachable and ran:
            fn += 1; cell = "FN"   # DANGER: ran but static said unreachable
        else:
            tn += 1; cell = "TN"
        rows.append({"import": imp, "verdict": (st or {}).get("verdict", "—"),
                     "ran": ran, "executed": imp in executed, "cell": cell,
                     "import_detected": bool(st and st["import_detected"])})

    # The FN split that matters: a false negative where static DID see a direct
    # import but still scored NOT_OBSERVED is a real detection bug; one where
    # static saw no direct import is an indirect/transitive load (a dep pulled in
    # by another package), which source-scanning static cannot see by design.
    # This separates "my fixes regressed" from "the known transitive-reach gap".
    fn_rows = [r for r in rows if r["cell"] == "FN"]
    direct_misses = [r["import"] for r in fn_rows if r["import_detected"]]
    indirect_misses = [r["import"] for r in fn_rows if not r["import_detected"]]

    precision = tp / (tp + fp) if (tp + fp) else None
    recall = tp / (tp + fn) if (tp + fn) else None
    # Of packages that provably executed (R2/R5/R6), how many did static CONFIRM?
    exec_universe = sorted(executed & set(universe))
    exec_confirmed = sum(1 for i in exec_universe
                         if (static.get(i) or {}).get("verdict") == "CONFIRMED")
    return {
        "universe_size": len(universe),
        "tp": tp, "fp": fp, "fn": fn, "tn": tn,
        "precision": precision, "recall": recall,
        "false_negatives": sorted(r["import"] for r in rows if r["cell"] == "FN"),
        "false_positives": sorted(r["import"] for r in rows if r["cell"] == "FP"),
        "fn_direct_detection_bugs": sorted(direct_misses),
        "fn_indirect_transitive": sorted(indirect_misses),
        "executed_count": len(exec_universe),
        "executed_confirmed_by_static": exec_confirmed,
        "rows": rows,
    }


def _print_report(app: str, image: str, cmp: dict, loaded_n: int) -> None:
    print("\n" + "=" * 78)
    print(f"STATIC vs RUNTIME (eBPF ground truth) — {app}")
    if image:
        print(f"image: {image}   runtime-loaded packages: {loaded_n}")
    print("=" * 78)
    p, r = cmp["precision"], cmp["recall"]
    print(f"  universe (declared ∩ installed): {cmp['universe_size']}")
    print(f"  confusion:  TP={cmp['tp']}  FP={cmp['fp']}  FN={cmp['fn']}  TN={cmp['tn']}")
    print(f"  precision:  {p:.2f}" if p is not None else "  precision:  n/a")
    print(f"  recall:     {r:.2f}" if r is not None else "  recall:     n/a")
    print(f"  executed (R2/R5/R6) confirmed by static: "
          f"{cmp['executed_confirmed_by_static']}/{cmp['executed_count']}")
    print("-" * 78)
    if cmp["false_negatives"]:
        print(f"  ⚠  FALSE NEGATIVES (ran, but static said unreachable): "
              f"{cmp['false_negatives']}")
        # The split that says whether this is a bug or the known gap:
        bugs = cmp["fn_direct_detection_bugs"]
        if bugs:
            print(f"       ✗ direct-detection BUGS (imported in source, still missed): {bugs}")
        else:
            print("       ✓ direct-detection bugs: NONE — every miss is indirect")
        print(f"       · indirect/transitive (not imported in app source, pulled in "
              f"by a dep): {cmp['fn_indirect_transitive']}")
    else:
        print("  ✓  no false negatives — static flagged every package that ran")
    if cmp["false_positives"]:
        print(f"  ·  false positives (static reachable, never ran): "
              f"{cmp['false_positives']}")
    print("-" * 78)
    print(f"  {'import':22s} {'verdict':12s} {'ran':4s} {'exec':4s} cell")
    for row in sorted(cmp["rows"], key=lambda x: (x["cell"], x["import"])):
        print(f"  {row['import']:22s} {row['verdict']:12s} "
              f"{str(row['ran']):4s} {str(row['executed']):4s} {row['cell']}")
    print("=" * 78)


async def _runtime_side(image: str, port: int, ecosystem: str, paths: list[str]) -> dict:
    from inventory import inventory  # observer/e2e/inventory.py
    return await inventory(image, port, ecosystem, paths,
                           boot_timeout=180.0, settle=3.0)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--app", required=True, help="path to the app source (for static)")
    ap.add_argument("--image", default="", help="running-target image (for runtime)")
    ap.add_argument("--port", type=int, default=3000)
    ap.add_argument("--ecosystem", default="python")
    ap.add_argument("--path", action="append", default=[])
    ap.add_argument("--static-only", action="store_true",
                    help="run only the static half (no Docker)")
    ap.add_argument("--runtime-json", default="",
                    help="load the runtime oracle from an inventory.py --out file "
                         "instead of driving Docker here (keeps the static side, "
                         "which needs tainter, on the host)")
    ap.add_argument("--out", default="")
    a = ap.parse_args()

    app = Path(a.app).resolve()
    if a.ecosystem != "python":
        print(f"ecosystem '{a.ecosystem}' static side not wired yet (python only)")
        return 2

    print(f"[static] analyzing {app} ...", flush=True)
    static = static_python(app)
    reachable = {i for i, v in static.items() if v["verdict"] != _NOT_REACHABLE}
    print(f"[static] {len(static)} declared deps analyzed, "
          f"{len(reachable)} predicted reachable", flush=True)

    if a.static_only:
        print("\n[static-only] verdicts:")
        for imp in sorted(static):
            v = static[imp]
            print(f"  {imp:22s} {v['verdict']:12s} (dist={v['dist']})")
        return 0

    if a.runtime_json:
        rt = json.load(open(a.runtime_json))
    else:
        paths = a.path or ["/", "/yaml-test", "/request-test", "/render-test"]
        rt = asyncio.run(_runtime_side(a.image, a.port, a.ecosystem, paths))
    loaded = set(rt.get("loaded", []))
    executed = set(rt.get("executed", []))
    installed = loaded | set(rt.get("never_loaded", []))
    declared_imports = {_norm_import(d) for d in declared_dependencies(app)}

    cmp = compare(static, loaded, executed, installed, declared_imports)
    _print_report(str(app), a.image, cmp, len(loaded))

    if a.out:
        with open(a.out, "w") as fh:
            json.dump({"app": str(app), "image": a.image, "static": static,
                       "runtime": {"loaded": sorted(loaded), "executed": sorted(executed)},
                       "comparison": cmp}, fh, indent=2)
        print(f"[out] wrote {a.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
