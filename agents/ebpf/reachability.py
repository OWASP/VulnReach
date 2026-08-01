"""Reachability correlation over observer events (deterministic, rule-based).

Maps raw syscall events to package-level reachability verdicts. This is the
deterministic-first layer (no LLM): Rule R1 attributes file-open events to
packages via the PackageIndex.

These are eBPF-internal *reachability tiers* describing the strength of the
runtime evidence. They are NOT the product's verdict enum (D6): the boundary in
``verdict_integration.to_reachability_findings`` translates them to the canonical
``Verdict`` (CONFIRMED/LIKELY/POSSIBLE/NOT_OBSERVED) that risk scoring, policy,
storage and the dashboard consume — R1 load-level ⇒ LIKELY (D5).

  CONFIRMED_REACHABLE    package code demonstrably executed (R2 native / Tier B / R4)
  POTENTIALLY_REACHABLE  package files loaded, no proof a function ran (R1)
  NOT_OBSERVED           package present but never seen during the window

P2 implements R1 only → POTENTIALLY_REACHABLE. R2/R3/R4 land in P4/P6/P7.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field

from agents.ebpf.package_index import PackageIndex

# Native extension suffixes: a mapped-executable file with one of these under a
# package prefix means that package's compiled code is running.
_NATIVE_SUFFIXES = (".so", ".pyd", ".node", ".dylib")

CONFIRMED_REACHABLE = "CONFIRMED_REACHABLE"
POTENTIALLY_REACHABLE = "POTENTIALLY_REACHABLE"
NOT_OBSERVED = "NOT_OBSERVED"


@dataclass
class PackageReach:
    name: str
    ecosystem: str
    version: str | None
    verdict: str
    rule: str
    hit_count: int = 0
    evidence: list[str] = field(default_factory=list)


def correlate_opens(events: list[dict], index: PackageIndex,
                    max_evidence: int = 5) -> dict[str, PackageReach]:
    """Correlate observer events to per-package reachability.

    Rule R1 — an ``open`` under a package prefix ⇒ package loaded
              ⇒ POTENTIALLY_REACHABLE.
    Rule R2 — a native extension of that package was mapped PROT_EXEC
              (``mmap_exec``) ⇒ its compiled code is executing
              ⇒ CONFIRMED_REACHABLE (upgrades R1).

    The kernel gives only the *basename* for mmap_exec (a full path walk needs an
    unbounded dentry loop), so we join it to the full path already seen in the
    openat stream to attribute it to a package.

    Returns {``<ecosystem>:<name>`` → PackageReach}.
    """
    reached: dict[str, PackageReach] = {}
    # basename → full path, for native libs observed in the open stream
    native_paths: dict[str, str] = {}

    def _touch(entry, path: str, verdict: str, rule: str) -> PackageReach:
        key = f"{entry.ecosystem}:{entry.name}"
        pr = reached.get(key)
        if pr is None:
            pr = PackageReach(
                name=entry.name, ecosystem=entry.ecosystem, version=entry.version,
                verdict=verdict, rule=rule,
            )
            reached[key] = pr
        if len(pr.evidence) < max_evidence and path not in pr.evidence:
            pr.evidence.append(path)
        return pr

    # Pass 1 — R1 over file opens; remember native lib paths for the R2 join.
    for ev in events:
        if ev.get("type") != "open":
            continue
        path = ev.get("filename") or ""
        if path.endswith(_NATIVE_SUFFIXES):
            native_paths.setdefault(os.path.basename(path), path)
        entry = index.match(path)
        if entry is None:
            continue
        pr = _touch(entry, path, POTENTIALLY_REACHABLE, "R1")
        pr.hit_count += 1

    # Pass 2 — R2: native code mapped executable upgrades the verdict.
    for ev in events:
        if ev.get("type") != "mmap_exec":
            continue
        base = os.path.basename(ev.get("filename") or "")
        if not base.endswith(_NATIVE_SUFFIXES):
            continue
        path = native_paths.get(base)
        if path is None:
            continue  # never saw it opened → cannot attribute to a package
        entry = index.match(path)
        if entry is None:
            continue
        pr = _touch(entry, path, CONFIRMED_REACHABLE, "R2")
        pr.verdict = CONFIRMED_REACHABLE  # upgrade if it was R1
        pr.rule = "R2"
        pr.hit_count += 1

    return reached
