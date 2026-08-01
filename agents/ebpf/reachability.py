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

from dataclasses import dataclass, field

from agents.ebpf.package_index import PackageIndex

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
    """Rule R1: an ``open`` under a package prefix ⇒ package loaded.

    Returns {``<ecosystem>:<name>`` → PackageReach} for every package that had at
    least one matched file-open. Non-open events are ignored.
    """
    reached: dict[str, PackageReach] = {}
    for ev in events:
        if ev.get("type") != "open":
            continue
        path = ev.get("filename") or ""
        entry = index.match(path)
        if entry is None:
            continue
        key = f"{entry.ecosystem}:{entry.name}"
        pr = reached.get(key)
        if pr is None:
            pr = PackageReach(
                name=entry.name, ecosystem=entry.ecosystem, version=entry.version,
                verdict=POTENTIALLY_REACHABLE, rule="R1",
            )
            reached[key] = pr
        pr.hit_count += 1
        if len(pr.evidence) < max_evidence:
            pr.evidence.append(path)
    return reached
