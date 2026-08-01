"""P5 — map eBPF observer reachability onto the canonical verdict pipeline.

Converts the language-agnostic PackageReach output (Rule R1, from
reachability.correlate_opens) into ``ReachabilityFinding`` objects using the
product's canonical Verdict vocabulary (D6: reuse CONFIRMED/LIKELY/POSSIBLE/
NOT_OBSERVED — no parallel enum).

Verdict mapping (D5):
  R2 native code mapped PROT_EXEC (compiled code running) → CONFIRMED (0.8)
  R1 openat load (package files loaded, no call proof)    → LIKELY  (import-hit)
  package never observed                                  → NOT_OBSERVED

This mirrors how agents/utils/coverage_correlator treats an import-only hit
(LIKELY, 0.65, import_time_hit=True), so eBPF findings are indistinguishable
downstream from coverage-derived import hits. CONFIRMED is reserved for
function-level evidence (R2 native / Tier B) and static-taint cross-ref (R4),
which land in later phases.
"""
from __future__ import annotations

from typing import Any, Optional

from core.models import ReachabilityFinding
from agents.utils.import_resolver import resolve_import_name as _resolve_import_name
from agents.ebpf.package_index import _norm
from agents.ebpf.reachability import PackageReach, CONFIRMED_REACHABLE

# Confidence values kept identical to coverage_correlator for consistency.
_CONF_NATIVE_EXEC = 0.8   # R2: native code mapped PROT_EXEC (redesign §6)
_CONF_IMPORT_HIT = 0.65
_CONF_NOT_OBSERVED = 0.1


def _cve_list(vuln: dict) -> list[Optional[str]]:
    cves = vuln.get("cve_id", [])
    if isinstance(cves, str):
        cves = [cves]
    return list(cves) if cves else [None]


def to_reachability_findings(
    reach: dict[str, PackageReach],
    vulnerabilities: list[dict],
    import_map: Optional[dict[str, str]] = None,
) -> list[ReachabilityFinding]:
    """Produce canonical ReachabilityFindings from eBPF PackageReach results.

    Args:
        reach:           output of reachability.correlate_opens (keyed pkg → PackageReach)
        vulnerabilities: SCA vuln dicts (need at least ``package`` and ``cve_id``)
        import_map:      optional dist→module map (from MetadataAgent) to bridge
                         PyPI dist names to the import names the observer sees
    """
    # Index reached packages by normalized name for dist/import-name matching.
    by_name: dict[str, PackageReach] = {}
    for pr in reach.values():
        by_name[_norm(pr.name)] = pr

    findings: list[ReachabilityFinding] = []
    for vuln in vulnerabilities:
        pypi = (vuln.get("package") or "").strip()
        if not pypi:
            continue
        import_name = _resolve_import_name(pypi, import_map)
        pr = by_name.get(_norm(import_name)) or by_name.get(_norm(pypi))

        for cve in _cve_list(vuln):
            if pr is not None:
                # R2 (native code mapped executable) is proof the package's
                # compiled code ran → CONFIRMED. R1 is load-only → LIKELY.
                native_exec = pr.verdict == CONFIRMED_REACHABLE
                findings.append(ReachabilityFinding(
                    cve_id=cve,
                    package=vuln.get("package"),
                    import_detected=True,
                    call_chain_exists=native_exec,
                    sink_reachable=False,
                    import_time_hit=not native_exec,
                    verdict="CONFIRMED" if native_exec else "LIKELY",
                    confidence=_CONF_NATIVE_EXEC if native_exec else _CONF_IMPORT_HIT,
                    evidence_type="dynamic",
                    files=list(pr.evidence)[:5],
                ))
            else:
                findings.append(ReachabilityFinding(
                    cve_id=cve,
                    package=vuln.get("package"),
                    import_detected=False,
                    call_chain_exists=False,
                    sink_reachable=False,
                    import_time_hit=False,
                    verdict="NOT_OBSERVED",
                    confidence=_CONF_NOT_OBSERVED,
                    evidence_type="dynamic",
                    files=[],
                ))
    return findings
