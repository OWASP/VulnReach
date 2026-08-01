"""Observer orchestration — attach to a running container and produce findings.

This is the single entrypoint the DynamicReachabilityAgent calls for the eBPF
"observer" engine. It ties the pieces together:

    resolve container → cgroup id        (target_resolver)
    build Package-Index from /proc root  (package_index)
    run the observer over a traffic window (observer_client)
    correlate opens → package reach      (reachability, Rule R1)
    map to canonical ReachabilityFinding (verdict_integration, D5/D6)

Kept separate from the agent so the whole path is unit-testable against a real
container without standing up a full scan (OpenAPI/schemathesis/etc.).
"""
from __future__ import annotations

import asyncio
import os
import platform
from typing import Any, Awaitable, Callable, Optional

from core.models import ReachabilityFinding
from agents.ebpf.target_resolver import DockerTargetResolver
from agents.ebpf.observer_client import ObserverClient, _DEFAULT_BIN
from agents.ebpf.package_index import build_index
from agents.ebpf.reachability import correlate_opens
from agents.ebpf.verdict_integration import (
    to_reachability_findings,
    taint_modules as _taint_modules,
)


def observer_available(binary_path: str = _DEFAULT_BIN) -> tuple[bool, str]:
    """Return (available, reason). Bypasses the legacy bpftrace/LinuxKit gate.

    The observer only needs a Linux host, the built binary, and kernel BTF —
    it works on modern LinuxKit (Docker Desktop 6.x) where the old bpftrace
    check in _ebpf_available() false-negatives.
    """
    if platform.system() != "Linux":
        return False, "not_linux"
    if not os.path.exists(binary_path):
        return False, f"observer_binary_missing:{binary_path}"
    if not os.path.exists("/sys/kernel/btf/vmlinux"):
        return False, "btf_unavailable"
    return True, "ok"


async def run_observer_reachability(
    container_ref: str,
    vulnerabilities: list[dict],
    *,
    import_map: Optional[dict[str, str]] = None,
    taint_flows: Optional[list[dict]] = None,
    ecosystems: tuple[str, ...] = ("python", "node"),
    duration: int = 10,
    binary_path: Optional[str] = None,
    traffic: Optional[Callable[[], Awaitable[None]]] = None,
) -> tuple[list[ReachabilityFinding], dict[str, Any]]:
    """Observe *container_ref* over a window and return (findings, metadata).

    Args:
        container_ref:   Docker container id/name (already running).
        vulnerabilities: SCA vuln dicts (need ``package`` + ``cve_id``).
        import_map:      optional dist→module map (from MetadataAgent).
        ecosystems:      Package-Index ecosystems to enumerate.
        duration:        hard cap (seconds) on the observation window; the run
                         normally ends when ``traffic`` returns and we stop the
                         observer, whichever comes first.
        binary_path:     observer binary (defaults to VULNREACH_OBSERVER_BIN / bundled).
        traffic:         optional async callback to drive load during the window
                         (e.g. schemathesis). If None, we observe for ``duration`` seconds.
    """
    resolver = DockerTargetResolver()
    target = resolver.resolve(container_ref)

    # Attach the observer FIRST, then build the Package-Index while already
    # recording — every millisecond before attach is a startup import we miss.
    client = ObserverClient(binary_path or _DEFAULT_BIN)
    await client.start([target.cgroup_id], duration=duration)

    # Read the event stream CONCURRENTLY with driving traffic — otherwise a busy
    # container fills the observer's stdout pipe and stalls it while we wait.
    collector = asyncio.create_task(client.collect())
    try:
        index = build_index(f"/proc/{target.init_pid}/root", ecosystems=ecosystems)
        if traffic is not None:
            await traffic()
        else:
            await asyncio.sleep(duration)
    finally:
        await client.stop()  # SIGTERM → observer flushes summary → collector returns
    events = await collector

    reach = correlate_opens(events, index)
    findings = to_reachability_findings(reach, vulnerabilities, import_map, taint_flows)

    metadata = {
        "engine": "observer",
        "target_container": target.container_id[:12],
        "target_cgroup_id": target.cgroup_id,
        "index_entries": len(index),
        "open_events": sum(1 for e in events if e.get("type") == "open"),
        "packages_reached": len(reach),
        "reached": sorted({pr.name for pr in reach.values()}),
        "native_exec": sorted({pr.name for pr in reach.values() if pr.rule == "R2"}),
        "taint_modules": sorted(_taint_modules(taint_flows)),
    }
    return findings, metadata
