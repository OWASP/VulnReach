"""P0 acceptance test for the eBPF observer.

Isolation test (the P0 pass/fail): start two containers, run the observer
filtered to one, exec in both, assert only the target's execs are captured.

Gated: requires Linux + root (CAP_BPF/CAP_PERFMON) + docker + the built observer
binary + cgroup v2. Designed to run inside a privileged --pid=host --cgroupns=host
container (the node-agent context). Skipped everywhere else.
"""
from __future__ import annotations

import asyncio
import os
import platform
import shutil
import subprocess
import uuid

import pytest

from agents.ebpf.target_resolver import DockerTargetResolver
from agents.ebpf.observer_client import ObserverClient, _DEFAULT_BIN
from agents.ebpf.package_index import build_index
from agents.ebpf.reachability import correlate_opens, POTENTIALLY_REACHABLE
from agents.ebpf.verdict_integration import to_reachability_findings
from agents.ebpf.observer_runner import run_observer_reachability, observer_available

_LINUX = platform.system() == "Linux"
_ROOT = hasattr(os, "geteuid") and os.geteuid() == 0
_DOCKER = shutil.which("docker") is not None
_BIN = os.environ.get("VULNREACH_OBSERVER_BIN", _DEFAULT_BIN)
_HAVE_BIN = os.path.exists(_BIN)

pytestmark = pytest.mark.skipif(
    not (_LINUX and _ROOT and _DOCKER and _HAVE_BIN),
    reason="needs Linux+root+docker+built observer binary (run in the node-agent container)",
)


def _run(*args: str) -> str:
    return subprocess.run(list(args), capture_output=True, text=True, check=True).stdout.strip()


@pytest.fixture()
def two_containers():
    tag = uuid.uuid4().hex[:8]
    names = [f"vr_p0_{tag}_t", f"vr_p0_{tag}_c"]
    for n in names:
        _run("docker", "run", "-d", "--name", n, "alpine", "sleep", "300")
    try:
        yield names
    finally:
        for n in names:
            subprocess.run(["docker", "rm", "-f", n], capture_output=True)


def test_cgroup_isolation(two_containers):
    target, control = two_containers
    resolver = DockerTargetResolver()
    rt = resolver.resolve(target)
    rc = resolver.resolve(control)
    assert rt.cgroup_id != rc.cgroup_id
    # cross-check the derivation against the container's own view (F2 invariant)
    inside = int(_run("docker", "exec", target, "stat", "-c", "%i", "/sys/fs/cgroup"))
    assert rt.cgroup_id == inside

    async def drive():
        client = ObserverClient(_BIN)
        ready = await client.start([rt.cgroup_id], duration=5)
        assert ready["cgroup_ids"] == [rt.cgroup_id]
        try:
            await asyncio.sleep(1.0)  # let probe settle
            for name in (target, control):
                _run("docker", "exec", name, "/bin/true")
                _run("docker", "exec", name, "/bin/date")
            return await client.collect()
        finally:
            await client.stop()  # close the subprocess transport within the loop

    events = asyncio.run(drive())

    target_events = [e for e in events if e["cgroup_id"] == rt.cgroup_id]
    control_events = [e for e in events if e["cgroup_id"] == rc.cgroup_id]

    assert target_events, "expected exec events from the target container"
    assert not control_events, f"control cgroup leaked events: {control_events}"
    comms = {e["comm"] for e in target_events}
    assert comms & {"true", "date"}, f"unexpected comms captured: {comms}"


def test_openat_capture(two_containers):
    """P1: openat file-load events are captured and cgroup-isolated."""
    target, control = two_containers
    resolver = DockerTargetResolver()
    rt = resolver.resolve(target)
    rc = resolver.resolve(control)

    tag = uuid.uuid4().hex[:8]
    tpath = f"/tmp/vr_open_t_{tag}"
    cpath = f"/tmp/vr_open_c_{tag}"

    async def drive():
        client = ObserverClient(_BIN)
        await client.start([rt.cgroup_id], duration=5)
        try:
            await asyncio.sleep(1.0)
            _run("docker", "exec", target, "sh", "-c", f"echo hi > {tpath}; cat {tpath}")
            _run("docker", "exec", control, "sh", "-c", f"echo hi > {cpath}; cat {cpath}")
            return await client.collect()
        finally:
            await client.stop()

    events = asyncio.run(drive())
    opens = [e for e in events if e["type"] == "open"]

    assert any(e["filename"] == tpath and e["cgroup_id"] == rt.cgroup_id for e in opens), \
        f"target open {tpath} not captured"
    assert not any(e["cgroup_id"] == rc.cgroup_id for e in events), "control cgroup leaked events"
    assert not any(cpath in e["filename"] for e in opens), "control probe path leaked"


_P2_IMAGE = os.environ.get("VULNREACH_P2_FIXTURE", "vulnreach-p2-fixture")


@pytest.fixture()
def py_app_container():
    name = f"vr_p2_{uuid.uuid4().hex[:8]}"
    _run("docker", "run", "-d", "--name", name, _P2_IMAGE, "sleep", "600")
    try:
        yield name
    finally:
        subprocess.run(["docker", "rm", "-f", name], capture_output=True)


def test_package_reach_r1(py_app_container):
    """P2 MVP: openat under a package prefix ⇒ POTENTIALLY_REACHABLE (Rule R1).

    Import only `requests`; assert it (and its deps) are reached, while the
    installed-but-never-imported `tabulate` is not.
    """
    resolver = DockerTargetResolver()
    rt = resolver.resolve(py_app_container)

    index = build_index(f"/proc/{rt.init_pid}/root", ecosystems=("python",))
    names = {e.name for e in index.entries()}
    assert {"requests", "tabulate"} <= names, f"index missing fixtures: {sorted(names)[:20]}"

    async def drive():
        client = ObserverClient(_BIN)
        await client.start([rt.cgroup_id], duration=6)
        try:
            await asyncio.sleep(1.0)
            _run("docker", "exec", py_app_container, "python", "-c", "import requests")
            return await client.collect()
        finally:
            await client.stop()

    events = asyncio.run(drive())
    reach = correlate_opens(events, index)
    reached = {pr.name for pr in reach.values()}

    assert "requests" in reached, f"requests not reached; got {sorted(reached)}"
    assert reach["python:requests"].verdict == POTENTIALLY_REACHABLE
    assert reach["python:requests"].hit_count > 0
    assert "tabulate" not in reached, "tabulate was never imported but shows reached"


def test_verdict_integration_r1(py_app_container):
    """P5: PackageReach → canonical ReachabilityFinding (D5/D6).

    A reached package maps to LIKELY (import-hit); an unreached vulnerable
    package maps to NOT_OBSERVED. Verdicts use the canonical enum the rest of
    the pipeline (risk scoring, policy, storage) already consumes.
    """
    resolver = DockerTargetResolver()
    rt = resolver.resolve(py_app_container)
    index = build_index(f"/proc/{rt.init_pid}/root", ecosystems=("python",))

    async def drive():
        client = ObserverClient(_BIN)
        await client.start([rt.cgroup_id], duration=6)
        try:
            await asyncio.sleep(1.0)
            _run("docker", "exec", py_app_container, "python", "-c", "import requests")
            return await client.collect()
        finally:
            await client.stop()

    reach = correlate_opens(asyncio.run(drive()), index)

    # Simulated SCA output: one CVE in a reached pkg, one in an unreached pkg.
    vulns = [
        {"package": "requests", "cve_id": ["CVE-TEST-REQ"], "severity": "HIGH"},
        {"package": "tabulate", "cve_id": ["CVE-TEST-TAB"], "severity": "HIGH"},
    ]
    findings = {f.package: f for f in to_reachability_findings(reach, vulns)}

    req = findings["requests"]
    assert req.verdict == "LIKELY"
    assert req.import_detected and req.import_time_hit
    assert not req.call_chain_exists
    assert req.evidence_type == "dynamic"
    assert req.files, "expected evidence paths for reached package"

    tab = findings["tabulate"]
    assert tab.verdict == "NOT_OBSERVED"
    assert not tab.import_detected


def test_observer_runner_end_to_end(py_app_container):
    """Agent-facing entrypoint: run_observer_reachability drives the full path
    (resolve → index → observe+traffic → correlate → canonical findings)."""
    ok, reason = observer_available()
    assert ok, f"observer not available: {reason}"

    async def traffic():
        _run("docker", "exec", py_app_container, "python", "-c", "import requests")

    vulns = [
        {"package": "requests", "cve_id": ["CVE-TEST-REQ"], "severity": "HIGH"},
        {"package": "tabulate", "cve_id": ["CVE-TEST-TAB"], "severity": "HIGH"},
    ]
    findings, meta = asyncio.run(run_observer_reachability(
        py_app_container, vulns, ecosystems=("python",), duration=6, traffic=traffic,
    ))
    by_pkg = {f.package: f for f in findings}
    assert by_pkg["requests"].verdict == "LIKELY"
    assert by_pkg["tabulate"].verdict == "NOT_OBSERVED"
    assert meta["engine"] == "observer"
    assert meta["open_events"] > 0
    assert "requests" in meta["reached"]
