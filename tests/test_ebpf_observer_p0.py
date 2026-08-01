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
from agents.ebpf.reachability import (
    correlate_opens, POTENTIALLY_REACHABLE, CONFIRMED_REACHABLE,
)
from agents.ebpf.verdict_integration import to_reachability_findings
from agents.ebpf.observer_runner import (
    run_observer_reachability, observer_available, find_libpython, find_libjvm,
    TrafficWindow,
)

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


def test_native_exec_r2_confirmed(py_app_container):
    """P4/Rule R2: a native extension mapped PROT_EXEC ⇒ CONFIRMED.

    charset_normalizer ships a compiled .so; requests is pure Python. Importing
    both must yield CONFIRMED for the native package and LIKELY for the pure one.
    """
    resolver = DockerTargetResolver()
    rt = resolver.resolve(py_app_container)
    index = build_index(f"/proc/{rt.init_pid}/root", ecosystems=("python",))

    async def drive():
        client = ObserverClient(_BIN)
        await client.start([rt.cgroup_id], duration=8)
        try:
            await asyncio.sleep(1.0)
            _run("docker", "exec", py_app_container, "python", "-c",
                 "import requests, charset_normalizer")
            return await client.collect()
        finally:
            await client.stop()

    events = asyncio.run(drive())
    assert any(e["type"] == "mmap_exec" for e in events), "no mmap_exec events captured"

    reach = correlate_opens(events, index)
    cn = reach.get("python:charset_normalizer")
    assert cn is not None, f"charset_normalizer not reached: {sorted(reach)}"
    assert cn.verdict == CONFIRMED_REACHABLE, f"expected R2 CONFIRMED, got {cn.verdict}/{cn.rule}"
    assert cn.rule == "R2"

    vulns = [
        {"package": "charset-normalizer", "cve_id": ["CVE-T-CN"], "severity": "HIGH"},
        {"package": "requests", "cve_id": ["CVE-T-REQ"], "severity": "HIGH"},
    ]
    by_pkg = {f.package: f for f in to_reachability_findings(reach, vulns)}
    assert by_pkg["charset-normalizer"].verdict == "CONFIRMED"
    assert by_pkg["charset-normalizer"].call_chain_exists is True
    assert by_pkg["charset-normalizer"].confidence == 0.8
    # Pure-Python package stays load-level.
    assert by_pkg["requests"].verdict == "LIKELY"
    assert by_pkg["requests"].import_time_hit is True


def test_taint_crossref_r4_confirmed(py_app_container):
    """P7/Rule R4: runtime load + a static taint path ⇒ CONFIRMED.

    This is the route to CONFIRMED for *pure-interpreted* packages, which R2
    (native code) can never reach. Uses the product's canonical rule
    (dynamic_reachability_verdict): taint flow + runtime evidence ⇒ CONFIRMED.
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

    # Tainter-shaped flow: user input reaches requests (pure-Python package).
    flows = [{
        "id": "FLOW-TEST",
        "vulnerability_class": "SSRF",
        "sink": {"definition": {"module": "requests", "function": "get"}},
        "source": {"location": {"file": "/app/src/app.py", "line": 10}},
    }]
    vulns = [
        {"package": "requests", "cve_id": ["CVE-T-REQ"], "severity": "HIGH"},
        {"package": "tabulate", "cve_id": ["CVE-T-TAB"], "severity": "HIGH"},
    ]

    # Without taint: runtime load only ⇒ LIKELY.
    no_taint = {f.package: f for f in to_reachability_findings(reach, vulns)}
    assert no_taint["requests"].verdict == "LIKELY"

    # With taint: loaded + static path ⇒ CONFIRMED (R4).
    with_taint = {f.package: f
                  for f in to_reachability_findings(reach, vulns, taint_flows=flows)}
    req = with_taint["requests"]
    assert req.verdict == "CONFIRMED", f"R4 did not elevate: {req.verdict}"
    assert req.sink_reachable is True
    assert req.confidence == 0.9
    # Taint path but never loaded stays below CONFIRMED.
    assert with_taint["tabulate"].verdict == "NOT_OBSERVED"


def test_taint_only_is_possible():
    """A taint path to a package that was never loaded ⇒ POSSIBLE (not CONFIRMED)."""
    flows = [{"sink": {"definition": {"module": "yaml"}}}]
    vulns = [{"package": "PyYAML", "cve_id": ["CVE-T-YAML"], "severity": "HIGH"}]
    out = to_reachability_findings({}, vulns, taint_flows=flows)
    assert out[0].verdict == "POSSIBLE"
    assert out[0].import_detected is False


def test_observer_runner_end_to_end(py_app_container):
    """Agent-facing entrypoint: run_observer_reachability drives the full path
    (resolve → index → observe+traffic → correlate → canonical findings)."""
    ok, reason = observer_available()
    assert ok, f"observer not available: {reason}"

    # Mirrors _run_observer_mode: mark the boundary once the target is "healthy",
    # then drive real calls into the package.
    window = TrafficWindow()

    # Must not block the event loop: the collector drains the observer's stdout
    # concurrently, and a blocking subprocess.run here lets the pipe fill and
    # truncate the tail of the event stream. Production traffic
    # (_run_schemathesis) is async for the same reason.
    async def _exec(*cmd: str) -> None:
        proc = await asyncio.create_subprocess_exec(
            "docker", "exec", py_app_container, *cmd,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        await proc.wait()

    async def traffic():
        await _exec("python", "-c", "import requests")
        window.mark()
        await asyncio.sleep(0.3)
        await _exec("python", "-c", "import requests; requests.utils.default_headers()")
        await asyncio.sleep(0.5)  # let the tail of the stream drain

    vulns = [
        {"package": "requests", "cve_id": ["CVE-TEST-REQ"], "severity": "HIGH"},
        {"package": "tabulate", "cve_id": ["CVE-TEST-TAB"], "severity": "HIGH"},
    ]
    findings, meta = asyncio.run(run_observer_reachability(
        py_app_container, vulns, ecosystems=("python",), duration=10,
        traffic=traffic, window=window,
    ))
    by_pkg = {f.package: f for f in findings}
    # The runner auto-discovers libpython, so Tier B is on and `requests` is
    # CONFIRMED by execution during traffic (R5), not merely loaded (R1).
    assert by_pkg["requests"].verdict == "CONFIRMED"
    assert by_pkg["tabulate"].verdict == "NOT_OBSERVED"
    assert meta["engine"] == "observer"
    assert meta["open_events"] > 0
    assert "requests" in meta["reached"]
    assert meta["tier_b"]["enabled"] is True
    assert meta["py_call_events"] > 0
    assert "requests" in meta["code_executed"]


def _drive(cgroup_id: int, cmd: list[str], container: str, python_lib=None, secs=8):
    """Observe `container` for `secs` while running `cmd` inside it."""
    async def go():
        client = ObserverClient(_BIN)
        ready = await client.start([cgroup_id], duration=secs, python_lib=python_lib)
        try:
            await asyncio.sleep(1.0)  # let the probes settle
            _run("docker", "exec", container, *cmd)
            return ready, await client.collect()
        finally:
            await client.stop()
    return asyncio.run(go())


def test_interpreted_exec_r5_confirmed(py_app_container):
    """P8/Rule R5: the CPython uprobe lifts a pure-Python package to CONFIRMED.

    A/B against the same workload: Tier A alone can only prove `requests` was
    *loaded* (LIKELY). With Tier B attached we see the interpreter evaluate
    frames from its source, which is execution proof (CONFIRMED).
    """
    rt = DockerTargetResolver().resolve(py_app_container)
    root = f"/proc/{rt.init_pid}/root"
    index = build_index(root, ecosystems=("python",))

    lib = find_libpython(root)
    assert lib is not None, "no libpython found in the fixture image"

    imp = ["python", "-c", "import requests; requests.utils.default_headers()"]

    # A — Tier A only.
    _, base_events = _drive(rt.cgroup_id, imp, py_app_container)
    assert not any(e["type"] == "py_call" for e in base_events)
    base = correlate_opens(base_events, index)
    assert base["python:requests"].verdict == POTENTIALLY_REACHABLE

    # B — Tier B attached.
    ready, events = _drive(rt.cgroup_id, imp, py_app_container, python_lib=lib)
    assert "uprobe:py_eval_frame" in ready["progs"], f"tier B did not attach: {ready}"
    assert any(e["type"] == "py_call" for e in events), "no py_call events captured"

    reach = correlate_opens(events, index)
    req = reach.get("python:requests")
    assert req is not None, f"requests not reached: {sorted(reach)}"
    assert req.verdict == CONFIRMED_REACHABLE, f"expected R5 CONFIRMED, got {req.verdict}/{req.rule}"
    assert "R5" in req.rule

    vulns = [{"package": "requests", "cve_id": ["CVE-T-REQ"], "severity": "HIGH"},
             {"package": "tabulate", "cve_id": ["CVE-T-TAB"], "severity": "HIGH"}]
    by_pkg = {f.package: f for f in to_reachability_findings(reach, vulns)}
    assert by_pkg["requests"].verdict == "CONFIRMED"
    assert by_pkg["requests"].confidence == 0.85
    assert by_pkg["requests"].call_chain_exists is True
    # Never imported ⇒ Tier B must not invent evidence for it.
    assert by_pkg["tabulate"].verdict == "NOT_OBSERVED"


def test_tier_b_failure_preserves_baseline(py_app_container):
    """The redesign's hard constraint: Tier B may only ever add signal.

    Point the uprobe at an unusable path — the observer must still come up and
    deliver the full Tier A baseline rather than failing the scan.
    """
    rt = DockerTargetResolver().resolve(py_app_container)
    index = build_index(f"/proc/{rt.init_pid}/root", ecosystems=("python",))

    ready, events = _drive(rt.cgroup_id, ["python", "-c", "import requests"],
                           py_app_container, python_lib="/nonexistent/libpython3.9.so")
    assert "uprobe:py_eval_frame" not in ready["progs"]
    assert not any(e["type"] == "py_call" for e in events)

    # Baseline intact.
    reach = correlate_opens(events, index)
    assert reach["python:requests"].verdict == POTENTIALLY_REACHABLE
    vulns = [{"package": "requests", "cve_id": ["CVE-T-REQ"], "severity": "HIGH"}]
    assert to_reachability_findings(reach, vulns)[0].verdict == "LIKELY"


def test_r5_traffic_boundary_separates_import_from_use(py_app_container):
    """R5's precision rule: importing a package is not using it.

    Importing runs plenty of a package's own code (module bodies, class bodies,
    decorators), so "a frame executed" alone is barely stricter than R1. The
    boot→traffic boundary is what makes R5 mean *this ran to serve a request*.
    Here `tabulate` is only imported; `requests` is imported and then called.
    """
    rt = DockerTargetResolver().resolve(py_app_container)
    root = f"/proc/{rt.init_pid}/root"
    index = build_index(root, ecosystems=("python",))
    lib = find_libpython(root)
    window = TrafficWindow()

    async def go():
        client = ObserverClient(_BIN)
        await client.start([rt.cgroup_id], duration=10, python_lib=lib)
        # Bumps the in-kernel dedupe epoch on mark, so files already reported
        # during startup can be reported again while serving traffic.
        window.attach(client.mark)
        try:
            await asyncio.sleep(1.0)
            # "boot": both packages imported before traffic starts.
            _run("docker", "exec", py_app_container, "python", "-c",
                 "import tabulate, requests")
            await asyncio.sleep(0.5)
            window.mark()
            await asyncio.sleep(0.5)
            # "traffic": only requests is actually called.
            _run("docker", "exec", py_app_container, "python", "-c",
                 "import requests; requests.utils.default_headers()")
            return await client.collect()
        finally:
            await client.stop()

    events = asyncio.run(go())
    reach = correlate_opens(events, index, traffic_start_ns=window.start_ns)

    req = reach.get("python:requests")
    assert req is not None and req.verdict == CONFIRMED_REACHABLE, \
        f"requests should be CONFIRMED after being called: {req}"
    assert "R5" in req.rule

    tab = reach.get("python:tabulate")
    assert tab is not None, "tabulate should still be seen as loaded"
    assert tab.verdict == POTENTIALLY_REACHABLE, \
        f"import-only package must not reach CONFIRMED, got {tab.verdict}/{tab.rule}"

    # Same events without the boundary: tabulate would be indistinguishable.
    naive = correlate_opens(events, index)
    assert naive["python:tabulate"].verdict == CONFIRMED_REACHABLE


_JAVA_IMAGE = os.environ.get("VULNREACH_JAVA_FIXTURE", "vulnreach-java-fixture")


@pytest.fixture()
def java_app_container():
    name = f"vr_java_{uuid.uuid4().hex[:8]}"
    _run("docker", "run", "-d", "--name", name, _JAVA_IMAGE, "sleep", "600")
    try:
        yield name
    finally:
        subprocess.run(["docker", "rm", "-f", name], capture_output=True)


async def _docker_exec(container: str, *cmd: str) -> None:
    """Async so the collector keeps draining the observer's stdout."""
    proc = await asyncio.create_subprocess_exec(
        "docker", "exec", container, *cmd,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    await proc.wait()


def test_java_class_load_r6_confirmed(java_app_container):
    """Rule R6: the JVM resolves a class only on first active use.

    Both jars are on the classpath, so nothing static can tell them apart —
    only the class__loaded probe shows that com.example.used.Greeter was needed
    and com.example.unused.Idle never was.
    """
    rt = DockerTargetResolver().resolve(java_app_container)
    root = f"/proc/{rt.init_pid}/root"
    index = build_index(root, ecosystems=("java",))
    names = {e.name for e in index.entries()}
    assert {"usedlib", "unusedlib"} <= names, f"fixture jars not indexed: {sorted(names)}"

    libjvm = find_libjvm(root)
    assert libjvm is not None, "no libjvm.so found in the fixture image"
    window = TrafficWindow()

    async def go():
        client = ObserverClient(_BIN)
        ready = await client.start([rt.cgroup_id], duration=20, jvm_lib=libjvm)
        assert "uprobe:jvm_class_loaded" in ready["progs"], f"jvm tier B not attached: {ready}"
        window.attach(client.mark)
        try:
            await asyncio.sleep(1.0)
            window.mark()
            await asyncio.sleep(0.3)
            await _docker_exec(java_app_container, "java", "-cp",
                               "/libs/usedlib-1.0.jar:/libs/unusedlib-1.0.jar:/app", "App")
            await asyncio.sleep(0.5)
            return await client.collect()
        finally:
            await client.stop()

    events = asyncio.run(go())
    assert any(e["type"] == "java_class" for e in events), "no java_class events captured"

    reach = correlate_opens(events, index, traffic_start_ns=window.start_ns)
    used = reach.get("java:usedlib")
    assert used is not None, f"usedlib not reached: {sorted(reach)}"
    assert used.verdict == CONFIRMED_REACHABLE, f"expected R6 CONFIRMED, got {used.verdict}/{used.rule}"
    assert used.rule == "R6"
    assert used.version == "1.0"
    assert "java:unusedlib" not in reach, "a jar that was never used shows as reached"

    vulns = [{"package": "usedlib", "cve_id": ["CVE-T-USED"], "severity": "HIGH"},
             {"package": "unusedlib", "cve_id": ["CVE-T-UNUSED"], "severity": "HIGH"}]
    by_pkg = {f.package: f for f in to_reachability_findings(reach, vulns)}
    assert by_pkg["usedlib"].verdict == "CONFIRMED"
    assert by_pkg["usedlib"].confidence == 0.85
    assert by_pkg["usedlib"].call_chain_exists is True
    assert by_pkg["unusedlib"].verdict == "NOT_OBSERVED"
