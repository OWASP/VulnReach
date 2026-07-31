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
