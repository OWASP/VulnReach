"""Unit tests for DynamicReachabilityAgent._run_observer_mode orchestration.

This 100-line method is the seam that wires the eBPF observer into a real scan:
build image → start container → attach observer → drive traffic → correlate →
canonical AgentResult. It had no automated coverage — only the heavy manual
e2e (observer/e2e/scan_driver.py) exercised it, and never on the CI machine.

These tests stub the heavy pieces (image build, container lifecycle,
schemathesis, run_observer_reachability) and assert the ORCHESTRATION: the skip
and failure branches, that scan inputs (vulns / import_map / taint_flows) are
threaded through, that the traffic callback marks the boot→traffic boundary and
drives load, and that the container is always torn down. No Docker or kernel
needed, so it runs in normal CI.
"""
from __future__ import annotations

import asyncio
from pathlib import Path
from types import SimpleNamespace

import pytest

import agents.ebpf.observer_runner as observer_runner
from agents.agent_dynamic_reachability import DynamicReachabilityAgent
from core.models import ReachabilityFinding, ScanContext


def _runtime():
    return SimpleNamespace(container_port=3000, timeout=10, coverage_wait=10)


def _context():
    return ScanContext(
        repo_path="/tmp/app",
        scan_id="s1",
        vulnerabilities=[{"package": "flask", "cve_id": ["CVE-X"]}],
        import_map={"flask": "flask"},
        taint_flows=[{"sink": {"definition": {"module": "yaml"}}}],
    )


def _run(agent, context, preflight):
    return asyncio.run(
        agent._run_observer_mode(context, Path("/tmp/app"), _runtime(), preflight))


# ── skip / failure branches ───────────────────────────────────────────────────

def test_skips_when_not_dockerfile_mode(monkeypatch):
    agent = DynamicReachabilityAgent()
    built = []
    monkeypatch.setattr(agent, "_build_plain_image",
                        lambda *a, **k: built.append(1))  # must NOT be called
    res = _run(agent, _context(), {"openapi_path": "/tmp/o.json"})  # no dockerfile_path
    assert res.metadata["status"] == "skipped"
    assert res.metadata["reason"] == "observer_requires_dockerfile_mode"
    assert not built and res.findings == []


def test_skips_when_observer_unavailable(monkeypatch):
    agent = DynamicReachabilityAgent()
    monkeypatch.setattr(observer_runner, "observer_available",
                        lambda *a, **k: (False, "btf_unavailable"))
    res = _run(agent, _context(), {"dockerfile_path": "/tmp/Dockerfile"})
    assert res.metadata["status"] == "skipped"
    assert res.metadata["reason"] == "observer_unavailable:btf_unavailable"


def test_fails_when_image_build_fails(monkeypatch):
    agent = DynamicReachabilityAgent()
    monkeypatch.setattr(observer_runner, "observer_available", lambda *a, **k: (True, "ok"))

    async def _build(*a, **k):
        return None, {"build_error": "boom"}
    monkeypatch.setattr(agent, "_build_plain_image", _build)

    res = _run(agent, _context(), {"dockerfile_path": "/tmp/Dockerfile"})
    assert res.metadata["status"] == "failed"
    assert res.metadata["step"] == "observer_image_build"


def test_fails_when_container_start_fails(monkeypatch):
    agent = DynamicReachabilityAgent()
    monkeypatch.setattr(observer_runner, "observer_available", lambda *a, **k: (True, "ok"))

    async def _build(*a, **k):
        return "img:tag", {}

    async def _start(*a, **k):
        return None
    monkeypatch.setattr(agent, "_build_plain_image", _build)
    monkeypatch.setattr(agent, "_start_container_plain", _start)

    res = _run(agent, _context(), {"dockerfile_path": "/tmp/Dockerfile"})
    assert res.metadata["status"] == "failed"
    assert res.metadata["step"] == "observer_container_start"


# ── success path: the wiring that matters ─────────────────────────────────────

def test_success_threads_inputs_drives_traffic_and_tears_down(monkeypatch):
    agent = DynamicReachabilityAgent()
    calls: dict = {}

    monkeypatch.setattr(observer_runner, "observer_available", lambda *a, **k: (True, "ok"))

    async def _build(*a, **k):
        return "img:tag", {}

    async def _start(*a, **k):
        return "containerabcdef0123"

    async def _healthy(base_url, timeout=30):
        calls["healthy_url"] = base_url
        return True

    async def _schema(base_url, openapi_path, container_port, workdir=None):
        calls["schemathesis"] = (base_url, openapi_path, container_port)

    async def _stop(container_id):
        calls["stopped"] = container_id

    monkeypatch.setattr(agent, "_build_plain_image", _build)
    monkeypatch.setattr(agent, "_start_container_plain", _start)
    monkeypatch.setattr(agent, "_wait_for_healthy", _healthy)
    monkeypatch.setattr(agent, "_run_schemathesis", _schema)
    monkeypatch.setattr(agent, "_stop_container", _stop)

    async def _observe(container_ref, vulnerabilities, *, import_map, taint_flows,
                       duration, traffic, window):
        # Capture what the seam threads through, then exercise the traffic
        # callback exactly as the real runner does (so health-wait → mark →
        # schemathesis is covered), and confirm the window was marked.
        calls["observe"] = {
            "container_ref": container_ref,
            "vulns": vulnerabilities,
            "import_map": import_map,
            "taint_flows": taint_flows,
        }
        await traffic()
        calls["window_marked"] = window.start_ns is not None
        return [ReachabilityFinding(cve_id="CVE-X", package="flask",
                                    verdict="LIKELY", evidence_type="dynamic")], {"engine": "observer"}
    monkeypatch.setattr(observer_runner, "run_observer_reachability", _observe)

    ctx = _context()
    res = _run(agent, ctx, {"dockerfile_path": "/tmp/Dockerfile", "openapi_path": "/tmp/o.json"})

    # Result shape
    assert res.metadata["status"] == "ok"
    assert res.metadata["mode"] == "ebpf_observer"
    assert res.metadata["finding_count"] == 1
    assert res.findings[0]["package"] == "flask"

    # Scan inputs threaded into the observer runner
    assert calls["observe"]["vulns"] == ctx.vulnerabilities
    assert calls["observe"]["import_map"] == ctx.import_map
    assert calls["observe"]["taint_flows"] == ctx.taint_flows
    assert calls["observe"]["container_ref"] == "containerabcdef0123"

    # Traffic wiring: health-checked, window marked at the boundary, load driven
    assert calls["window_marked"] is True
    assert "schemathesis" in calls
    # Container always torn down (the finally block)
    assert calls["stopped"] == "containerabcdef0123"


def test_container_torn_down_even_when_observer_raises(monkeypatch):
    """The finally must stop the container even if correlation blows up."""
    agent = DynamicReachabilityAgent()
    calls: dict = {}
    monkeypatch.setattr(observer_runner, "observer_available", lambda *a, **k: (True, "ok"))

    async def _build(*a, **k):
        return "img:tag", {}

    async def _start(*a, **k):
        return "cid123456789"

    async def _stop(container_id):
        calls["stopped"] = container_id

    async def _observe(*a, **k):
        raise RuntimeError("correlation exploded")

    monkeypatch.setattr(agent, "_build_plain_image", _build)
    monkeypatch.setattr(agent, "_start_container_plain", _start)
    monkeypatch.setattr(agent, "_stop_container", _stop)
    monkeypatch.setattr(observer_runner, "run_observer_reachability", _observe)

    with pytest.raises(RuntimeError, match="correlation exploded"):
        _run(agent, _context(), {"dockerfile_path": "/tmp/Dockerfile"})
    assert calls["stopped"] == "cid123456789"
