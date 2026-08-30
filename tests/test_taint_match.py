"""Taint→package matching and the Java/JS static verdict grounding.

Plain unit tests (no Docker, no tainter binary). They pin the behaviour that a
call chain alone is LIKELY and only a taint path into the package's namespace
lifts a finding to CONFIRMED — across Python, Java, and the JS/multi-language
bridge, which all previously set sink_reachable = call_chain_exists and so
marked every used package CONFIRMED.
"""
from __future__ import annotations

import pytest

from agents.reachability.taint_match import sink_modules, package_taint_reachable


# ── sink_modules extraction ───────────────────────────────────────────────────

def test_sink_modules_keeps_full_namespace_lowercased():
    flows = [
        {"sink": {"definition": {"module": "Axios"}}},
        {"sink": {"definition": {"module": "com.google.gson"}}},
        {"sink": {"definition": {"module": ""}}},
        {"sink": {}},
        {},
    ]
    assert sink_modules(flows) == {"axios", "com.google.gson"}


def test_sink_modules_does_not_collapse_java_namespaces():
    # 'java.lang' must NOT become 'java' — that would match every Java package.
    assert sink_modules([{"sink": {"definition": {"module": "org.apache.velocity"}}}]) == {
        "org.apache.velocity"}


# ── matching, per language ────────────────────────────────────────────────────

@pytest.mark.parametrize("pkg,tainted,expected", [
    # JS: npm sink modules are bare names.
    ("axios", {"axios"}, True),
    ("@myco/axios", {"axios"}, True),         # scoped → last segment
    ("lodash", {"axios"}, False),
    ("express", {"builtins"}, False),          # eval sink credits no package
])
def test_js_matching(pkg, tainted, expected):
    assert package_taint_reachable(pkg, "javascript", tainted) is expected


@pytest.mark.parametrize("pkg,tainted,expected", [
    # group == namespace
    ("org.apache.velocity:velocity-engine-core", {"org.apache.velocity"}, True),
    # group != namespace, artifact token is a dotted segment of the sink
    ("com.google.code.gson:gson", {"com.google.gson"}, True),
    ("org.freemarker:freemarker", {"freemarker.template"}, True),
    # generic artifact token must not match an unrelated namespace
    ("com.foo:core", {"com.bar.core"}, False),
    # a builtin/runtime sink credits no dependency
    ("org.apache.velocity:velocity", {"java.lang"}, False),
])
def test_java_matching(pkg, tainted, expected):
    assert package_taint_reachable(pkg, "java", tainted) is expected


@pytest.mark.parametrize("pkg,tainted,expected", [
    ("PyYAML", {"yaml"}, True),                # dist name → import name
    ("lxml", {"lxml.etree"}, True),            # submodule sink credits top-level
    ("requests", {"yaml"}, False),
])
def test_python_matching(pkg, tainted, expected):
    assert package_taint_reachable(pkg, "python", tainted) is expected


def test_no_taint_is_never_reachable():
    assert package_taint_reachable("axios", "javascript", set()) is False
    assert package_taint_reachable("axios", "javascript", None) is False


# ── Java agent verdict grounding ──────────────────────────────────────────────

class _FakeAnalysis:
    def __init__(self, package_name, is_used, call_chain_graph=None):
        self.package_name = package_name
        self.is_used = is_used
        self.call_chain_graph = call_chain_graph
        self.usage_contexts = []


def _java_finding(analysis, tainted):
    from agents.agent_java_reachability import JavaReachabilityAgent
    vulns = [{"package_name": analysis.package_name, "cve_ids": ["CVE-J"]}]
    return JavaReachabilityAgent()._map_findings([analysis], vulns, tainted)[0]


def test_java_call_chain_without_taint_is_likely():
    a = _FakeAnalysis("org.apache.velocity:velocity-engine-core", True, "graph TD;")
    assert _java_finding(a, set())["verdict"] == "LIKELY"
    assert _java_finding(a, set())["sink_reachable"] is False


def test_java_taint_into_namespace_is_confirmed():
    a = _FakeAnalysis("org.apache.velocity:velocity-engine-core", True, "graph TD;")
    f = _java_finding(a, {"org.apache.velocity"})
    assert f["verdict"] == "CONFIRMED"
    assert f["sink_reachable"] is True


def test_java_import_only_is_possible():
    # No taint into the package and no call chain → import-only → POSSIBLE.
    a = _FakeAnalysis("org.apache.velocity:velocity", True, None)
    assert _java_finding(a, set())["verdict"] == "POSSIBLE"


def test_java_taint_confirms_without_call_graph():
    # The Java analyzer often emits no call graph; taint alone must still confirm.
    a = _FakeAnalysis("org.apache.velocity:velocity-engine-core", True, None)
    f = _java_finding(a, {"org.apache.velocity"})
    assert f["verdict"] == "CONFIRMED"
    assert f["sink_reachable"] is True


# ── Bridge (JS/Go/PHP/C#) verdict grounding ───────────────────────────────────

def _bridge_finding(report_analysis, language, tainted):
    from agents.reachability.agent_bridge import MultiLanguageReachabilityBridge
    report = {"analyses": [report_analysis]}
    vulns = [{"package": report_analysis["package_name"], "cve_id": ["CVE-B"]}]
    bridge = MultiLanguageReachabilityBridge()
    return bridge._map_findings(report, vulns, language, tainted)[0]


def test_bridge_js_call_chain_without_taint_is_likely():
    a = {"package_name": "axios", "is_used": True, "call_chain_graph": "graph TD;",
         "usage_contexts": []}
    assert _bridge_finding(a, "javascript", set())["verdict"] == "LIKELY"


def test_bridge_js_taint_is_confirmed():
    a = {"package_name": "axios", "is_used": True, "call_chain_graph": "graph TD;",
         "usage_contexts": []}
    f = _bridge_finding(a, "javascript", {"axios"})
    assert f["verdict"] == "CONFIRMED"
    assert f["sink_reachable"] is True


def test_bridge_js_untainted_package_stays_likely():
    a = {"package_name": "lodash", "is_used": True, "call_chain_graph": "graph TD;",
         "usage_contexts": []}
    # A taint flow exists, but into a different package.
    assert _bridge_finding(a, "javascript", {"axios"})["verdict"] == "LIKELY"
