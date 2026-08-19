"""Static (Python) reachability — wiring, name resolution, and verdict gradation.

These are plain unit tests: no Docker, no root, no kernel. They run in normal CI,
which matters because the defects they cover survived for seven months precisely
because nothing exercised this path.
"""
from __future__ import annotations

import textwrap

import pytest

from agents.agent_python_reachability import PythonReachabilityAgent
from agents.reachability import python_reachability_analyzer as pra
from agents.reachability.python_reachability_analyzer import PythonReachabilityAnalyzer


# ── The regression that started this ──────────────────────────────────────────

def test_optional_analysis_modules_are_actually_importable():
    """Both optional sub-analyzers must resolve inside the reachability package.

    `agents/reachability/` was created as a refactor of `agents/utils/`, but
    python_call_graph.py and dependency_tree_analyzer.py were not moved with it.
    The imports are wrapped in `except ImportError`, so instead of failing they
    silently set these flags False — the call graph, and with it every CONFIRMED
    static verdict, was dead for seven months and no test noticed.

    Java and JavaScript kept their call graphs through the same refactor, so this
    asserts the Python one specifically.
    """
    assert pra.HAS_CALL_GRAPH is True, (
        "PythonCallGraphBuilder did not import — static reachability has silently "
        "degraded to import-detection only and can never return CONFIRMED"
    )
    assert pra.HAS_DEP_TREE_ANALYZER is True, (
        "PythonDependencyTreeAnalyzer did not import — transitive dependency "
        "detection is silently disabled"
    )


def test_call_graph_builds_for_a_flask_app(tmp_path):
    app = tmp_path / "app.py"
    app.write_text(textwrap.dedent("""
        from flask import Flask, request
        import yaml

        app = Flask(__name__)

        def parse(raw):
            return yaml.load(raw)

        @app.route('/x')
        def handler():
            return parse(request.args.get('d', ''))
    """))
    analyzer = PythonReachabilityAnalyzer(str(tmp_path))
    assert analyzer.call_graph_builder is not None
    analyses = analyzer.analyze_vulnerability_reachability(
        [{"package_name": "PyYAML", "cve_ids": ["CVE-X"]}])
    assert analyses and analyses[0].is_used


# ── Distribution name vs import name ──────────────────────────────────────────

@pytest.mark.parametrize("dist,module", [
    ("PyYAML", "yaml"),
    ("Pillow", "pil"),            # normalized: PIL
    ("beautifulsoup4", "bs4"),
    ("python-dateutil", "dateutil"),
])
def test_candidate_module_names_bridge_dist_to_import(tmp_path, dist, module):
    """A PyPI name is not an import name, and matching only the former is a
    silent false negative on a package that is genuinely used."""
    analyzer = PythonReachabilityAnalyzer(str(tmp_path))
    assert module in analyzer.candidate_module_names(dist)


def test_pyyaml_usage_is_detected_via_its_import_name(tmp_path):
    """The concrete miss: `import yaml` under distribution name `PyYAML`.

    This scored NOT_OBSERVED at confidence 0.1 on the project's own demo app —
    advising a user to ignore a reachable `yaml.load` on request data.
    """
    (tmp_path / "app.py").write_text("import yaml\n\ndef f(raw):\n    return yaml.load(raw)\n")
    analyzer = PythonReachabilityAnalyzer(str(tmp_path))
    assert analyzer.find_package_usage("PyYAML"), "PyYAML usage missed via `import yaml`"


# ── Verdict gradation and evidence consistency ────────────────────────────────

class _FakeAnalysis:
    def __init__(self, package_name, is_used, call_chain_graph=None):
        self.package_name = package_name
        self.is_used = is_used
        self.call_chain_graph = call_chain_graph
        self.usage_contexts = []


def _map_one(analysis, tainted=None):
    vulns = [{"package_name": analysis.package_name, "cve_ids": ["CVE-1"]}]
    return PythonReachabilityAgent()._map_findings([analysis], vulns, tainted)[0]


def test_taint_flow_is_required_for_confirmed():
    """A call chain proves the package is reached, not that the vulnerable sink
    is. Without that distinction `yaml.safe_load` and `yaml.load` are the same
    finding and everything used lands on CONFIRMED 0.95."""
    with_taint = _map_one(_FakeAnalysis("PyYAML", True, "graph TD;"), {"yaml"})
    assert with_taint["verdict"] == "CONFIRMED"
    assert with_taint["sink_reachable"] is True

    without_taint = _map_one(_FakeAnalysis("PyYAML", True, "graph TD;"), set())
    assert without_taint["verdict"] == "LIKELY"
    assert without_taint["sink_reachable"] is False


def test_import_only_is_possible():
    """Import detected, no call chain, and no taint into it → POSSIBLE.

    (No taint deliberately: a taint flow reaching the package would itself prove
    a source→sink path and lift it to CONFIRMED.)
    """
    f = _map_one(_FakeAnalysis("requests", True, None), set())
    assert f["verdict"] == "POSSIBLE"


def test_taint_confirms_even_without_analyzer_call_graph():
    """Taint is stronger than the analyzer's call graph, not gated behind it.

    The JS/Java analyzers frequently emit no call_chain_graph; a proven taint
    flow into the package must still reach CONFIRMED.
    """
    f = _map_one(_FakeAnalysis("PyYAML", True, None), {"yaml"})
    assert f["verdict"] == "CONFIRMED"
    assert f["call_chain_exists"] is True
    assert f["sink_reachable"] is True


def test_unused_package_is_not_observed():
    f = _map_one(_FakeAnalysis("lxml", False, None), set())
    assert f["verdict"] == "NOT_OBSERVED"
    assert f["import_detected"] is False


@pytest.mark.parametrize("is_used,graph,tainted", [
    (True, "graph TD;", {"yaml"}),
    (True, "graph TD;", set()),
    (True, None, {"yaml"}),
    (False, None, set()),
])
def test_reported_evidence_matches_the_verdict(is_used, graph, tainted):
    """Findings must not contradict themselves.

    The verdict and the evidence fields were computed from different values, so
    a finding could report verdict=LIKELY — which the engine defines as
    import + call chain — next to call_chain_exists=False. That contradiction
    flows into the EvidenceGraph and the AI next-steps endpoint.
    """
    from correlation.engine import reachability_verdict

    f = _map_one(_FakeAnalysis("PyYAML", is_used, graph), tainted)
    assert f["verdict"] == reachability_verdict(
        f["import_detected"], f["call_chain_exists"], f["sink_reachable"])
