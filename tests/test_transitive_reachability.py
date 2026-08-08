"""Transitive reachability — a vulnerable dep reached through a used package.

Plain unit tests (no Docker). Validated end-to-end by the Tier 3 oracle
(observer/e2e/static_vs_runtime.py), which measured recall on labs/python_vuln_app
rising 0.33 → 0.89 once these upgrades were applied, precision holding at 1.00.
"""
from __future__ import annotations

import textwrap

from agents.reachability.transitive import (
    apply_transitive, requires_graph_from_site_packages, transitive_paths,
)


_FLASK_STACK = {
    "flask": {"werkzeug", "jinja2", "click", "itsdangerous"},
    "jinja2": {"markupsafe"},
    "werkzeug": {"markupsafe"},
    "requests": {"urllib3", "certifi", "idna"},
}


def test_transitive_paths_shortest_chain():
    paths = transitive_paths(["flask", "requests"], _FLASK_STACK)
    assert paths["werkzeug"] == ["flask", "werkzeug"]
    assert paths["urllib3"] == ["requests", "urllib3"]
    # markupsafe is reachable via both flask→jinja2 and flask→werkzeug; either
    # 3-hop chain is acceptable, but it must be shortest (no longer path).
    assert len(paths["markupsafe"]) == 3
    # a root is never listed as reachable-from-itself
    assert "flask" not in paths


def test_apply_transitive_upgrades_only_not_observed():
    findings = [
        {"package": "Flask", "verdict": "CONFIRMED"},
        {"package": "Werkzeug", "verdict": "NOT_OBSERVED"},
        {"package": "Jinja2", "verdict": "NOT_OBSERVED"},
        {"package": "lxml", "verdict": "NOT_OBSERVED"},   # not a dep of anything used
    ]
    apply_transitive(findings, _FLASK_STACK)
    by = {f["package"]: f for f in findings}
    # CONFIRMED is left alone
    assert by["Flask"]["verdict"] == "CONFIRMED"
    assert by["Flask"].get("reachable_via") is None
    # transitive vuln deps become POSSIBLE with a parent chain
    assert by["Werkzeug"]["verdict"] == "POSSIBLE"
    assert by["Werkzeug"]["reachable_via"] == ["flask", "werkzeug"]
    assert by["Jinja2"]["verdict"] == "POSSIBLE"
    # a package no used package depends on stays NOT_OBSERVED
    assert by["lxml"]["verdict"] == "NOT_OBSERVED"
    assert by["lxml"].get("reachable_via") is None


def test_apply_transitive_noop_without_used_roots():
    # Nothing directly used ⇒ nothing to reach through ⇒ no upgrades.
    findings = [{"package": "Werkzeug", "verdict": "NOT_OBSERVED"}]
    apply_transitive(findings, _FLASK_STACK)
    assert findings[0]["verdict"] == "NOT_OBSERVED"


def test_apply_transitive_noop_with_empty_graph():
    findings = [{"package": "Flask", "verdict": "CONFIRMED"},
                {"package": "Werkzeug", "verdict": "NOT_OBSERVED"}]
    apply_transitive(findings, {})
    assert findings[1]["verdict"] == "NOT_OBSERVED"


def test_requires_graph_from_site_packages_parses_metadata(tmp_path):
    """The graph reader must handle the real METADATA header shape.

    Regression guard: the Name value carries leading whitespace ("Name: Flask")
    and Requires-Dist entries carry version specifiers and extras — the first
    cut keyed the graph on " flask\\n" and the flask→werkzeug edge was lost.
    """
    sp = tmp_path / "site-packages"
    dist = sp / "Flask-2.0.1.dist-info"
    dist.mkdir(parents=True)
    (dist / "METADATA").write_text(textwrap.dedent("""\
        Metadata-Version: 2.1
        Name: Flask
        Version: 2.0.1
        Requires-Dist: Werkzeug (>=2.0)
        Requires-Dist: Jinja2 (>=3.0)
        Requires-Dist: asgiref (>=3.2) ; extra == 'async'

        Flask is a lightweight WSGI web application framework.
    """))
    graph = requires_graph_from_site_packages(str(sp))
    assert "flask" in graph, f"Name not parsed cleanly: {list(graph)}"
    assert "werkzeug" in graph["flask"]
    assert "jinja2" in graph["flask"]
    # extras are optional deps, not part of the default closure
    assert "asgiref" not in graph["flask"]
