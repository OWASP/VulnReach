
from correlation.engine import (
    classify_reachability,
    dynamic_reachability_verdict,
    evidence_basis_from_signals,
    priority_from_score,
    reachability_verdict,
    risk_score,
)


# ------------------------------------------------------------------
# Static reachability verdicts — import / call-chain evidence only
# CONFIRMED is never produced here; that is reserved for the dynamic path.
# ------------------------------------------------------------------
def test_static_reachability_verdict_rules():
    # import + call_chain + sink_reachable → CONFIRMED (full static trace to sink)
    assert reachability_verdict(True, True, True) == "CONFIRMED"
    # call-chain present but no sink proof → LIKELY
    assert reachability_verdict(True, True, False) == "LIKELY"
    # import only → POSSIBLE
    assert reachability_verdict(True, False, False) == "POSSIBLE"
    # nothing → NOT_OBSERVED
    assert reachability_verdict(False, False, False) == "NOT_OBSERVED"


# ------------------------------------------------------------------
# Dynamic reachability verdicts — taint flow + runtime coverage
# ------------------------------------------------------------------
def test_dynamic_reachability_verdict_rules():
    # both taint flow + coverage → CONFIRMED
    assert dynamic_reachability_verdict(True, True) == "CONFIRMED"
    # runtime coverage only → LIKELY
    assert dynamic_reachability_verdict(False, True) == "LIKELY"
    # taint flow only (not executed at runtime) → POSSIBLE
    assert dynamic_reachability_verdict(True, False) == "POSSIBLE"
    # neither → NOT_OBSERVED
    assert dynamic_reachability_verdict(False, False) == "NOT_OBSERVED"


def test_risk_score_and_priority():
    score = risk_score("CRITICAL", "CONFIRMED", "public")
    assert score == 7.8
    assert priority_from_score(score) == "P1"

    low_score = risk_score("LOW", "NOT_OBSERVED", "private")
    assert low_score == 0.5
    assert priority_from_score(low_score) == "P4"


# ------------------------------------------------------------------
# evidence_basis_from_signals — distinguishes dynamic vs static CONFIRMED
# ------------------------------------------------------------------
def test_evidence_basis_dynamic():
    """Dynamic confirmed findings return evidence_basis='dynamic'."""
    assert evidence_basis_from_signals("dynamic", has_coverage_hit=True, has_taint_flow=True) == "dynamic"
    assert evidence_basis_from_signals("dynamic", has_coverage_hit=True) == "dynamic"


def test_evidence_basis_static():
    """Call chain without coverage returns evidence_basis='static'."""
    assert evidence_basis_from_signals("static", call_chain_exists=True, import_detected=True) == "static"
    assert evidence_basis_from_signals("static", call_chain_exists=True) == "static"


def test_evidence_basis_taint_only():
    """Taint flow without call chain returns evidence_basis='taint_only'."""
    assert evidence_basis_from_signals("static", has_taint_flow=True) == "taint_only"


def test_evidence_basis_import_only():
    """Import only returns evidence_basis='import_only'."""
    assert evidence_basis_from_signals("static", import_detected=True) == "import_only"


def test_evidence_basis_none():
    """No signals returns evidence_basis='none'."""
    assert evidence_basis_from_signals("not_reachable") == "none"


def test_dynamic_finding_type_without_coverage_falls_through():
    """finding_type='dynamic' but has_coverage_hit=False falls through to other signals."""
    # This shouldn't happen in practice, but the function handles it gracefully.
    assert evidence_basis_from_signals("dynamic", has_coverage_hit=False, call_chain_exists=True) == "static"


# ------------------------------------------------------------------
# classify_reachability — import-only demotion to UNCERTAIN (Task 4)
# ------------------------------------------------------------------

def test_classify_import_only_is_uncertain():
    """import_detected alone must produce UNCERTAIN, not STATICALLY_REACHABLE."""
    cls, subtype = classify_reachability(
        coverage_hit=False,
        call_chain_exists=False,
        import_detected=True,
        function=None,
        file=None,
        evidence_type="static",
        package="requests",
    )
    assert cls == "UNCERTAIN"
    assert subtype is None


def test_classify_call_chain_without_import_is_statically_reachable():
    """call_chain_exists=True (even without import) must produce STATICALLY_REACHABLE."""
    cls, subtype = classify_reachability(
        coverage_hit=False,
        call_chain_exists=True,
        import_detected=False,
        function=None,
        file=None,
        evidence_type="static",
        package="requests",
    )
    assert cls == "STATICALLY_REACHABLE"


def test_classify_import_plus_call_chain_is_statically_reachable():
    """import + call_chain together still produces STATICALLY_REACHABLE."""
    cls, subtype = classify_reachability(
        coverage_hit=False,
        call_chain_exists=True,
        import_detected=True,
        function=None,
        file=None,
        evidence_type="static",
        package="requests",
    )
    assert cls == "STATICALLY_REACHABLE"


def test_classify_no_evidence_is_not_reachable():
    """No evidence at all must produce NOT_REACHABLE."""
    cls, subtype = classify_reachability(
        coverage_hit=False,
        call_chain_exists=False,
        import_detected=False,
        function=None,
        file=None,
        evidence_type="static",
        package="requests",
    )
    assert cls == "NOT_REACHABLE"


