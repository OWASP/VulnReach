"""Response analysis for the Intelligent DAST steering loop.

Three-step analysis pipeline:
  Step 1 — Strong signal check (pattern-based, no LLM needed)
  Step 2 — Medium signal check (status/body-length anomalies)
  Step 3 — LLM judge (for medium/weak signals)

The top-level `analyse()` function is the ResponseAnalyser callback
used by PayloadSession.
"""

from __future__ import annotations

import json
import logging
import re
from typing import Dict, List, Optional, Tuple

from .models import (
    AnalysisDecision,
    AttackFlow,
    IterationResult,
    Outcome,
    VulnClass,
)
from .llm_client import LLMClient

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Step 1 — Strong signal patterns by vuln class
# ---------------------------------------------------------------------------

_SQL_PATTERNS = re.compile(
    r"syntax error"
    r"|sql syntax"
    r"|you have an error in your sql"
    r"|sqlite3\.OperationalError"
    r"|sqlite3\.ProgrammingError"
    r"|OperationalError:"
    r"|ProgrammingError:"
    r"|DatabaseError:"
    r"|IntegrityError:"
    r"|DataError:"
    r"|mysql_fetch"
    r"|mysql_num_rows"
    r"|MySQLSyntaxErrorException"
    r"|ORA-\d{5}"
    r"|PLS-\d{5}"
    r"|pg_query\("
    r"|PSQLException"
    r"|psycopg2\."
    r"|ERROR:\s+syntax"
    r"|unterminated quoted string"
    r"|unclosed quotation"
    r"|Unclosed quotation mark"
    r"|SQLSTATE\["
    r"|Incorrect syntax near"
    r"|near \"[^\"]*\": syntax error"
    r"|unrecognized token"
    r"|django\.db\.utils\."
    r"|You have an error in your SQL syntax",
    re.IGNORECASE,
)

_SSTI_PATTERNS = re.compile(
    r"(?<!\d)49(?!\d)"  # 7*7 = 49, not part of a larger number
    r"|(?<!\d)7777777(?!\d)"  # 7*'7' string multiplication
    r"|<%=.*?%>"  # template tag leak
    r"|\\$\\{.*?\\}",  # expression language
    re.IGNORECASE,
)

_DESERIALIZE_PATTERNS = re.compile(
    r"yaml\.constructor"
    r"|yaml\.scanner"
    r"|yaml\.parser"
    r"|pickle\.loads"
    r"|_pickle\.UnpicklingError"
    r"|marshal\.loads"
    r"|Unpickler"
    r"|!!python/object"
    r"|__reduce__"
    r"|deserialization",
    re.IGNORECASE,
)

_SSRF_PATTERNS = re.compile(
    r"\b10\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"
    r"|\b172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}\b"
    r"|\b192\.168\.\d{1,3}\.\d{1,3}\b"
    r"|\b169\.254\.\d{1,3}\.\d{1,3}\b"
    r"|\b127\.0\.0\.\d{1,3}\b"
    r"|localhost",
    re.IGNORECASE,
)

_CMDI_PATTERNS = re.compile(
    r"uid=\d+"          # id command output
    r"|gid=\d+"
    r"|root:"           # /etc/passwd content
    r"|/bin/"           # path leak from command execution
    r"|/usr/bin/"
    r"|total \d+"       # ls -la output
    r"|drwx",           # directory listing
    re.IGNORECASE,
)

_RCE_ERROR_PATTERNS = re.compile(
    r"NameError:"
    r"|SyntaxError:"
    r"|TypeError:"
    r"|AttributeError:"
    r"|__builtins__"
    r"|<module>"
    r"|compile\(",
    re.IGNORECASE,
)

# Strong signals for eval/exec sinks: exception-based reflection
_RCE_EVAL_STRONG_PATTERNS = re.compile(
    r"ZeroDivisionError"
    r"|IndexError"
    r"|NameError: name"
    r"|division by zero"
    r"|VULNREACH_MARKER",
    re.IGNORECASE,
)

# Arithmetic expressions commonly used to detect eval() — maps payload→expected result
_EVAL_ARITHMETIC = {
    "7*7": "49",
    "3*41": "123",
    "11*13": "143",
    "1/0": None,        # exception-based — checked via _RCE_EVAL_STRONG_PATTERNS
    "[][999]": None,    # exception-based — checked via _RCE_EVAL_STRONG_PATTERNS
}

_GENERIC_PATTERNS = re.compile(
    r"Traceback \(most recent call last\)"
    r"|Unhandled Exception"
    r"|Internal Server Error"
    r"|stack trace"
    r"|at [\w.]+\([\w.]+:\d+\)"  # Java-style stack trace
    r"|File \"[^\"]+\", line \d+",  # Python traceback
    re.IGNORECASE,
)

_VULN_CLASS_PATTERNS: Dict[VulnClass, re.Pattern[str]] = {
    VulnClass.SQL: _SQL_PATTERNS,
    VulnClass.SSTI: _SSTI_PATTERNS,
    VulnClass.DESERIALIZE: _DESERIALIZE_PATTERNS,
    VulnClass.SSRF: _SSRF_PATTERNS,
    VulnClass.CMDI: _CMDI_PATTERNS,
    VulnClass.GENERIC: _GENERIC_PATTERNS,
}


def _check_strong_signals(
    body: str, vuln_class: VulnClass, payload: str = "",
) -> Optional[Tuple[str, str]]:
    """Check for strong pattern-based signals in the response body.

    Returns (matched_pattern, reason) or None.
    """
    # RCE / eval: check if arithmetic payload result appears in response
    if vuln_class == VulnClass.RCE and payload:
        stripped = payload.strip()
        expected = _EVAL_ARITHMETIC.get(stripped)
        # Arithmetic result check (e.g. 7*7 → 49)
        if expected and expected in body:
            return expected, f"Strong signal: eval arithmetic confirmed — payload '{payload}' produced '{expected}' in response"

        # Exception-based reflection check (e.g. 1/0 → ZeroDivisionError)
        match = _RCE_EVAL_STRONG_PATTERNS.search(body)
        if match:
            return match.group(0)[:80], f"Strong signal: eval exception reflected — '{match.group(0)[:60]}' in response"

        # Marker reflection check
        if "VULNREACH_MARKER" in payload and "VULNREACH_MARKER" in body:
            return "VULNREACH_MARKER", "Strong signal: eval marker reflected in response body — eval() returns output to HTTP response"

    # Django debug page detection for SQL injection
    if vuln_class == VulnClass.SQL:
        has_exception_type = "Exception Type:" in body
        has_exception_value = "Exception Value:" in body
        if has_exception_type and has_exception_value:
            # Django debug page with SQL-related exception
            sql_match = _SQL_PATTERNS.search(body)
            if sql_match:
                return sql_match.group(0)[:80], (
                    f"Strong signal: Django debug page with SQL error — "
                    f"{sql_match.group(0)[:60]}"
                )
            # Even without a SQL pattern match, if the payload is reflected
            # in the debug page, that's a strong signal
            if payload and payload in body:
                return "Django debug page + payload reflected", (
                    "Strong signal: Django debug page reflecting vulnerable "
                    "parameter value — confirms input reaches error path"
                )

    # Check the specific vuln class patterns first
    pattern = _VULN_CLASS_PATTERNS.get(vuln_class)
    if pattern:
        match = pattern.search(body)
        if match:
            return match.group(0)[:80], f"Strong signal: {vuln_class.value} pattern matched: {match.group(0)[:60]}"

    # Also check generic error patterns for any vuln class
    if vuln_class != VulnClass.GENERIC:
        match = _GENERIC_PATTERNS.search(body)
        if match:
            return match.group(0)[:80], f"Generic error pattern matched: {match.group(0)[:60]}"

    return None


# ---------------------------------------------------------------------------
# Step 2 — Medium signal checks (status/body anomalies)
# ---------------------------------------------------------------------------

# Body length difference threshold for medium signal
_BODY_LEN_DIFF_THRESHOLD = 0.20  # 20%


def _check_medium_signals(
    result: IterationResult,
    baseline_status: Optional[int] = None,
    baseline_body_len: Optional[int] = None,
    vuln_class: Optional[VulnClass] = None,
) -> Optional[str]:
    """Check for medium-strength anomalies.

    Returns a reason string if a medium signal is detected, None otherwise.
    """
    reasons: List[str] = []

    # RCE / eval: error messages that reveal eval context (medium, not strong)
    if vuln_class == VulnClass.RCE:
        match = _RCE_ERROR_PATTERNS.search(result.response_body)
        if match:
            reasons.append(
                f"Eval context revealed: {match.group(0)[:60]} — confirms eval() is executing input"
            )

    # Status code change from baseline
    if baseline_status is not None and result.response_status != baseline_status:
        reasons.append(
            f"Status changed from {baseline_status} to {result.response_status}"
        )

    # Body length anomaly
    if baseline_body_len is not None and baseline_body_len > 0:
        current_len = len(result.response_body)
        diff_ratio = abs(current_len - baseline_body_len) / baseline_body_len
        if diff_ratio > _BODY_LEN_DIFF_THRESHOLD:
            reasons.append(
                f"Body length changed by {diff_ratio:.0%} "
                f"(baseline={baseline_body_len}, current={current_len})"
            )

    # 5xx status is suspicious on its own
    if result.response_status >= 500:
        reasons.append(f"Server error status {result.response_status}")

    return "; ".join(reasons) if reasons else None


# ---------------------------------------------------------------------------
# Step 3 — LLM judge
# ---------------------------------------------------------------------------

_LLM_JUDGE_PROMPT = """\
Here is the HTTP response to the last payload:
Status: {status}
Body (first 500 chars): {body}
Response time: {time_ms:.0f}ms

Based on this response, what is your assessment?
Respond ONLY in JSON:
{{"outcome": "CONFIRMED|MUTATE|STOP", "confidence": "high|medium|low", "reason": "...", "signal_strength": "medium|weak", "suggested_payload": "..." or null}}"""


def _ask_llm_judge(
    result: IterationResult,
    llm: LLMClient,
    session_id: str,
) -> AnalysisDecision:
    """Ask the LLM to judge the response and decide next action.

    Falls back to MUTATE if the LLM response can't be parsed.
    """
    prompt = _LLM_JUDGE_PROMPT.format(
        status=result.response_status,
        body=result.response_body[:500],
        time_ms=result.response_time_ms,
    )

    # Use a minimal system prompt for the judge — the session already has context
    system = "You are analysing HTTP responses for vulnerability confirmation. Respond ONLY in JSON."

    try:
        raw = llm.chat(session_id, system, prompt)
        return _parse_llm_decision(raw)
    except Exception as exc:
        logger.warning(f"[response_analyser] LLM judge call failed: {exc}")
        return AnalysisDecision(
            outcome=Outcome.MUTATE,
            confidence="low",
            reason=f"LLM judge error: {exc}",
            signal_strength="weak",
        )


def _parse_llm_decision(raw: str) -> AnalysisDecision:
    """Parse the LLM judge's JSON response into an AnalysisDecision.

    Falls back to MUTATE if parsing fails.
    """
    text = raw.strip()
    # Strip code fences
    if text.startswith("```"):
        lines = text.split("\n")
        lines = [ln for ln in lines if not ln.strip().startswith("```")]
        text = "\n".join(lines).strip()

    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        # Try regex extraction
        match = re.search(r"\{[^{}]*\}", raw, re.DOTALL)
        if match:
            try:
                data = json.loads(match.group(0))
            except json.JSONDecodeError:
                logger.warning("[response_analyser] Could not parse LLM judge JSON")
                return AnalysisDecision(
                    outcome=Outcome.MUTATE,
                    confidence="low",
                    reason="LLM response not parseable as JSON",
                    signal_strength="weak",
                )
        else:
            return AnalysisDecision(
                outcome=Outcome.MUTATE,
                confidence="low",
                reason="LLM response not parseable as JSON",
                signal_strength="weak",
            )

    if not isinstance(data, dict):
        return AnalysisDecision(
            outcome=Outcome.MUTATE,
            confidence="low",
            reason="LLM returned non-object JSON",
            signal_strength="weak",
        )

    # Map outcome string to Outcome enum
    outcome_str = (data.get("outcome") or "MUTATE").upper()
    outcome_map = {
        "CONFIRMED": Outcome.CONFIRMED,
        "MUTATE": Outcome.MUTATE,
        "STOP": Outcome.STOP,
    }
    outcome = outcome_map.get(outcome_str, Outcome.MUTATE)

    return AnalysisDecision(
        outcome=outcome,
        confidence=data.get("confidence", "low"),
        reason=data.get("reason", "LLM judge decision"),
        signal_strength=data.get("signal_strength", "weak"),
        suggested_payload=data.get("suggested_payload"),
    )


# ---------------------------------------------------------------------------
# Top-level analyser function (the ResponseAnalyser callback)
# ---------------------------------------------------------------------------

_TIMING_PAYLOAD_KEYWORDS = ("sleep", "SLEEP", "WAITFOR", "pg_sleep", "BENCHMARK")

_TIMING_THRESHOLD_MS = 4000
_TIMING_BASELINE_MAX_MS = 1000


def analyse(
    iteration_result: IterationResult,
    flow: AttackFlow,
    llm: LLMClient,
    session_id: str,
    baseline_status: Optional[int] = None,
    baseline_body_len: Optional[int] = None,
    baseline_response_time_ms: float = 0,
) -> AnalysisDecision:
    """Analyse an HTTP response to decide the next action.

    Three-step pipeline:
      1a. Timing-based strong signal check
      1b. Strong signal check — pattern match → CONFIRMED immediately
      2.  Medium signal check — status/body anomaly detection
      3.  LLM judge — for medium/weak signals, ask the LLM

    Args:
        iteration_result: The HTTP response data from the probe.
        flow:             The AttackFlow being tested.
        llm:              LLM client for the judge step.
        session_id:       Session ID for LLM conversation continuity.
        baseline_status:  Expected normal status code (optional).
        baseline_body_len: Expected normal response body length (optional).
        baseline_response_time_ms: Baseline response time from a benign request.

    Returns:
        An AnalysisDecision with outcome, confidence, reason, and signal info.
    """
    body = iteration_result.response_body
    payload = iteration_result.payload

    # Step 1a: timing-based strong signal
    if (
        iteration_result.response_time_ms > _TIMING_THRESHOLD_MS
        and baseline_response_time_ms < _TIMING_BASELINE_MAX_MS
        and any(kw in payload for kw in _TIMING_PAYLOAD_KEYWORDS)
    ):
        reason = (
            f"Time-based confirmation: response took "
            f"{iteration_result.response_time_ms:.0f}ms vs baseline "
            f"{baseline_response_time_ms:.0f}ms"
        )
        logger.info(f"[response_analyser] Timing signal for {flow.id}: {reason}")
        return AnalysisDecision(
            outcome=Outcome.CONFIRMED,
            confidence="high",
            reason=reason,
            signal_strength="strong",
        )

    # Step 1b: strong signals (no LLM needed)
    strong = _check_strong_signals(body, flow.vulnerability_class, payload)
    if strong:
        matched_pattern, reason = strong
        logger.info(
            f"[response_analyser] Strong signal for {flow.id}: {matched_pattern}"
        )
        return AnalysisDecision(
            outcome=Outcome.CONFIRMED,
            confidence="high",
            reason=reason,
            signal_strength="strong",
        )

    # Step 2: medium signals
    medium_reason = _check_medium_signals(
        iteration_result, baseline_status, baseline_body_len,
        vuln_class=flow.vulnerability_class,
    )
    if medium_reason:
        logger.info(
            f"[response_analyser] Medium signal for {flow.id}: {medium_reason}"
        )
        # Pass to LLM for final judgement with medium signal context
        return _ask_llm_judge(iteration_result, llm, session_id)

    # Step 3: no strong/medium signals — ask LLM anyway for weak signal assessment
    return _ask_llm_judge(iteration_result, llm, session_id)
