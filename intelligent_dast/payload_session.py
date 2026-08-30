"""Core steering loop for a single AttackFlow.

Class: PayloadSession
  - Builds a system prompt from flow metadata
  - Asks the LLM for payloads (one per iteration)
  - Fires HTTP requests via `requests`
  - Passes responses to a response_analyser callback
  - Loops until CONFIRMED, STOP, or max_iterations exhausted

No async — uses synchronous `requests` for simplicity.
"""

from __future__ import annotations

import json
import logging
import re
import time
from datetime import datetime, timezone
from typing import Callable, Dict, List, Optional, Tuple
from urllib.parse import urlencode

try:
    import requests as requests_lib
except ImportError:
    requests_lib = None  # type: ignore

from .models import (
    AnalysisDecision,
    AttackFlow,
    Finding,
    HttpContext,
    HttpMethod,
    IterationResult,
    Outcome,
    ParamLocation,
)
from .llm_client import LLMClient

logger = logging.getLogger(__name__)

# Type alias for the response analyser callback
ResponseAnalyser = Callable[..., AnalysisDecision]

# Trim response bodies stored in IterationResult
_BODY_SNIPPET_LEN = 2000

# Request timeout in seconds
_REQUEST_TIMEOUT = 15


def _build_system_prompt(flow: AttackFlow, ctx: HttpContext) -> str:
    """Build the system prompt from flow + context metadata."""
    parts = [
        "You are a security testing assistant performing controlled vulnerability validation.\n"
        "You are given a confirmed taint flow from static analysis. Your job is to generate HTTP payloads\n"
        "that will confirm whether the vulnerability is exploitable.\n",
        f"\nVulnerability: {flow.vulnerability_class.value}",
        f"Source: {flow.source_code}",
        f"Sink: {flow.sink_code}",
        f"Parameter: {ctx.param_name} (location: {ctx.param_location.value})",
    ]

    # Taint propagation path — shows transformations applied to input
    if flow.steps:
        parts.append("\nTaint propagation path (how input reaches the sink):")
        for i, step in enumerate(flow.steps, 1):
            snippet = step.code_snippet or step.description
            if snippet:
                parts.append(f"  Step {i}: {snippet}")
        parts.append(f"  Sink: {flow.sink_code}")

    # Variable path — which variables carry the taint
    if flow.variable_path:
        parts.append(f"\nVariable path: {' → '.join(flow.variable_path)}")

    # Indirect source — input enters via function parameter, not request object
    if ctx.source_type == "indirect":
        parts.append(
            f"\nNote: Input enters via function parameter, not directly from a request object. "
            f"The actual HTTP parameter name may differ. Try common parameter names based "
            f"on the variable name '{ctx.param_name}' and the vulnerability class."
        )

    # Inferred URL warning
    if ctx.url_confidence == "inferred":
        parts.append(
            "\nNote: URL path was inferred from source code, not confirmed. "
            "If you get consistent 404s, the endpoint path may be wrong."
        )

    # Endpoint description from OpenAPI spec
    if ctx.spec_description:
        parts.append(f"\nEndpoint note from spec: {ctx.spec_description}")

    parts.append(
        "\nRules:\n"
        "- Generate ONE payload per response\n"
        '- Respond ONLY in JSON: {"payload": "...", "reasoning": "..."}\n'
        "- Payloads must be targeted to the specific sink function, not generic\n"
        "- Study the taint propagation path carefully — understand what transformations\n"
        "  are applied to your input before it reaches the sink, and craft payloads that survive them\n"
        "- For SSTI: use {{7*7}} style detection first\n"
        "- For DESERIALIZE (yaml): use !!python/object style\n"
        "- For SSRF: use internal addresses like 127.0.0.1\n"
        "- For SQL: use error-based detection first (single quote, SLEEP, etc.)\n"
        "  This Django app may have DEBUG=True. A successful SQL injection will likely trigger\n"
        "  a database error that Django renders as a full debug page containing\n"
        "  'Exception Type', 'Exception Value', and the raw SQL query.\n"
        "  Look for these strings in the response body — they are strong confirmation.\n"
        "- For CMDI: try command separators like ; id, | id, && id, $(id)\n"
        "- For eval() sinks: first try `1/0` to trigger a ZeroDivisionError.\n"
        "  If the error appears in the response body, that is strong confirmation.\n"
        "  Then try `[][999]` for IndexError, or `\"VULNREACH_MARKER_7x9k\"` for reflection.\n"
        "  Do NOT use timing-based payloads for eval — they cannot be confirmed in-band.\n"
        "  Do NOT confirm based on response time differences under 200ms.\n"
    )

    return "\n".join(parts)


def _build_first_message(flow: AttackFlow, ctx: HttpContext) -> str:
    """Build the initial user message with full flow context."""
    return (
        f"Target endpoint: {ctx.method.value} {ctx.url}\n"
        f"Parameter: {ctx.param_name} (location: {ctx.param_location.value})\n"
        f"Vulnerability class: {flow.vulnerability_class.value}\n"
        f"Source code: {flow.source_code}\n"
        f"Sink code: {flow.sink_code}\n"
        f"Call chain: {' → '.join(flow.call_chain)}\n"
        f"Confidence: {flow.confidence}\n\n"
        "Generate the first payload to test this flow."
    )


def _build_followup_message(
    iteration: int,
    prev_result: IterationResult,
    decision: AnalysisDecision,
) -> str:
    """Build a follow-up message after a MUTATE decision."""
    parts = [
        f"Iteration {iteration} result:",
        f"  Status: {prev_result.response_status}",
        f"  Response body (truncated): {prev_result.response_body[:500]}",
        f"  Response time: {prev_result.response_time_ms:.0f}ms",
        f"\nAnalysis: {decision.reason}",
        f"Signal strength: {decision.signal_strength}",
    ]
    if decision.suggested_payload:
        parts.append(f"Suggested next payload hint: {decision.suggested_payload}")
    parts.append("\nGenerate the next payload.")
    return "\n".join(parts)


def _parse_llm_payload(raw: str) -> Optional[str]:
    """Extract the payload string from LLM JSON response.

    Tries to parse JSON; falls back to extracting a payload field
    from the raw text if strict parsing fails.
    """
    # Strip markdown code fences if present
    text = raw.strip()
    if text.startswith("```"):
        lines = text.split("\n")
        # Remove first and last lines (fences)
        lines = [ln for ln in lines if not ln.strip().startswith("```")]
        text = "\n".join(lines).strip()

    try:
        data = json.loads(text)
        if isinstance(data, dict) and "payload" in data:
            return str(data["payload"])
    except json.JSONDecodeError:
        pass

    # Fallback: regex for "payload": "..."
    import re
    match = re.search(r'"payload"\s*:\s*"((?:[^"\\]|\\.)*)"', raw)
    if match:
        return match.group(1).encode().decode("unicode_escape")

    logger.warning("[payload_session] Could not parse payload from LLM response")
    return None


# ---------------------------------------------------------------------------
# CSRF token extraction
# ---------------------------------------------------------------------------

_CSRF_COOKIE_RE = re.compile(r"csrftoken=([^;\s]+)")
_CSRF_INPUT_RE = re.compile(
    r'<input[^>]+name=["\']csrfmiddlewaretoken["\'][^>]+value=["\']([^"\']+)["\']',
    re.IGNORECASE,
)


def _extract_csrf_from_headers(resp_headers: Dict[str, str]) -> str:
    """Extract CSRF token from Set-Cookie header."""
    for key, value in resp_headers.items():
        if key.lower() == "set-cookie":
            match = _CSRF_COOKIE_RE.search(value)
            if match:
                return match.group(1)
    return ""


def _extract_csrf_from_body(body: str) -> str:
    """Extract CSRF token from hidden input in HTML body."""
    match = _CSRF_INPUT_RE.search(body)
    return match.group(1) if match else ""


def _fire_request(
    ctx: HttpContext,
    payload: str,
    extra_headers: Optional[Dict[str, str]] = None,
    extra_cookies: Optional[Dict[str, str]] = None,
    csrf_token: str = "",
) -> Tuple[int, str, Dict[str, str], float]:
    """Fire an HTTP request with the payload injected per param_location.

    If csrf_token is provided and the method is POST, CSRF headers/cookies/body
    fields are automatically injected (Django convention).

    Returns (status_code, body, response_headers, elapsed_ms).
    """
    if requests_lib is None:
        raise RuntimeError("requests package is required. Run: pip install requests")

    headers = {**ctx.base_headers, **(extra_headers or {})}
    cookies = {**ctx.base_cookies, **(extra_cookies or {})}
    url = ctx.url
    body: Optional[str | Dict] = None
    data: Optional[str] = None

    # Inject CSRF token for POST requests
    if csrf_token and ctx.method == HttpMethod.POST:
        headers["X-CSRFToken"] = csrf_token
        cookies["csrftoken"] = csrf_token

    if ctx.param_location == ParamLocation.QUERY:
        sep = "&" if "?" in url else "?"
        url = f"{url}{sep}{urlencode({ctx.param_name: payload})}"

    elif ctx.param_location == ParamLocation.BODY_JSON:
        headers.setdefault("Content-Type", "application/json")
        body = {**ctx.extra_params, ctx.param_name: payload}

    elif ctx.param_location == ParamLocation.BODY_FORM:
        headers.setdefault("Content-Type", "application/x-www-form-urlencoded")
        form_params = {**ctx.extra_params, ctx.param_name: payload}
        # Add CSRF token to form body for Django
        if csrf_token and ctx.method == HttpMethod.POST:
            form_params["csrfmiddlewaretoken"] = csrf_token
        data = urlencode(form_params)

    elif ctx.param_location == ParamLocation.PATH:
        url = re.sub(r"[{<]\w+[}>]", payload, url, count=1)

    elif ctx.param_location == ParamLocation.HEADER:
        headers[ctx.param_name] = payload

    elif ctx.param_location == ParamLocation.COOKIE:
        cookies[ctx.param_name] = payload

    method = ctx.method.value

    # Debug: log exactly what we're sending for POST requests
    if method == "POST":
        if isinstance(body, dict):
            body_keys = list(body.keys())
        elif data:
            body_keys = [p.split("=")[0] for p in data.split("&") if "=" in p]
        else:
            body_keys = []
        logger.debug(
            f"[payload_session] flow={ctx.flow_id}: "
            f"POST body keys={body_keys}, "
            f"csrf_in_header={'X-CSRFToken' in headers}, "
            f"csrf_in_cookie={'csrftoken' in cookies}"
        )

    start = time.monotonic()

    try:
        resp = requests_lib.request(
            method=method,
            url=url,
            headers=headers,
            cookies=cookies,
            json=body,
            data=data,
            timeout=_REQUEST_TIMEOUT,
            allow_redirects=True,
        )
        elapsed_ms = (time.monotonic() - start) * 1000
        resp_body = resp.text[:_BODY_SNIPPET_LEN]
        resp_headers = dict(resp.headers)
        return resp.status_code, resp_body, resp_headers, elapsed_ms

    except requests_lib.RequestException as exc:
        elapsed_ms = (time.monotonic() - start) * 1000
        logger.warning(f"[payload_session] Request failed: {exc}")
        return 0, str(exc)[:_BODY_SNIPPET_LEN], {}, elapsed_ms


class PayloadSession:
    """Run the LLM-steered payload loop for a single AttackFlow.

    Args:
        flow:              The taint flow to probe.
        context:           HTTP context (URL, method, param location, etc.).
        llm:               LLM client instance.
        response_analyser: Callback that takes (IterationResult, AttackFlow)
                           and returns an AnalysisDecision.
        max_iterations:    Max probe attempts before giving up.
        extra_headers:     Additional headers (e.g. from AuthResolver).
        extra_cookies:     Additional cookies (e.g. from AuthResolver).
    """

    def __init__(
        self,
        flow: AttackFlow,
        context: HttpContext,
        llm: LLMClient,
        response_analyser: ResponseAnalyser,
        max_iterations: int = 5,
        extra_headers: Optional[Dict[str, str]] = None,
        extra_cookies: Optional[Dict[str, str]] = None,
    ) -> None:
        self._flow = flow
        self._ctx = context
        self._llm = llm
        self._analyser = response_analyser
        self._max_iterations = max_iterations
        self._extra_headers = extra_headers or {}
        self._extra_cookies = extra_cookies or {}

    def _measure_baseline(self) -> Tuple[int, int, float]:
        """Send a benign request to capture baseline status, body length, and response time."""
        status, body, _, elapsed_ms = _fire_request(
            self._ctx, "", self._extra_headers, self._extra_cookies,
        )
        logger.info(
            f"[payload_session] flow={self._flow.id} baseline: "
            f"status={status} body_len={len(body)} time={elapsed_ms:.0f}ms"
        )
        return status, len(body), elapsed_ms

    def _fetch_csrf_token(self) -> str:
        """Fetch a CSRF token via GET to the target endpoint.

        Tries GET to the endpoint URL first. If that returns 405,
        falls back to GET on the base URL (root path).

        Returns the token string, or "" if none found.
        """
        if requests_lib is None:
            return ""

        headers = {**self._ctx.base_headers, **self._extra_headers}
        cookies = {**self._ctx.base_cookies, **self._extra_cookies}

        # Try the endpoint URL first
        urls_to_try = [self._ctx.url]
        # Fall back to base URL (strip path)
        base = re.match(r"(https?://[^/]+)", self._ctx.url)
        if base:
            base_url = base.group(1) + "/"
            if base_url != self._ctx.url and base_url != self._ctx.url + "/":
                urls_to_try.append(base_url)

        for url in urls_to_try:
            try:
                resp = requests_lib.get(
                    url, headers=headers, cookies=cookies,
                    timeout=_REQUEST_TIMEOUT, allow_redirects=True,
                )
            except requests_lib.RequestException:
                continue

            # Check Set-Cookie for csrftoken
            token = _extract_csrf_from_headers(dict(resp.headers))
            if not token:
                token = _extract_csrf_from_body(resp.text[:_BODY_SNIPPET_LEN])
            if token:
                logger.info(
                    f"[payload_session] flow={self._flow.id}: "
                    f"CSRF token obtained from {url}"
                )
                return token

        logger.debug(
            f"[payload_session] flow={self._flow.id}: no CSRF token found"
        )
        return ""

    def run(self) -> Tuple[Optional[Finding], List[IterationResult]]:
        """Execute the steering loop.

        Returns:
            (Finding or None, list of all IterationResults)
        """
        session_id = self._flow.id
        self._llm.new_session(session_id)

        system_prompt = _build_system_prompt(self._flow, self._ctx)
        results: List[IterationResult] = []

        # Measure baseline before probing (also serves as preflight check)
        baseline_status, baseline_body_len, baseline_time_ms = self._measure_baseline()

        # Preflight: skip unreachable endpoints
        if baseline_status in (404, 405):
            logger.info(
                f"[payload_session] flow={self._flow.id}: endpoint not reachable "
                f"(HTTP {baseline_status}) — skipping"
            )
            return None, []

        # Fetch CSRF token for POST endpoints (Django)
        csrf_token = ""
        if self._ctx.method == HttpMethod.POST:
            csrf_token = self._fetch_csrf_token()
            logger.debug(
                f"[payload_session] flow={self._flow.id}: "
                f"csrf_cookie={csrf_token[:16] + '…' if len(csrf_token) > 16 else csrf_token}, "
                f"csrf_token={csrf_token[:16] + '…' if len(csrf_token) > 16 else csrf_token}"
            )

        # Step 1: first message with full context
        user_msg = _build_first_message(self._flow, self._ctx)

        for i in range(1, self._max_iterations + 1):
            logger.info(
                f"[payload_session] flow={self._flow.id} iteration={i}/{self._max_iterations}"
            )

            # Ask LLM for payload
            llm_response = self._llm.chat(session_id, system_prompt, user_msg)
            payload = _parse_llm_payload(llm_response)

            if payload is None:
                logger.warning(
                    f"[payload_session] flow={self._flow.id} iter={i}: "
                    "LLM returned unparseable response, skipping iteration"
                )
                # Record a failed iteration
                results.append(IterationResult(
                    iteration=i,
                    payload="<parse_error>",
                    request_method=self._ctx.method.value,
                    request_url=self._ctx.url,
                ))
                # Try once more with a nudge
                user_msg = (
                    "Your previous response was not valid JSON. "
                    'Please respond ONLY with: {"payload": "...", "reasoning": "..."}'
                )
                continue

            # Fire HTTP request
            status, body, resp_headers, elapsed_ms = _fire_request(
                self._ctx, payload, self._extra_headers, self._extra_cookies,
                csrf_token=csrf_token,
            )

            iter_result = IterationResult(
                iteration=i,
                payload=payload,
                request_method=self._ctx.method.value,
                request_url=self._ctx.url,
                request_body=(
                    {self._ctx.param_name: payload}
                    if self._ctx.param_location in (
                        ParamLocation.BODY_JSON, ParamLocation.BODY_FORM
                    )
                    else None
                ),
                response_status=status,
                response_body=body,
                response_headers=resp_headers,
                response_time_ms=elapsed_ms,
            )
            results.append(iter_result)

            # Analyse response
            decision = self._analyser(
                iter_result, self._flow, self._llm, session_id,
                baseline_status=baseline_status,
                baseline_body_len=baseline_body_len,
                baseline_response_time_ms=baseline_time_ms,
            )

            logger.info(
                f"[payload_session] flow={self._flow.id} iter={i}: "
                f"outcome={decision.outcome.value} confidence={decision.confidence} "
                f"signal={decision.signal_strength}"
            )

            if decision.outcome == Outcome.CONFIRMED:
                request_snap = {
                    "method": iter_result.request_method,
                    "url": iter_result.request_url,
                    "body": iter_result.request_body,
                }
                if self._ctx.source_type == "indirect":
                    request_snap["entry_point_inferred"] = True

                finding = Finding(
                    flow_id=self._flow.id,
                    vulnerability_class=self._flow.vulnerability_class.value,
                    confirmed_at_iteration=i,
                    payload=payload,
                    evidence=decision.reason,
                    request_snapshot=request_snap,
                    response_snapshot={
                        "status": iter_result.response_status,
                        "body": iter_result.response_body[:500],
                        "time_ms": iter_result.response_time_ms,
                    },
                    timestamp=datetime.now(timezone.utc).isoformat(),
                )
                return finding, results

            if decision.outcome == Outcome.STOP:
                logger.info(
                    f"[payload_session] flow={self._flow.id}: STOP at iter {i} — "
                    f"{decision.reason}"
                )
                return None, results

            # MUTATE — build follow-up message and continue
            user_msg = _build_followup_message(i, iter_result, decision)

        # Exhausted all iterations
        logger.info(
            f"[payload_session] flow={self._flow.id}: exhausted {self._max_iterations} iterations"
        )
        return None, results
