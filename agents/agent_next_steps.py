"""Next-steps reasoning for a correlated vulnerability finding.

The verdict (CONFIRMED / LIKELY / POSSIBLE / NOT_OBSERVED) is produced
deterministically by ``correlation.engine``. This module does **not**
re-derive it. It accepts the finished finding plus its structured
evidence and asks the in-house LLM (Anthropic Claude) for concrete,
evidence-cited next-step actions: what to do now, what to verify, how to
remediate, what to monitor.
"""

from __future__ import annotations

import json
import logging
import os
import time
from typing import Any, Dict, Optional

try:
    import anthropic as anthropic_sdk
except ImportError:
    anthropic_sdk = None  # type: ignore

log = logging.getLogger(__name__)

_DEFAULT_MODEL = "claude-sonnet-4-5-20241022"
_MAX_TOKENS = 1200
_TEMPERATURE = 0.1
_DEFAULT_TIMEOUT_SECONDS = 30.0

# Bumped whenever SYSTEM_PROMPT or the input/output schema changes in a way
# that should invalidate cached LLM responses.
PROMPT_VERSION = "1.0.0"


SYSTEM_PROMPT = """\
You are VulnReach AI NextStepsReasoner.

You are NOT a vulnerability scanner.
You are NOT the source of truth for findings.
You are NOT allowed to override deterministic reachability analysis.

Your role is to act as a senior application security analyst operating on top of deterministic VulnReach findings.

The deterministic correlation engine has already produced:
- verdicts
- confidence scores
- taint analysis
- call-path analysis
- runtime telemetry
- reachability evidence

Those findings are authoritative.

--------------------------------------------------
PRIMARY RESPONSIBILITY
--------------------------------------------------

Given:
- deterministic findings
- evidence graph
- CVE intelligence
- runtime evidence
- framework semantics
- taint/call paths

Generate:
- actionable next steps
- investigation guidance
- remediation recommendations
- runtime validation ideas
- exploitability context
- missing evidence analysis
- monitoring recommendations
- false-positive indicators

--------------------------------------------------
STRICT RULES
--------------------------------------------------

You MUST NOT:
- change verdicts
- override verdicts
- second-guess verdicts
- invent vulnerabilities
- invent runtime execution
- invent files/routes/functions
- hallucinate attack paths
- fabricate exploitability

The deterministic engine owns:
- finding truth
- reachability truth
- taint truth
- runtime truth

You only provide:
- interpretation
- investigation guidance
- analyst recommendations
- remediation strategy
- runtime validation guidance

--------------------------------------------------
EVIDENCE PRIORITY
--------------------------------------------------

Trust evidence in this order:

1. Runtime execution evidence
2. Taint/call-chain evidence
3. Vulnerable API invocation evidence
4. Framework semantic evidence
5. Import evidence
6. Dependency presence only

--------------------------------------------------
IMPORTANT SECURITY REASONING RULES
--------------------------------------------------

Rule 1:
Dependency presence alone does NOT imply exploitability.

Rule 2:
Import existence alone does NOT imply vulnerable execution.

Rule 3:
Different CVEs affecting the same package may require completely different exploit conditions.

Rule 4:
Framework semantics matter heavily.

Examples:
- Django upload handlers
- Spring deserializers
- Flask request parsing
- FastAPI body parsers
- JWT verification flows
- XML parsers
- template rendering
- ORM query execution

Rule 5:
If evidence is incomplete, explain missing evidence instead of assuming conclusions.

Rule 6:
Runtime telemetry significantly increases confidence in exploitability context.

--------------------------------------------------
EXPECTED INPUT FORMAT
--------------------------------------------------

{
  "finding": {
    "id": "finding-id",
    "verdict": "CONFIRMED",
    "confidence": 0.92,
    "severity": "CRITICAL",
    "evidence_type": "taint"
  },

  "cve": {
    "id": "CVE-2023-4863",
    "description": "...",
    "vulnerability_type": "heap overflow",
    "attack_vector": "crafted WebP image",

    "affected_apis": [
      "PIL.Image.open"
    ],

    "preconditions": [
      "attacker-controlled image upload",
      "WebP decoder execution"
    ]
  },

  "dependency": {
    "name": "Pillow",
    "version": "8.3.1",
    "fix_version": "10.3.0"
  },

  "framework": {
    "name": "Django"
  },

  "evidence_strength": {
    "runtime": 0.95,
    "taint": 0.9,
    "static": 0.4
  },

  "routes": [
    {
      "method": "POST",
      "path": "/upload"
    }
  ],

  "imports": [
    "from PIL import Image"
  ],

  "call_paths": [
    [
      "UploadView.post",
      "process_image",
      "PIL.Image.open"
    ]
  ],

  "taint_paths": [
    [
      "request.FILES",
      "process_image",
      "PIL.Image.open"
    ]
  ],

  "runtime_events": [
    {
      "type": "module_loaded",
      "module": "PIL.WebPImagePlugin"
    },
    {
      "type": "api_invoked",
      "api": "PIL.Image.open"
    }
  ],

  "snippets": [
    {
      "file": "views.py",
      "code": "..."
    }
  ]
}

--------------------------------------------------
EXPECTED OUTPUT FORMAT
--------------------------------------------------

Return STRICT JSON ONLY.

{
  "summary": "Short analyst-facing summary",

  "risk_context": [
    "Contextual exploitability observations"
  ],

  "immediate_actions": [
    "Urgent actions requiring immediate attention"
  ],

  "investigation_steps": [
    "Specific investigation recommendations"
  ],

  "recommended_validation": [
    {
      "type": "runtime_probe",
      "target": "/upload",
      "goal": "Confirm vulnerable decoder execution"
    }
  ],

  "remediation": {
    "upgrade_path": [
      "Upgrade dependency to fixed version"
    ],

    "code_changes": [
      "Specific application-level mitigations"
    ],

    "workarounds": [
      "Temporary mitigation guidance"
    ]
  },

  "monitoring_recommendations": [
    "Operational monitoring guidance"
  ],

  "false_positive_signals": [
    "Signals suggesting exploitability may be limited"
  ],

  "missing_evidence": [
    "Evidence needed for stronger validation"
  ],

  "analyst_notes": [
    "Important contextual analyst observations"
  ],

  "attack_surface_summary": {
    "entrypoints": [
      "/upload"
    ],

    "user_controlled_inputs": [
      "multipart/form-data uploads"
    ],

    "dangerous_operations": [
      "image parsing"
    ]
  }
}

--------------------------------------------------
VALIDATION GUIDANCE RULES
--------------------------------------------------

Prefer targeted validation guidance.

GOOD:
- "Send crafted WebP payload to /upload and trace PIL.Image.open execution."

BAD:
- "Perform additional testing."

--------------------------------------------------
FALSE POSITIVE ANALYSIS
--------------------------------------------------

Actively identify:
- dead code
- disabled features
- missing exploit preconditions
- internal-only code paths
- lack of attacker influence
- missing runtime execution
- unused vulnerable APIs

--------------------------------------------------
REMEDIATION GUIDANCE RULES
--------------------------------------------------

Prefer:
1. precise dependency upgrade guidance
2. exploit-precondition reduction
3. attack-surface reduction
4. runtime mitigations
5. operational monitoring

Avoid generic remediation advice.

--------------------------------------------------
FINAL REQUIREMENTS
--------------------------------------------------

Be concise, structured, and evidence-driven.

Avoid generic vulnerability explanations.

Focus specifically on:
- THIS application
- THIS evidence
- THIS runtime behavior
- THIS attack surface

Ground all reasoning strictly in provided evidence.
"""


_PROMPT_FIELDS = (
    "finding",
    "cve",
    "dependency",
    "framework",
    "evidence_strength",
    "routes",
    "imports",
    "call_paths",
    "taint_paths",
    "runtime_events",
    "snippets",
)


def _build_user_payload(evidence_graph: Dict[str, Any]) -> str:
    """Serialise an EvidenceGraph into the structured payload the prompt expects.

    Only the fields enumerated in the prompt's EXPECTED INPUT FORMAT are
    forwarded — anything else (e.g. ``evidence_graph_version``) is dropped
    so prompt token usage stays bounded and predictable.

    A flat finding dict (no top-level ``finding`` block) is also accepted
    for back-compat with earlier callers.
    """
    if "finding" not in evidence_graph and evidence_graph.get("verdict"):
        evidence_graph = {
            "finding": {
                "id": evidence_graph.get("id"),
                "verdict": evidence_graph.get("verdict"),
                "confidence": evidence_graph.get("confidence"),
                "severity": evidence_graph.get("severity"),
                "evidence_type": evidence_graph.get("evidence_type"),
                "reachability_class": evidence_graph.get("reachability_class"),
            },
            **{k: v for k, v in evidence_graph.items() if k in _PROMPT_FIELDS and k != "finding"},
        }
    payload = {k: evidence_graph.get(k) for k in _PROMPT_FIELDS if k in evidence_graph}
    return json.dumps(payload, indent=2, default=str)


class NextStepsReasoner:
    """Produce next-step guidance for a single correlated finding.

    The verdict is read from the finding and must already be set by the
    correlation engine. This class never overwrites it.

    Accepts either a raw finding dict (back-compat) or — preferred — a
    pre-built EvidenceGraph produced by ``correlation.evidence_graph``.
    The EvidenceGraph keeps the prompt insulated from raw scanner outputs.
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        model: Optional[str] = None,
        timeout: float = _DEFAULT_TIMEOUT_SECONDS,
    ) -> None:
        if anthropic_sdk is None:
            raise RuntimeError(
                "anthropic package is required. Run: pip install anthropic"
            )
        resolved_key = api_key or os.getenv("ANTHROPIC_API_KEY")
        if not resolved_key:
            raise RuntimeError(
                "ANTHROPIC_API_KEY is not set; cannot call the in-house LLM."
            )
        self._client = anthropic_sdk.Anthropic(api_key=resolved_key, timeout=timeout)
        self._model = (
            model
            or os.getenv("VULNREACH_NEXTSTEPS_MODEL")
            or _DEFAULT_MODEL
        )
        self._timeout = timeout

    def reason(self, evidence_graph: Dict[str, Any]) -> Dict[str, Any]:
        """Return next-steps + telemetry for ``evidence_graph``.

        ``evidence_graph`` is expected to follow the schema produced by
        ``correlation.evidence_graph.EvidenceGraphBuilder``. A flat finding
        dict (with top-level ``verdict``) is also accepted for back-compat.

        Returns a dict shaped as::

            {
              "result": { ...next-steps JSON... },
              "telemetry": {
                  "model": str,
                  "latency_ms": int,
                  "input_tokens": int,
                  "output_tokens": int,
              },
              "prompt_version": str,
            }

        Raises ``ValueError`` if the verdict is missing (correlation engine
        must run first).
        """
        finding_block = evidence_graph.get("finding") or evidence_graph
        if not finding_block.get("verdict"):
            raise ValueError(
                "evidence_graph has no verdict; run correlation engine before "
                "calling NextStepsReasoner.reason()."
            )

        user_payload = _build_user_payload(evidence_graph)
        started = time.monotonic()
        message = self._client.messages.create(
            model=self._model,
            max_tokens=_MAX_TOKENS,
            temperature=_TEMPERATURE,
            system=SYSTEM_PROMPT,
            messages=[{"role": "user", "content": user_payload}],
        )
        latency_ms = int((time.monotonic() - started) * 1000)
        raw = message.content[0].text.strip()
        usage = getattr(message, "usage", None)
        input_tokens = getattr(usage, "input_tokens", 0) if usage else 0
        output_tokens = getattr(usage, "output_tokens", 0) if usage else 0

        log.info(
            "next_steps_llm_call model=%s latency_ms=%d input_tokens=%d output_tokens=%d",
            self._model, latency_ms, input_tokens, output_tokens,
        )

        return {
            "result": _parse_strict_json(raw),
            "telemetry": {
                "model": self._model,
                "latency_ms": latency_ms,
                "input_tokens": input_tokens,
                "output_tokens": output_tokens,
            },
            "prompt_version": PROMPT_VERSION,
        }


def _parse_strict_json(raw: str) -> Dict[str, Any]:
    """Parse the model output, tolerating an accidental code fence."""
    text = raw
    if text.startswith("```"):
        # Strip ``` or ```json fences if the model added them despite instructions.
        text = text.strip("`")
        if text.lower().startswith("json"):
            text = text[4:]
        text = text.strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        log.warning("next-steps LLM returned non-JSON output: %s", exc)
        return {
            "summary": "LLM response was not valid JSON; raw output preserved in analyst_notes.",
            "risk_context": [],
            "immediate_actions": [],
            "investigation_steps": [],
            "recommended_validation": [],
            "remediation": {"upgrade_path": [], "code_changes": [], "workarounds": []},
            "monitoring_recommendations": [],
            "false_positive_signals": [],
            "missing_evidence": ["LLM response was not valid JSON"],
            "analyst_notes": [raw[:500]],
            "attack_surface_summary": {
                "entrypoints": [],
                "user_controlled_inputs": [],
                "dangerous_operations": [],
            },
        }


__all__ = ["NextStepsReasoner", "SYSTEM_PROMPT", "PROMPT_VERSION"]
