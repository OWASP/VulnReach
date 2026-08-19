"""Top-level runner for the Intelligent DAST pipeline.

Orchestrates: flow parsing → auth resolution → HTTP context building →
payload sessions → findings collection.

Can be used as a library (`run_dast()`) or as a CLI entry point
(`python -m intelligent_dast.runner`).
"""

from __future__ import annotations

import argparse
import json
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

from .auth_resolver import AuthResolver
from .flow_parser import load_flows_from_file
from .http_context import build_http_context
from .llm_client import LLMClient
from .models import AttackFlow, Finding, IterationResult
from .payload_session import PayloadSession
from .response_analyser import analyse

from dataclasses import dataclass, field, asdict

logger = logging.getLogger(__name__)


@dataclass
class FlowResult:
    """Result of processing a single flow."""
    flow_id: str
    vulnerability_class: str
    endpoint: str
    finding: Optional[Finding] = None
    iterations: List[IterationResult] = field(default_factory=list)
    skipped: bool = False
    skip_reason: str = ""


def _load_openapi_spec(path: str) -> Optional[Dict[str, Any]]:
    """Load an OpenAPI spec from a JSON or YAML file."""
    p = Path(path)
    if not p.exists():
        logger.warning(f"[runner] OpenAPI spec not found: {path}")
        return None

    text = p.read_text(encoding="utf-8")
    if p.suffix in (".yaml", ".yml"):
        return yaml.safe_load(text)
    return json.loads(text)


def run_dast(
    taint_file: str,
    base_url: str,
    auth_config: Optional[str] = None,
    openapi_spec: Optional[str] = None,
    max_parallel: int = 1,
    llm_provider: str = "anthropic",
    llm_model: Optional[str] = None,
    max_iterations: int = 5,
    ollama_base_url: str = "http://localhost:11434",
) -> List[FlowResult]:
    """Run the full Intelligent DAST pipeline.

    Args:
        taint_file:     Path to tainter JSON output.
        base_url:       Target application base URL.
        auth_config:    Path to auth YAML config (optional).
        openapi_spec:   Path to OpenAPI spec file (optional).
        max_parallel:   Max concurrent flow sessions (default 1).
        llm_provider:   LLM provider ("anthropic" or "ollama").
        llm_model:      LLM model override (optional).
        max_iterations: Max iterations per flow (default 5).

    Returns:
        List of FlowResult objects (one per flow tested).
    """
    # 1. Parse taint flows
    flows, errors = load_flows_from_file(taint_file)
    if errors:
        for err in errors:
            logger.warning(f"[runner] Flow parse error: {err.flow_id} — {err.reason}")
    if not flows:
        logger.error("[runner] No valid flows to test")
        return []

    print(f"Loaded {len(flows)} flows ({len(errors)} parse errors)")

    # 2. Auth resolver
    auth = AuthResolver(config_path=auth_config)
    auth_headers, auth_cookies = auth.resolve()
    if auth_headers or auth_cookies:
        print(f"Auth: {len(auth_headers)} headers, {len(auth_cookies)} cookies")

    # 3. OpenAPI spec
    spec = None
    if openapi_spec:
        spec = _load_openapi_spec(openapi_spec)
        if spec:
            print(f"OpenAPI spec loaded: {len(spec.get('paths', {}))} paths")

    # 4. LLM client (shared across all sessions)
    llm = LLMClient(provider=llm_provider, model=llm_model, ollama_base_url=ollama_base_url)

    # 5. Process flows
    flow_results: List[FlowResult] = []

    def _process_flow(flow: AttackFlow) -> FlowResult:
        logger.debug(
            f"[runner] Queuing flow {flow.id} ({flow.vulnerability_class.value}) for session"
        )
        ctx = build_http_context(flow, base_url, openapi_spec=spec)
        ctx.base_headers.update(auth_headers)
        ctx.base_cookies.update(auth_cookies)

        endpoint = f"{ctx.method.value} {ctx.url}"

        session = PayloadSession(
            flow=flow,
            context=ctx,
            llm=llm,
            response_analyser=analyse,
            max_iterations=max_iterations,
            extra_headers=auth_headers,
            extra_cookies=auth_cookies,
        )

        print(f"  Testing flow {flow.id} ({flow.vulnerability_class.value}) ...", end=" ", flush=True)
        finding, results = session.run()

        fr = FlowResult(
            flow_id=flow.id,
            vulnerability_class=flow.vulnerability_class.value,
            endpoint=endpoint,
            finding=finding,
            iterations=results,
        )

        if finding:
            print(f"CONFIRMED (iter {finding.confirmed_at_iteration}, payload: {finding.payload[:40]})")
        elif not results:
            # Preflight returned 404/405 — skipped
            fr.skipped = True
            fr.skip_reason = "endpoint not reachable"
            print("SKIPPED (endpoint not reachable)")
        else:
            print(f"no finding ({len(results)} iterations)")

        return fr

    if max_parallel <= 1:
        for flow in flows:
            flow_results.append(_process_flow(flow))
    else:
        with ThreadPoolExecutor(max_workers=max_parallel) as executor:
            future_to_flow = {
                executor.submit(_process_flow, flow): flow
                for flow in flows
            }
            for future in as_completed(future_to_flow):
                try:
                    flow_results.append(future.result())
                except Exception as exc:
                    flow = future_to_flow[future]
                    logger.error(f"[runner] Flow {flow.id} failed: {exc}")

    return flow_results


def _print_summary(flow_results: List[FlowResult], parse_error_count: int = 0) -> None:
    """Print a detailed findings summary."""
    total = len(flow_results)
    confirmed = [fr for fr in flow_results if fr.finding]
    no_finding = [fr for fr in flow_results if not fr.finding and not fr.skipped]
    skipped = [fr for fr in flow_results if fr.skipped]

    sep = "\u2500" * 50

    print(f"\n{sep}")
    print("INTELLIGENT DAST RESULTS")
    print(sep)
    print(f"  Flows tested:           {total}")
    print(f"  Confirmed:              {len(confirmed)}")
    print(f"  No finding:             {len(no_finding)}")
    print(f"  Skipped (unreachable):  {len(skipped)}")
    if parse_error_count:
        print(f"  Skipped (parse error):  {parse_error_count}")

    if confirmed:
        print("\nCONFIRMED FINDINGS:")
        for i, fr in enumerate(confirmed, 1):
            f = fr.finding
            signal = f.evidence[:60] if f.evidence else "unknown"
            payload_display = f.payload[:50] + ".." if len(f.payload) > 50 else f.payload
            print(f"  [{i}] {fr.flow_id}  {fr.vulnerability_class.upper()}")
            print(f"      Payload:    {payload_display}")
            print(f"      Confirmed:  iteration {f.confirmed_at_iteration}")
            print(f"      Signal:     {signal}")
            print(f"      Endpoint:   {fr.endpoint}")
    else:
        print("\n  No vulnerabilities confirmed.")

    print(sep)


def _build_output_json(flow_results: List[FlowResult]) -> List[Dict[str, Any]]:
    """Build JSON output with full iteration history per flow."""
    output = []
    for fr in flow_results:
        entry: Dict[str, Any] = {
            "flow_id": fr.flow_id,
            "vulnerability_class": fr.vulnerability_class,
            "endpoint": fr.endpoint,
            "skipped": fr.skipped,
        }
        if fr.skipped:
            entry["skip_reason"] = fr.skip_reason
        if fr.finding:
            entry["confirmed"] = True
            entry["finding"] = fr.finding.to_dict()
        else:
            entry["confirmed"] = False

        # Full iteration history for replay
        entry["iterations"] = [asdict(it) for it in fr.iterations]
        output.append(entry)
    return output


def main() -> None:
    """CLI entry point."""
    parser = argparse.ArgumentParser(
        description="Intelligent DAST — LLM-steered vulnerability confirmation",
    )
    parser.add_argument(
        "--taint", required=True,
        help="Path to tainter JSON output file",
    )
    parser.add_argument(
        "--url", required=True,
        help="Target application base URL",
    )
    parser.add_argument(
        "--auth", default=None,
        help="Path to auth YAML config file",
    )
    parser.add_argument(
        "--openapi", default=None,
        help="Path to OpenAPI spec (JSON or YAML)",
    )
    parser.add_argument(
        "--parallel", type=int, default=1,
        help="Max parallel flow sessions (default: 1)",
    )
    parser.add_argument(
        "--provider", default="anthropic",
        choices=["anthropic", "ollama"],
        help="LLM provider (default: anthropic)",
    )
    parser.add_argument(
        "--model", default=None,
        help="LLM model override",
    )
    parser.add_argument(
        "--max-iterations", type=int, default=5,
        help="Max iterations per flow (default: 5)",
    )
    parser.add_argument(
        "--output", default="findings.json",
        help="Output findings file (default: findings.json)",
    )
    parser.add_argument(
        "--ollama-url", default="http://localhost:11434",
        help="Ollama server URL (default: http://localhost:11434)",
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true",
        help="Enable debug logging",
    )

    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
    )

    flow_results = run_dast(
        taint_file=args.taint,
        base_url=args.url,
        auth_config=args.auth,
        openapi_spec=args.openapi,
        max_parallel=args.parallel,
        llm_provider=args.provider,
        llm_model=args.model,
        max_iterations=args.max_iterations,
        ollama_base_url=args.ollama_url,
    )

    # Count parse errors for the summary
    _, parse_errors = load_flows_from_file(args.taint)
    _print_summary(flow_results, parse_error_count=len(parse_errors))

    # Write findings JSON with full iteration history
    output_path = Path(args.output)
    output_data = _build_output_json(flow_results)
    output_path.write_text(json.dumps(output_data, indent=2), encoding="utf-8")
    print(f"\nFindings written to {output_path}")


if __name__ == "__main__":
    main()
