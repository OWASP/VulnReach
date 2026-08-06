import json
import io
import re
from contextlib import redirect_stdout
from pathlib import Path
from typing import Any, Dict, List, Optional

from correlation.engine import reachability_verdict
from agents.reachability.taint_match import sink_modules, package_taint_reachable
from core.agent import BaseTool
from core.models import AgentResult, ReachabilityFinding, ScanContext
from agents.reachability.python_reachability_analyzer import (
    PythonReachabilityAnalyzer,
    run_python_reachability_analysis,
)

class PythonReachabilityAgent(BaseTool):
    tool_name = "python_reachability"

    def __init__(self, timeout_seconds: int = 300) -> None:
        self.timeout_seconds = timeout_seconds

    async def run(self, context: ScanContext) -> AgentResult:  # type: ignore[override]
        if not context.repo_path:
            return AgentResult(tool_name=self.tool_name, findings=[], metadata={"error": "missing_repo_path"})

        repo_path = Path(context.repo_path).resolve()
        if not repo_path.exists():
            return AgentResult(
                tool_name=self.tool_name,
                findings=[],
                metadata={"error": "repo_path_not_found", "repo_path": str(repo_path)},
            )

        vuln_inputs = self._build_vuln_inputs(context.vulnerabilities)
        if not vuln_inputs:
            return AgentResult(tool_name=self.tool_name, findings=[], metadata={"status": "no_vulns"})

        stdout_buf = io.StringIO()
        try:
            with redirect_stdout(stdout_buf):
                analyzer = PythonReachabilityAnalyzer(
                    str(repo_path), import_map=context.import_map or {})
                analyses = analyzer.analyze_vulnerability_reachability(vuln_inputs)
                report = analyzer.generate_report(analyses)
        except Exception as exc:  # pragma: no cover
            return AgentResult(
                tool_name=self.tool_name,
                findings=[],
                metadata={"error": "python_reachability_failed", "details": str(exc)},
            )

        # Taint flows decide sink_reachable (see _map_findings). TainterAgent is
        # sequenced before this agent in runner.py precisely so this is populated.
        tainted = sink_modules(getattr(context, "taint_flows", None))
        finding_map = self._map_findings(analyses, vuln_inputs, tainted,
                                         context.import_map or {})
        findings = [ReachabilityFinding.model_validate(f).model_dump() for f in finding_map]
        metadata = {
            "status": "ok",
            "finding_count": len(findings),
            "raw": report,
            "logs": stdout_buf.getvalue(),
            "taint_modules": sorted(tainted),
        }
        return AgentResult.model_validate({"tool_name": self.tool_name, "findings": findings, "metadata": metadata})

    def _build_vuln_inputs(self, vulns: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        inputs: List[Dict[str, Any]] = []
        for vuln in vulns:
            pkg = vuln.get("package")
            if not pkg:
                continue
            cves = vuln.get("cve_id")
            cve_list = cves if isinstance(cves, list) else [cves] if cves else []
            inputs.append(
                {
                    "package_name": pkg,
                    "package_version": vuln.get("version"),
                    "installed_version": vuln.get("version"),
                    "recommended_fixed_version": vuln.get("fix_version"),
                    "cve_ids": cve_list,
                }
            )
        return inputs

    def _map_findings(self, analyses: List[Any], vuln_inputs: List[Dict[str, Any]],
                      tainted: Optional[set] = None,
                      import_map: Optional[Dict[str, str]] = None):
        # Map package -> cve_ids from inputs
        pkg_cves: Dict[str, List[str]] = {}
        for inp in vuln_inputs:
            pkg = inp.get("package_name")
            if not pkg:
                continue
            pkg_cves.setdefault(pkg, []).extend(inp.get("cve_ids", []))

        mapped: List[Dict[str, Any]] = []
        for analysis in analyses:
            cves = pkg_cves.get(analysis.package_name, [None]) or [None]
            # One set of booleans, used for BOTH the verdict and the reported
            # evidence. They were computed separately before, so a finding could
            # claim verdict=LIKELY (which the engine defines as import + call
            # chain) while reporting call_chain_exists=False alongside it.
            import_detected = bool(analysis.is_used)
            # A taint flow is itself a proven source→sink path, so it establishes
            # BOTH that the sink is reachable and that a call chain exists — it is
            # strictly stronger evidence than the analyzer's own call graph, and
            # must not be gated behind it (the JS/Java analyzers frequently emit
            # no call graph at all). A bare call chain, by contrast, proves the
            # package is reached but not that the vulnerable sink is: LIKELY.
            taint_reaches_sink = package_taint_reachable(
                analysis.package_name, "python", tainted, import_map)
            call_chain_exists = bool(analysis.call_chain_graph) or taint_reaches_sink
            sink_reachable = taint_reaches_sink
            verdict = reachability_verdict(import_detected, call_chain_exists, sink_reachable)
            confidence = self._confidence_from_verdict(verdict)
            files = list(dict.fromkeys(ctx.file_path for ctx in analysis.usage_contexts))
            functions = self._extract_functions(analysis)
            for cve in cves:
                mapped.append(
                    {
                        "cve_id": cve,
                        "package": analysis.package_name,
                        "import_detected": import_detected,
                        "call_chain_exists": call_chain_exists,
                        "sink_reachable": sink_reachable,
                        "verdict": verdict,
                        "confidence": confidence,
                        "evidence_type": "static",
                        "files": files,
                        "function": ", ".join(functions) if functions else None,
                    }
                )
        return mapped

    def _extract_functions(self, analysis: Any) -> List[str]:
        """Extract enclosing function names from usage contexts with fallbacks."""
        # Strategy 1: function_call or attribute_access contexts with enclosing_scope
        functions = list(dict.fromkeys(
            ctx.enclosing_scope for ctx in analysis.usage_contexts
            if ctx.enclosing_scope and ctx.usage_type in ("function_call", "attribute_access")
        ))
        if functions:
            return functions

        # Strategy 2: any context with enclosing_scope
        functions = list(dict.fromkeys(
            ctx.enclosing_scope for ctx in analysis.usage_contexts
            if ctx.enclosing_scope
        ))
        if functions:
            return functions

        # Strategy 3: parse call_chain_graph mermaid for function names
        if analysis.call_chain_graph:
            # Mermaid format: "graph TD;\n    request_test;\n    home;\n    ..."
            names = re.findall(r'^\s+(\w+);', analysis.call_chain_graph, re.MULTILINE)
            # Filter out mermaid keywords
            skip = {"graph", "TD", "LR", "classDef", "class", "subgraph", "end", "style"}
            functions = [n for n in names if n not in skip]
            if functions:
                return list(dict.fromkeys(functions))

        return []

    def _confidence_from_verdict(self, verdict: str) -> float:
        from correlation.engine import confidence_from_verdict
        return confidence_from_verdict(verdict)

