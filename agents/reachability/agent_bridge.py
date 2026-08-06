"""
agent_bridge.py – thin shim exposing run_multi_language_analysis() in a form
compatible with the BaseAgent/BaseTool runner pattern used by the rest of the
pipeline.

Usage from runner.py / orchestrator.py:
    from agents.reachability.agent_bridge import MultiLanguageReachabilityBridge
    bridge = MultiLanguageReachabilityBridge()
    result = await bridge.run(context)

The bridge also accepts plain kwargs so it can be called from scripts that
don't construct a ScanContext:
    bridge.run_sync(project_root=..., consolidated_path=..., output_dir=...)
"""

import io
import json
import os
import tempfile
from contextlib import redirect_stdout
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from correlation.engine import confidence_from_verdict, reachability_verdict
from .multi_language_analyzer import run_multi_language_analysis
from .taint_match import sink_modules, package_taint_reachable


class MultiLanguageReachabilityBridge:
    """Wraps run_multi_language_analysis() behind the BaseTool interface."""

    tool_name = "multi_language_reachability"

    def __init__(self, timeout_seconds: int = 300) -> None:
        self.timeout_seconds = timeout_seconds

    # ------------------------------------------------------------------
    # Async entry point – compatible with BaseTool.run(context)
    # ------------------------------------------------------------------
    async def run(self, context: Any) -> Any:  # type: ignore[override]
        """
        Accepts a ScanContext (or any object with .repo_path, .consolidated_path,
        .output_dir attributes).  Returns a plain dict so the method works even
        when core.models is not importable in isolated test environments.
        """
        repo_path = getattr(context, "repo_path", None)
        consolidated_path = getattr(context, "consolidated_path", None)
        output_dir = getattr(context, "output_dir", None)
        vulnerabilities = list(getattr(context, "vulnerabilities", []) or [])
        # TainterAgent analyzes JS/Go too; its flows lift a finding to CONFIRMED.
        tainted = sink_modules(getattr(context, "taint_flows", None))

        result = self.run_sync(
            project_root=repo_path,
            consolidated_path=consolidated_path,
            output_dir=output_dir,
            vulnerabilities=vulnerabilities,
            tainted=tainted,
        )

        # Wrap in AgentResult if the model is available; otherwise return dict.
        try:
            from core.models import AgentResult  # type: ignore
            return AgentResult.model_validate(result)
        except Exception:
            return result

    # ------------------------------------------------------------------
    # Synchronous entry point – usable from scripts / tests
    # ------------------------------------------------------------------
    def run_sync(
        self,
        *,
        project_root: Optional[str],
        consolidated_path: Optional[str],
        output_dir: Optional[str] = None,
        vulnerabilities: Optional[List[Dict[str, Any]]] = None,
        tainted: Optional[set] = None,
    ) -> Dict[str, Any]:
        vulnerabilities = list(vulnerabilities or [])
        if not project_root:
            return {"tool_name": self.tool_name, "findings": [], "metadata": {"error": "missing_project_root"}}
        if not consolidated_path and not vulnerabilities:
            return {"tool_name": self.tool_name, "findings": [], "metadata": {"status": "no_vulns"}}

        repo_path = Path(project_root).resolve()
        if not repo_path.exists():
            return {
                "tool_name": self.tool_name,
                "findings": [],
                "metadata": {"error": "repo_path_not_found", "repo_path": str(repo_path)},
            }

        if output_dir:
            report_dir = Path(output_dir)
        else:
            report_dir = repo_path / "security_findings"
        os.makedirs(report_dir, exist_ok=True)

        temp_consolidated_path: Optional[str] = None
        if not consolidated_path:
            temp_consolidated_path = self._write_consolidated_file(vulnerabilities)
            consolidated_path = temp_consolidated_path

        logs = io.StringIO()
        error: Optional[str] = None
        raw_reports: Dict[str, Dict[str, Any]] = {}
        languages: List[str] = []
        missing_reports: List[str] = []
        findings: List[Dict[str, Any]] = []

        try:
            with redirect_stdout(logs):
                run_result = run_multi_language_analysis(
                    project_root=str(repo_path),
                    consolidated_path=consolidated_path,
                    output_dir=str(report_dir),
                )
            if isinstance(run_result, str):
                languages = [run_result]
            elif isinstance(run_result, list):
                languages = [str(lang).strip() for lang in run_result if str(lang).strip()]
            else:
                languages = []

            for language in languages:
                report_path = report_dir / f"{language}_vulnerability_reachability_report.json"
                if not report_path.exists():
                    missing_reports.append(str(report_path))
                    continue
                with open(report_path, "r", encoding="utf-8") as f:
                    report = json.load(f)
                raw_reports[language] = report
                findings.extend(self._map_findings(report, vulnerabilities,
                                                   language, tainted))

            findings = self._dedupe_findings(findings)
            if languages and not raw_reports:
                error = "report_not_found"
            elif not languages:
                error = "no_languages_detected"
        except Exception as exc:  # pragma: no cover
            error = f"{type(exc).__name__}: {exc}"
        finally:
            if temp_consolidated_path:
                try:
                    os.remove(temp_consolidated_path)
                except Exception:
                    pass

        _experimental_languages = [lang for lang in languages if lang != "python"]
        analysis_notes: Dict[str, str] = {}
        for lang in _experimental_languages:
            analysis_notes[lang] = (
                f"{lang} reachability analysis is experimental. Call graph and "
                "import detection are functional, but taint-flow analysis "
                f"(user-input-to-sink tracing) is not yet supported for {lang}. "
                "Treat findings as indicative, not fully confirmed."
            )

        metadata: Dict[str, Any] = {
            "status": "error" if error else "ok",
            "language": languages[0] if languages else "unknown",
            "languages": languages,
            "output_dir": str(report_dir),
            "logs": logs.getvalue(),
            "raw": next(iter(raw_reports.values()), {}),
            "raw_by_language": raw_reports,
        }
        if analysis_notes:
            metadata["analysis_notes"] = analysis_notes
        if missing_reports:
            metadata["missing_reports"] = missing_reports
        if error:
            metadata["error"] = error

        return {"tool_name": self.tool_name, "findings": findings, "metadata": metadata}

    def _write_consolidated_file(self, vulnerabilities: List[Dict[str, Any]]) -> str:
        normalised = []
        for vuln in vulnerabilities:
            pkg = vuln.get("package") or vuln.get("package_name")
            if not pkg:
                continue
            normalised.append(
                {
                    "package_name": pkg,
                    "installed_version": vuln.get("version") or vuln.get("installed_version") or "",
                    "fixed_version": vuln.get("fix_version") or vuln.get("fixed_version") or "",
                    "recommended_version": vuln.get("fix_version") or vuln.get("recommended_version") or "",
                    "recommended_fixed_version": vuln.get("fix_version") or vuln.get("recommended_fixed_version") or "",
                    "severity": vuln.get("severity", "MEDIUM"),
                    "cve_ids": vuln.get("cve_id", []),
                }
            )

        fd, path = tempfile.mkstemp(prefix="vulnreach-consolidated-", suffix=".json")
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            # Use list shape for compatibility with Python analyzer and all
            # other analyzers (which already accept list input).
            json.dump(normalised, f)
        return path

    def _map_findings(self, report: Dict[str, Any], vulnerabilities: List[Dict[str, Any]],
                      language: Optional[str] = None,
                      tainted: Optional[set] = None) -> List[Dict[str, Any]]:
        pkg_cves: Dict[str, List[str]] = {}
        for vuln in vulnerabilities:
            pkg = vuln.get("package") or vuln.get("package_name")
            if not pkg:
                continue
            cves = vuln.get("cve_id")
            cve_list = cves if isinstance(cves, list) else [cves] if cves else []
            for alias in self._package_aliases(str(pkg)):
                existing = pkg_cves.setdefault(alias, [])
                for cve in cve_list:
                    if cve and cve not in existing:
                        existing.append(cve)

        findings: List[Dict[str, Any]] = []

        if not isinstance(report, dict):
            return findings

        # Common report shape (java/go/js/csharp/php analyzers)
        analyses = report.get("analyses", [])
        if isinstance(analyses, list) and analyses:
            for analysis in analyses:
                package_name = str(analysis.get("package_name", "")).strip()
                if not package_name:
                    continue
                cve_candidates: List[Optional[str]] = []
                for alias in self._package_aliases(package_name):
                    cve_candidates.extend(pkg_cves.get(alias, []))
                cve_ids = list(dict.fromkeys([c for c in cve_candidates if c])) or [None]

                usage_contexts = analysis.get("usage_contexts", []) or []
                import_detected = bool(analysis.get("is_used", False))
                # Taint proves source→sink (CONFIRMED) on its own; a bare call
                # chain proves only reachability (LIKELY). Taint is not gated
                # behind the analyzer call graph, which the JS/Go/PHP analyzers
                # frequently do not emit.
                taint_reaches_sink = package_taint_reachable(package_name, language, tainted)
                call_chain_exists = bool(analysis.get("call_chain_graph")) or taint_reaches_sink
                sink_reachable = taint_reaches_sink
                verdict = reachability_verdict(import_detected, call_chain_exists, sink_reachable)
                confidence = confidence_from_verdict(verdict)
                files = list(dict.fromkeys(
                    ctx.get("file_path") for ctx in usage_contexts if isinstance(ctx, dict) and ctx.get("file_path")
                ))
                funcs = list(dict.fromkeys(
                    ctx.get("enclosing_scope") for ctx in usage_contexts if isinstance(ctx, dict) and ctx.get("enclosing_scope")
                ))
                line = min(
                    (
                        int(ctx.get("line_number"))
                        for ctx in usage_contexts
                        if isinstance(ctx, dict) and isinstance(ctx.get("line_number"), int)
                    ),
                    default=None,
                )

                for cve in cve_ids:
                    findings.append(
                        {
                            "cve_id": cve,
                            "package": package_name,
                            "import_detected": import_detected,
                            "call_chain_exists": call_chain_exists,
                            "sink_reachable": sink_reachable,
                            "verdict": verdict,
                            "confidence": confidence,
                            "evidence_type": "static",
                            "function": ", ".join(funcs) if funcs else None,
                            "files": files,
                            "line": line,
                        }
                    )
            return findings

        # Python analyzer shape: {"summary": {...}, "vulnerabilities": [{...}]}
        py_vulns = report.get("vulnerabilities", [])
        if not isinstance(py_vulns, list):
            return findings

        for vuln in py_vulns:
            if not isinstance(vuln, dict):
                continue
            package_name = str(vuln.get("package_name", "")).strip()
            if not package_name:
                continue
            cve_candidates: List[Optional[str]] = []
            for alias in self._package_aliases(package_name):
                cve_candidates.extend(pkg_cves.get(alias, []))
            cve_ids = list(dict.fromkeys([c for c in cve_candidates if c])) or [None]
            evidence = vuln.get("evidence", {})
            usage_contexts = evidence.get("usage_contexts", []) if isinstance(evidence, dict) else []
            import_detected = bool(vuln.get("is_used", False))
            taint_reaches_sink = package_taint_reachable(package_name, language, tainted)
            call_chain_exists = bool(vuln.get("call_chain_graph")) or taint_reaches_sink
            sink_reachable = taint_reaches_sink
            verdict = reachability_verdict(import_detected, call_chain_exists, sink_reachable)
            confidence = confidence_from_verdict(verdict)
            files = list(dict.fromkeys(
                ctx.get("file_path") for ctx in usage_contexts if isinstance(ctx, dict) and ctx.get("file_path")
            ))
            funcs = list(dict.fromkeys(
                ctx.get("enclosing_scope") for ctx in usage_contexts if isinstance(ctx, dict) and ctx.get("enclosing_scope")
            ))
            line = min(
                (
                    int(ctx.get("line_number"))
                    for ctx in usage_contexts
                    if isinstance(ctx, dict) and isinstance(ctx.get("line_number"), int)
                ),
                default=None,
            )

            for cve in cve_ids:
                findings.append(
                    {
                        "cve_id": cve,
                        "package": package_name,
                        "import_detected": import_detected,
                        "call_chain_exists": call_chain_exists,
                        "sink_reachable": sink_reachable,
                        "verdict": verdict,
                        "confidence": confidence,
                        "evidence_type": "static",
                        "function": ", ".join(funcs) if funcs else None,
                        "files": files,
                        "line": line,
                    }
                )

        return findings

    def _package_aliases(self, package_name: str) -> List[str]:
        raw = package_name.strip()
        aliases = {raw.lower()}

        if raw.startswith("pkg:"):
            p = raw.split("pkg:", 1)[1]
            if "/" in p:
                p = p.split("/", 1)[1]
            p = p.split("@", 1)[0]
            aliases.add(p.lower())
            aliases.add(p.replace("/", ":").lower())

        if ":" in raw:
            g, a = raw.split(":", 1)
            aliases.add(f"{g}:{a.split('@', 1)[0]}".lower())
        if "/" in raw:
            aliases.add(raw.split("@", 1)[0].lower())
            aliases.add(raw.replace("/", ":").split("@", 1)[0].lower())

        aliases.add(raw.split("@", 1)[0].lower())
        return list(aliases)

    def _dedupe_findings(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        unique: Dict[Tuple[Any, ...], Dict[str, Any]] = {}
        for finding in findings:
            key = (
                finding.get("cve_id"),
                finding.get("package"),
                finding.get("line"),
                finding.get("function"),
                tuple(sorted(str(f) for f in finding.get("files", []) or [])),
            )
            existing = unique.get(key)
            if not existing:
                unique[key] = finding
                continue
            try:
                existing_conf = float(existing.get("confidence", 0) or 0)
            except (TypeError, ValueError):
                existing_conf = 0.0
            try:
                new_conf = float(finding.get("confidence", 0) or 0)
            except (TypeError, ValueError):
                new_conf = 0.0
            if new_conf > existing_conf:
                unique[key] = finding
        return list(unique.values())
