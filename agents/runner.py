import asyncio
from typing import Any, Callable, Dict, List, Sequence, Tuple
import logging

from core.models import AgentResult, ScanContext
from pydantic import ValidationError

from storage.repository import StorageRepository
from .reachability.multi_language_analyzer import ProjectLanguageDetector

from .agent_git import GitAgent
from .agent_trivy import TrivyAgent
from .agent_tainter import TainterAgent
from .agent_semgrep import SemgrepAgent
from .agent_python_reachability import PythonReachabilityAgent
from .agent_java_reachability import JavaReachabilityAgent
from .agent_dynamic_reachability import DynamicReachabilityAgent
from .reachability.agent_bridge import MultiLanguageReachabilityBridge
from .agent_openapi_generator import OpenAPIGeneratorAgent
from .agent_intelligent_dast import IntelligentDastAgent
from .agent_pytest_coverage import PytestCoverageAgent
from .agent_routextractor import RouteExtractorAgent
from .agent_metadata import MetadataAgent

logger = logging.getLogger(__name__)


_StageEntry = Tuple[Any, Callable[[ScanContext, AgentResult], None], str]

# Languages the tainter CLI (1.0.2) can perform source→sink analysis for. Used
# to decide whether taint evidence is available to ground a CONFIRMED verdict.
_TAINTER_LANGUAGES = {"python", "java", "javascript", "go"}


class AgentRunner:
    def __init__(self, storage: StorageRepository) -> None:
        self.storage = storage
        self.git = GitAgent()
        self.trivy = TrivyAgent()
        self.tainter = TainterAgent()
        self.semgrep = SemgrepAgent()
        self.python_reachability = PythonReachabilityAgent()
        self.java_reachability = JavaReachabilityAgent()
        self.multi_language_reachability = MultiLanguageReachabilityBridge()
        self.openapi_generator = OpenAPIGeneratorAgent()
        self.dynamic_reachability = DynamicReachabilityAgent()
        self.intelligent_dast = IntelligentDastAgent()
        self.pytest_coverage = PytestCoverageAgent()
        self.route_extractor = RouteExtractorAgent()
        self.metadata_agent = MetadataAgent()

    async def run_all(self, context: ScanContext) -> List[AgentResult]:
        """Execute agents in dependency-aware stages with parallelism where safe."""
        results: List[AgentResult] = []

        tools = self._selected_tools(context)

        # ── Stage 1: Git clone (sequential prerequisite) ────────────────
        if "git" in tools and context.repo_url:
            git_result = await self._run_and_persist(
                context,
                self.git,
                self._persist_git,
                error_event="agent_skipped",
            )
            results.append(git_result)
            if git_result.metadata.get("fatal") or git_result.metadata.get("error"):
                return results
            # GitAgent may auto-discover vulnreach.yaml/scan.yml in the cloned
            # repository and replace context.config. Refresh the selected tools
            # so repository-owned config controls subsequent stages.
            tools = self._selected_tools(context)

        detected_languages = self._detect_project_languages(context)
        python_only_repo = self._is_python_only_repo(detected_languages)

        # ── Stage 2: Trivy + Metadata prerequisites (sequential) ────────
        if "trivy" in tools:
            results.append(
                await self._run_and_persist(
                    context,
                    self.trivy,
                    self._persist_trivy,
                    error_event="agent_skipped",
                )
            )

        if "metadata" in tools:
            results.append(
                await self._run_and_persist(
                    context,
                    self.metadata_agent,
                    self._persist_metadata,
                    error_event="agent_skipped",
                )
            )

        # ── Stage 3: Static/supplemental analysis (parallel) ─────────────
        # Safe to parallelize: all agents consume the same immutable repo/vuln
        # snapshot, and context updates are applied after each agent completes.
        #
        # Tainter is NOT Python-only: tainter 1.0.2 ships Java, JavaScript and Go
        # flow finders, so it runs for any repo whose languages it can analyze.
        # It used to be skipped for every non-python-only repo, which left the
        # Java and multi-language static verdicts with no taint evidence — and
        # those paths set sink_reachable = call_chain_exists, marking every used
        # package CONFIRMED without proof the vulnerable sink was reached.
        taint_applicable = bool(set(detected_languages) & _TAINTER_LANGUAGES)
        if "tainter" in tools and not taint_applicable:
            results.append(
                self._persist_skipped(
                    context,
                    self.tainter.tool_name,
                    self._persist_tainter,
                    "no_taint_supported_language",
                    detected_languages,
                )
            )

        static_stage_map: Dict[str, _StageEntry] = {
            "python_reachability": (
                self.python_reachability,
                self._persist_python_reachability,
                "agent_skipped",
            ),
            "java_reachability": (
                self.java_reachability,
                self._persist_java_reachability,
                "agent_skipped",
            ),
            "multi_language_reachability": (
                self.multi_language_reachability,
                self._persist_multi_language_reachability,
                "agent_skipped",
            ),
            "semgrep": (self.semgrep, self._persist_semgrep, "agent_skipped"),
            "route_extractor": (
                self.route_extractor,
                self._persist_route_extractor,
                "agent_skipped",
            ),
        }
        # Tainter runs BEFORE the parallel static stage, not inside it: every
        # static reachability verdict (Python, Java, and the multi-language
        # bridge) now uses taint flows to decide `sink_reachable`, so CONFIRMED
        # means "a source→sink path reaches this package" rather than merely "a
        # call chain reaches the import". Run in parallel, that is a race —
        # the reachability agents would observe an empty context.taint_flows and
        # silently cap every finding at LIKELY. Tainter is milliseconds on a
        # typical repo, so sequencing it is cheap.
        if taint_applicable and "tainter" in tools:
            results.append(
                await self._run_and_persist(
                    context,
                    self.tainter,
                    self._persist_tainter,
                    error_event="agent_skipped",
                )
            )
        static_entries = self._stage_entries_from_tools(tools, static_stage_map)
        if static_entries:
            results.extend(await self._run_parallel_stage(context, static_entries))

        # ── Stage 4: OpenAPI generation (sequential prerequisite for dynamic) ──
        if context.config and context.config.scan.runtime.enabled and context.config.scan.openapi_generator.enabled:
            results.append(
                await self._run_and_persist(
                    context,
                    self.openapi_generator,
                    self._persist_openapi_generator,
                    error_event="agent_error",
                )
            )

        # ── Stage 5: Runtime stage (parallel) ─────────────────────────────
        runtime_entries: List[_StageEntry] = []
        if context.config and context.config.scan.runtime.enabled:
            # Dynamic reachability is Docker-based and language-agnostic.
            # Run for any project with runtime enabled, not just Python-only repos.
            runtime_entries.append(
                (self.dynamic_reachability, self._persist_dynamic_reachability, "agent_error")
            )
        if "pytest_coverage" in tools:
            if python_only_repo:
                runtime_entries.append(
                    (self.pytest_coverage, self._persist_pytest_coverage, "agent_skipped")
                )
            else:
                results.append(
                    self._persist_skipped(
                        context,
                        self.pytest_coverage.tool_name,
                        self._persist_pytest_coverage,
                        "python_only_runtime_and_taint",
                        detected_languages,
                    )
                )
        if runtime_entries:
            results.extend(await self._run_parallel_stage(context, runtime_entries))

        # ── Stage 6: Intelligent DAST (sequential) ────────────────────────
        if context.config and context.config.scan.intelligent_dast.enabled:
            results.append(
                await self._run_and_persist(
                    context,
                    self.intelligent_dast,
                    self._persist_intelligent_dast,
                    error_event="agent_error",
                )
            )

        return results

    def _detect_project_languages(self, context: ScanContext) -> List[str]:
        if context.detected_languages:
            return list(context.detected_languages)
        if not context.repo_path:
            return []
        try:
            context.detected_languages = ProjectLanguageDetector(context.repo_path).detect_languages()
        except Exception as exc:  # pragma: no cover - detector is best effort
            logger.warning(
                "language_detection_failed",
                extra={"scan_id": context.scan_id, "repo_path": context.repo_path, "details": str(exc)},
            )
            context.detected_languages = []
        return list(context.detected_languages)

    def _is_python_only_repo(self, detected_languages: Sequence[str]) -> bool:
        return list(detected_languages) == ["python"]

    def _persist_skipped(
        self,
        context: ScanContext,
        tool_name: str,
        persist: Callable[[ScanContext, AgentResult], None],
        reason: str,
        detected_languages: Sequence[str],
    ) -> AgentResult:
        result = AgentResult(
            tool_name=tool_name,
            findings=[],
            metadata={
                "status": "skipped",
                "reason": reason,
                "detected_languages": list(detected_languages),
            },
        )
        persist(context, result)
        logger.info(
            "agent_skipped_by_language_gate",
            extra={
                "scan_id": context.scan_id,
                "agent": tool_name,
                "reason": reason,
                "detected_languages": list(detected_languages),
            },
        )
        return result

    async def _run_parallel_stage(
        self,
        context: ScanContext,
        entries: Sequence[_StageEntry],
    ) -> List[AgentResult]:
        coros = [
            self._run_and_persist(context, agent, persist, error_event=error_event)
            for agent, persist, error_event in entries
        ]
        return list(await asyncio.gather(*coros))

    def _stage_entries_from_tools(
        self,
        tools: Sequence[str],
        stage_map: Dict[str, _StageEntry],
    ) -> List[_StageEntry]:
        entries: List[_StageEntry] = []
        seen: set[str] = set()
        for tool in tools:
            if tool in stage_map and tool not in seen:
                entries.append(stage_map[tool])
                seen.add(tool)
        return entries

    def _selected_tools(self, context: ScanContext) -> List[str]:
        cfg_tools = context.config.scan.tools if context.config else ["trivy", "tainter"]
        tools = [tool.lower() for tool in cfg_tools]
        if context.repo_url and "git" not in tools:
            tools.insert(0, "git")
        return tools

    async def _run_and_persist(
        self,
        context: ScanContext,
        agent: Any,
        persist: Callable[[ScanContext, AgentResult], None],
        *,
        error_event: str,
    ) -> AgentResult:
        agent_name = getattr(agent, "tool_name", "unknown")
        logger.info("agent_start", extra={"scan_id": context.scan_id, "agent": agent_name})
        result = await self._run_agent(agent, context)
        persist(context, result)
        if result.metadata.get("error"):
            logger.warning(
                error_event,
                extra={
                    "scan_id": context.scan_id,
                    "agent": agent_name,
                    "error": result.metadata,
                },
            )
        else:
            logger.info("agent_complete", extra={"scan_id": context.scan_id, "agent": agent_name})
        return result

    def _store_raw_result(self, context: ScanContext, tool_name: str, result: AgentResult) -> None:
        self.storage.store_raw_output(
            context.scan_id or "",
            tool_name,
            result.metadata.get("raw", result.metadata or {}),
        )

    def _persist_git(self, context: ScanContext, result: AgentResult) -> None:
        self._store_raw_result(context, self.git.tool_name, result)

    def _persist_trivy(self, context: ScanContext, result: AgentResult) -> None:
        self._store_raw_result(context, self.trivy.tool_name, result)
        self.storage.store_vulnerabilities(context.scan_id or "", result.findings)
        context.vulnerabilities = result.findings

    def _persist_metadata(self, context: ScanContext, result: AgentResult) -> None:
        self._store_raw_result(context, self.metadata_agent.tool_name, result)
        raw_map = result.metadata.get("raw")
        if isinstance(raw_map, dict):
            context.import_map = {
                str(import_name): str(distribution)
                for import_name, distribution in raw_map.items()
            }

    def _persist_tainter(self, context: ScanContext, result: AgentResult) -> None:
        self._store_raw_result(context, self.tainter.tool_name, result)
        self.storage.store_reachability(context.scan_id or "", result.findings)
        context.taint_flows = result.metadata.get("flows", [])

    def _persist_python_reachability(self, context: ScanContext, result: AgentResult) -> None:
        self._store_raw_result(context, self.python_reachability.tool_name, result)
        self.storage.store_reachability(context.scan_id or "", result.findings)

    def _persist_java_reachability(self, context: ScanContext, result: AgentResult) -> None:
        self._store_raw_result(context, self.java_reachability.tool_name, result)
        if result.findings:
            self.storage.store_reachability(context.scan_id or "", result.findings)

    def _persist_multi_language_reachability(self, context: ScanContext, result: AgentResult) -> None:
        self._store_raw_result(context, self.multi_language_reachability.tool_name, result)
        if result.findings:
            self.storage.store_reachability(context.scan_id or "", result.findings)

    def _persist_semgrep(self, context: ScanContext, result: AgentResult) -> None:
        self._store_raw_result(context, self.semgrep.tool_name, result)
        self.storage.store_semgrep_findings(context.scan_id or "", result.findings)

    def _persist_route_extractor(self, context: ScanContext, result: AgentResult) -> None:
        self._store_raw_result(context, self.route_extractor.tool_name, result)
        self.storage.store_routes(context.scan_id or "", result.findings)
        context.routes = result.findings

    def _persist_openapi_generator(self, context: ScanContext, result: AgentResult) -> None:
        self._store_raw_result(context, self.openapi_generator.tool_name, result)

    def _persist_dynamic_reachability(self, context: ScanContext, result: AgentResult) -> None:
        self._store_raw_result(context, self.dynamic_reachability.tool_name, result)
        if result.findings:
            self.storage.store_reachability(context.scan_id or "", result.findings)

    def _persist_pytest_coverage(self, context: ScanContext, result: AgentResult) -> None:
        self._store_raw_result(context, self.pytest_coverage.tool_name, result)
        if result.findings:
            self.storage.store_reachability(context.scan_id or "", result.findings)

    def _persist_intelligent_dast(self, context: ScanContext, result: AgentResult) -> None:
        self._store_raw_result(context, self.intelligent_dast.tool_name, result)
        if result.findings:
            self.storage.store_reachability(context.scan_id or "", result.findings)

    async def _run_agent(self, agent, context: ScanContext) -> AgentResult:
        try:
            result = await agent.run(context)
            return AgentResult.model_validate(result)
        except ValidationError as ve:
            return AgentResult(tool_name=getattr(agent, "tool_name", "unknown"), findings=[], metadata={"error": "schema_validation_failed", "details": ve.errors()})
        except Exception as exc:  # pragma: no cover
            logger.exception("agent_exception", extra={"scan_id": context.scan_id, "agent": getattr(agent, "tool_name", "unknown")})
            return AgentResult(tool_name=getattr(agent, "tool_name", "unknown"), findings=[], metadata={"error": "agent_exception", "details": str(exc)})
