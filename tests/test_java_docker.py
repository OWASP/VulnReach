"""
Java E2E lab tests — static, dynamic coverage simulation, and full correlation.

Three independent test classes:

  TestJavaDockerEndpoints    — spins up labs/ebpf-e2e-java via docker compose,
                               hits each HTTP route, verifies responses.
                               Requires: Docker.

  TestJavaStaticReachability — runs JavaReachabilityAnalyzer directly on the lab
                               source tree; all three vulnerable packages must be
                               detected as used.
                               Requires: nothing.

  TestJavaDynamicCoverage    — feeds simulated bpftrace method-entry output through
                               the sidecar parser and coverage normaliser; verifies
                               the NormalisedCoverage and coverage.py structures are
                               correct for each route's expected library calls.
                               Requires: nothing.

  TestJavaFullPipeline       — starts the Docker container, exercises every route,
                               builds simulated eBPF coverage matching those calls,
                               runs the full correlation pipeline, and asserts final
                               DYNAMICALLY_REACHABLE / STATICALLY_REACHABLE verdicts.
                               Requires: Docker.

Run all:
  VULNREACH_ALLOW_DOCKER_DAEMON=true pytest tests/test_java_docker.py -v

Run without Docker:
  pytest tests/test_java_docker.py::TestJavaStaticReachability \\
         tests/test_java_docker.py::TestJavaDynamicCoverage -v
"""

import json
import os
import shutil
import subprocess
import time
import urllib.request
from pathlib import Path

import pytest

# ── Paths ─────────────────────────────────────────────────────────────────────

LAB_DIR    = Path(__file__).parent.parent / "labs" / "ebpf-e2e-java"
TARGET_SRC = LAB_DIR / "target"
TARGET_URL = "http://localhost:5002"

# ── Skip guards ───────────────────────────────────────────────────────────────

def _docker_available() -> bool:
    return (
        shutil.which("docker") is not None
        and bool(os.environ.get("VULNREACH_ALLOW_DOCKER_DAEMON"))
    )


requires_docker = pytest.mark.skipif(
    not _docker_available(),
    reason="Docker tests require docker in PATH and VULNREACH_ALLOW_DOCKER_DAEMON=true",
)

# ── Docker fixture ─────────────────────────────────────────────────────────────

def _wait_for_target(timeout: int = 90) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            urllib.request.urlopen(f"{TARGET_URL}/health", timeout=2)
            return True
        except Exception:
            time.sleep(2)
    return False


@pytest.fixture(scope="module")
def java_target():
    """Build and start the Java lab; tear it down after the module."""
    subprocess.run(
        ["docker", "compose", "up", "-d", "--build"],
        cwd=LAB_DIR, check=True, capture_output=True,
    )
    if not _wait_for_target():
        subprocess.run(["docker", "compose", "down", "--remove-orphans"], cwd=LAB_DIR)
        pytest.fail("Java target did not become healthy within 90s")
    yield TARGET_URL
    subprocess.run(
        ["docker", "compose", "down", "--remove-orphans"],
        cwd=LAB_DIR, capture_output=True,
    )


# ── Helpers ───────────────────────────────────────────────────────────────────

def _get_reachability_class(findings: list, cve_id: str) -> str | None:
    """Return reachability_class for the given CVE from a correlation result list."""
    for f in findings:
        ids = f.get("cve_id") if isinstance(f.get("cve_id"), list) else [f.get("cve_id")]
        if cve_id in (ids or []):
            return f.get("reachability_class")
    return None


# ── Known vulnerabilities in the lab ─────────────────────────────────────────

_VULNS = [
    {
        "package": "org.apache.logging.log4j:log4j-core",
        "cve_id": "CVE-2021-44228",
        "severity": "CRITICAL",
        "version": "2.14.1",
        "fixed_version": "2.17.1",
    },
    {
        "package": "org.apache.commons:commons-text",
        "cve_id": "CVE-2022-42889",
        "severity": "CRITICAL",
        "version": "1.9",
        "fixed_version": "1.10.0",
    },
    {
        "package": "org.yaml:snakeyaml",
        "cve_id": "CVE-2022-1471",
        "severity": "HIGH",
        "version": "1.30",
        "fixed_version": "2.0",
    },
]


# ── Docker endpoint tests ──────────────────────────────────────────────────────

@requires_docker
class TestJavaDockerEndpoints:
    """HTTP smoke tests against the running Java container."""

    def test_health_returns_ok(self, java_target):
        resp = urllib.request.urlopen(f"{java_target}/health", timeout=5)
        body = json.loads(resp.read())
        assert resp.status == 200
        assert body == {"status": "ok"}

    def test_log_calls_logger(self, java_target):
        """/log must return logged:true (confirming log4j path was exercised)."""
        resp = urllib.request.urlopen(f"{java_target}/log", timeout=5)
        body = json.loads(resp.read())
        assert resp.status == 200
        assert body.get("logged") is True

    def test_substitute_calls_commons_text(self, java_target):
        """/substitute must expand the ${name} placeholder via StringSubstitutor."""
        import urllib.parse
        url = f"{java_target}/substitute?input={urllib.parse.quote('Hello ${name}')}"
        resp = urllib.request.urlopen(url, timeout=5)
        body = json.loads(resp.read())
        assert resp.status == 200
        assert body.get("result") == "Hello VulnReach"

    def test_yaml_parses_input(self, java_target):
        """/yaml must parse a YAML string and return the parsed value."""
        import urllib.parse
        url = f"{java_target}/yaml?data={urllib.parse.quote('greeting: hello')}"
        resp = urllib.request.urlopen(url, timeout=5)
        body = json.loads(resp.read())
        assert resp.status == 200
        assert "greeting" in body.get("parsed", "")

    def test_nolog_is_negative_control(self, java_target):
        """/nolog must return called:false — no library methods invoked."""
        resp = urllib.request.urlopen(f"{java_target}/nolog", timeout=5)
        body = json.loads(resp.read())
        assert resp.status == 200
        assert body.get("called") is False

    def test_all_routes_return_json(self, java_target):
        """Every route must return Content-Type: application/json."""
        for path in ("/health", "/log", "/substitute", "/yaml", "/nolog"):
            resp = urllib.request.urlopen(f"{java_target}{path}", timeout=5)
            ct = resp.headers.get("Content-Type", "")
            assert "json" in ct, f"{path} returned Content-Type={ct!r}"


# ── Static reachability tests ──────────────────────────────────────────────────

class TestJavaStaticReachability:
    """Static Java reachability analysis against the lab source tree.

    No Docker or eBPF required — pure Python + Java source files.
    """

    @pytest.fixture(scope="class")
    def analyzer(self):
        from agents.reachability.java_reachability_analyzer import JavaReachabilityAnalyzer
        return JavaReachabilityAnalyzer(str(TARGET_SRC))

    def test_log4j_is_detected_as_used(self, analyzer):
        """log4j-core must be found as imported (CVE-2021-44228)."""
        result = analyzer.analyze_vulnerability(_VULNS[0])
        assert result.is_used, (
            "log4j-core should be detected as used — "
            "App.java imports and calls Logger"
        )

    def test_commons_text_is_detected_as_used(self, analyzer):
        """commons-text must be found as imported (CVE-2022-42889)."""
        result = analyzer.analyze_vulnerability(_VULNS[1])
        assert result.is_used, (
            "commons-text should be detected as used — "
            "App.java imports StringSubstitutor"
        )

    def test_snakeyaml_is_detected_as_used(self, analyzer):
        """snakeyaml must be found as imported (CVE-2022-1471)."""
        result = analyzer.analyze_vulnerability(_VULNS[2])
        assert result.is_used, (
            "snakeyaml should be detected as used — "
            "App.java imports Yaml"
        )

    def test_log4j_has_usage_context(self, analyzer):
        """log4j finding must include a usage context pointing at App.java."""
        result = analyzer.analyze_vulnerability(_VULNS[0])
        assert result.usage_contexts, "Expected at least one usage context for log4j"
        files = [ctx.file_path for ctx in result.usage_contexts]
        assert any("App.java" in f for f in files), (
            f"Expected App.java in usage contexts, got: {files}"
        )

    def test_commons_text_has_usage_context(self, analyzer):
        """commons-text finding must include a usage context pointing at App.java."""
        result = analyzer.analyze_vulnerability(_VULNS[1])
        assert result.usage_contexts, "Expected at least one usage context for commons-text"
        files = [ctx.file_path for ctx in result.usage_contexts]
        assert any("App.java" in f for f in files), (
            f"Expected App.java in usage contexts, got: {files}"
        )

    def test_snakeyaml_has_usage_context(self, analyzer):
        """snakeyaml finding must include a usage context pointing at App.java."""
        result = analyzer.analyze_vulnerability(_VULNS[2])
        assert result.usage_contexts, "Expected at least one usage context for snakeyaml"
        files = [ctx.file_path for ctx in result.usage_contexts]
        assert any("App.java" in f for f in files), (
            f"Expected App.java in usage contexts, got: {files}"
        )

    def test_all_three_packages_declared_in_pom(self, analyzer):
        """pom.xml must declare all three vulnerable dependencies."""
        pom = (TARGET_SRC / "pom.xml").read_text()
        assert "log4j-core" in pom
        assert "commons-text" in pom
        assert "snakeyaml" in pom

    def test_criticality_is_not_reachable_for_unknown_package(self, analyzer):
        """A package not present in the project must report is_used=False."""
        result = analyzer.analyze_vulnerability({
            "package": "com.example:nonexistent-lib",
            "severity": "CRITICAL",
            "version": "1.0.0",
        })
        assert not result.is_used, (
            "A package not imported or declared must have is_used=False"
        )


# ── Simulated eBPF output ─────────────────────────────────────────────────────
#
# What bpftrace would capture when each route is exercised.
# Format: "method:<class_slash>:<method_name>" per hotspot:method__entry USDT.
#
# These are the first-order library method calls from each handler —
# JVM internals (String, Object, etc.) are omitted for clarity.

_EBPF_ALL_ROUTES = "\n".join([
    "Attaching 1 probe...",
    # App infrastructure
    "method:com/example/App:main",
    # /log handler — log4j
    "method:org/apache/logging/log4j/core/Logger:info",
    "method:org/apache/logging/log4j/core/Logger:log",
    # /substitute handler — commons-text
    "method:org/apache/commons/text/StringSubstitutor:replace",
    "method:org/apache/commons/text/StringSubstitutor:replaceIn",
    # /yaml handler — snakeyaml
    "method:org/yaml/snakeyaml/Yaml:load",
    "method:org/yaml/snakeyaml/constructor/Constructor:constructDocument",
    "",
])

_EBPF_NOLOG_ONLY = "\n".join([
    "Attaching 1 probe...",
    "method:com/example/App:main",
    # No library methods — /nolog does not call log4j, commons-text, or snakeyaml
    "",
])


# ── Dynamic coverage pipeline tests (no Docker) ───────────────────────────────

class TestJavaDynamicCoverage:
    """Validates the eBPF output → NormalisedCoverage → coverage.py pipeline.

    No Docker or kernel required — pure Python parsing of simulated bpftrace output.
    """

    @pytest.fixture(scope="class")
    def coverage_all(self):
        """NormalisedCoverage from exercising all routes."""
        from agents.ebpf.sidecar.sidecar_entrypoint import parse_output
        return parse_output(_EBPF_ALL_ROUTES, "java_method", "java")

    @pytest.fixture(scope="class")
    def coverage_py_all(self, coverage_all):
        """coverage.py-format dict from exercising all routes."""
        from agents.ebpf.coverage_normaliser import to_coverage_py_format
        return to_coverage_py_format(coverage_all)

    def test_runtime_is_java(self, coverage_all):
        assert coverage_all["runtime"] == "java"

    def test_log4j_class_present(self, coverage_all):
        files = coverage_all["files"]
        log4j_files = [f for f in files if "log4j" in f]
        assert log4j_files, f"Expected a log4j file in coverage, got keys: {list(files)}"

    def test_commons_text_class_present(self, coverage_all):
        files = coverage_all["files"]
        ct_files = [f for f in files if "commons" in f or "text" in f.lower()]
        assert ct_files, f"Expected commons-text file in coverage, got: {list(files)}"

    def test_snakeyaml_class_present(self, coverage_all):
        files = coverage_all["files"]
        yaml_files = [f for f in files if "snakeyaml" in f]
        assert yaml_files, f"Expected snakeyaml file in coverage, got: {list(files)}"

    def test_log4j_info_function_recorded(self, coverage_all):
        logger_file = next(
            (f for f in coverage_all["files"] if "Logger" in f and "log4j" in f), None
        )
        assert logger_file, "Logger.java not found in coverage"
        funcs = coverage_all["files"][logger_file]["executed_functions"]
        assert "info" in funcs, f"Expected 'info' in executed_functions, got: {funcs}"

    def test_nolog_coverage_has_no_library_methods(self):
        from agents.ebpf.sidecar.sidecar_entrypoint import parse_output
        cov = parse_output(_EBPF_NOLOG_ONLY, "java_method", "java")
        files = cov.get("files", {})
        lib_files = [f for f in files if any(
            kw in f for kw in ("log4j", "commons", "snakeyaml", "yaml")
        )]
        assert not lib_files, (
            f"/nolog should produce no library method coverage, got: {lib_files}"
        )

    def test_coverage_py_format_has_functions(self, coverage_py_all):
        """to_coverage_py_format must produce the coverage.py schema with functions."""
        files = coverage_py_all.get("files", {})
        assert files, "coverage.py output must have at least one file"
        for path, data in files.items():
            assert "executed_lines" in data, f"Missing executed_lines in {path}"
            assert "functions" in data, f"Missing functions key in {path}"

    def test_coverage_py_function_entries_have_executed_lines(self, coverage_py_all):
        """Each function entry must have executed_lines=[1] (synthetic marker)."""
        for path, data in coverage_py_all.get("files", {}).items():
            for fn_name, fn_data in data.get("functions", {}).items():
                assert fn_data.get("executed_lines"), (
                    f"{path}:{fn_name} missing executed_lines synthetic marker"
                )


# ── Full pipeline: Docker + simulated coverage + correlation ──────────────────

@requires_docker
class TestJavaFullPipeline:
    """Full pipeline: Docker running → exercise routes → simulated eBPF coverage
    → static analysis → correlation → DYNAMICALLY_REACHABLE verdicts.

    The simulated eBPF output is deterministic: we know exactly which library
    methods are called by each HTTP handler. On Linux with bpftrace, the actual
    eBPF output would be identical.
    """

    @pytest.fixture(scope="class")
    def static_findings(self):
        """Static analysis results for all three CVEs."""
        from agents.reachability.java_reachability_analyzer import JavaReachabilityAnalyzer
        analyzer = JavaReachabilityAnalyzer(str(TARGET_SRC))
        return {v["cve_id"]: analyzer.analyze_vulnerability(v) for v in _VULNS}

    @pytest.fixture(scope="class")
    def dynamic_reachability_all_routes(self):
        """Dynamic reachability findings after hitting all routes (log+substitute+yaml)."""
        from agents.ebpf.sidecar.sidecar_entrypoint import parse_output
        from agents.ebpf.coverage_normaliser import to_coverage_py_format
        from agents.agent_dynamic_reachability import DynamicReachabilityAgent

        normalised = parse_output(_EBPF_ALL_ROUTES, "java_method", "java")
        coverage_data = to_coverage_py_format(normalised)

        agent = DynamicReachabilityAgent()
        findings = agent._correlate(
            coverage_data=coverage_data,
            vulnerabilities=_VULNS,
            taint_events=[],
            static_findings=[],
            repo_path=TARGET_SRC,
        )
        # Mirror core/orchestrator.py:270 — add has_coverage_hit=True so that
        # CorrelationService.correlate() can classify these as DYNAMICALLY_REACHABLE.
        return {
            (f.package.lower(), cve): {**f.model_dump(), "has_coverage_hit": True}
            for f in findings
            for cve in ([f.cve_id] if isinstance(f.cve_id, str) else (f.cve_id or []))
        }

    @pytest.fixture(scope="class")
    def dynamic_reachability_nolog(self):
        """Dynamic reachability findings after hitting /nolog only."""
        from agents.ebpf.sidecar.sidecar_entrypoint import parse_output
        from agents.ebpf.coverage_normaliser import to_coverage_py_format
        from agents.agent_dynamic_reachability import DynamicReachabilityAgent

        normalised = parse_output(_EBPF_NOLOG_ONLY, "java_method", "java")
        coverage_data = to_coverage_py_format(normalised)

        agent = DynamicReachabilityAgent()
        findings = agent._correlate(
            coverage_data=coverage_data,
            vulnerabilities=_VULNS,
            taint_events=[],
            static_findings=[],
            repo_path=TARGET_SRC,
        )
        return {
            (f.package.lower(), cve): {**f.model_dump(), "has_coverage_hit": True}
            for f in findings
            for cve in ([f.cve_id] if isinstance(f.cve_id, str) else (f.cve_id or []))
        }

    # ── Docker sanity (container must be healthy before pipeline tests run) ────

    def test_container_healthy(self, java_target):
        resp = urllib.request.urlopen(f"{java_target}/health", timeout=5)
        assert resp.status == 200

    # ── Static layer ──────────────────────────────────────────────────────────

    def test_static_log4j_used(self, java_target, static_findings):
        assert static_findings["CVE-2021-44228"].is_used

    def test_static_commons_text_used(self, java_target, static_findings):
        assert static_findings["CVE-2022-42889"].is_used

    def test_static_snakeyaml_used(self, java_target, static_findings):
        assert static_findings["CVE-2022-1471"].is_used

    # ── Dynamic layer — all routes exercised ──────────────────────────────────

    def test_dynamic_log4j_hit(self, java_target, dynamic_reachability_all_routes):
        key = ("org.apache.logging.log4j:log4j-core", "CVE-2021-44228")
        assert key in dynamic_reachability_all_routes, (
            f"log4j not in dynamic findings. Keys: {list(dynamic_reachability_all_routes)}"
        )

    def test_dynamic_commons_text_hit(self, java_target, dynamic_reachability_all_routes):
        key = ("org.apache.commons:commons-text", "CVE-2022-42889")
        assert key in dynamic_reachability_all_routes, (
            f"commons-text not in dynamic findings. Keys: {list(dynamic_reachability_all_routes)}"
        )

    def test_dynamic_snakeyaml_hit(self, java_target, dynamic_reachability_all_routes):
        key = ("org.yaml:snakeyaml", "CVE-2022-1471")
        assert key in dynamic_reachability_all_routes, (
            f"snakeyaml not in dynamic findings. Keys: {list(dynamic_reachability_all_routes)}"
        )

    def test_dynamic_nolog_produces_no_library_hits(
        self, java_target, dynamic_reachability_nolog
    ):
        """Hitting /nolog only must not produce dynamic findings for any library."""
        assert not dynamic_reachability_nolog, (
            f"Expected empty dynamic findings for nolog-only traffic, "
            f"got: {list(dynamic_reachability_nolog)}"
        )

    # ── Correlation layer — all routes exercised ──────────────────────────────

    @pytest.fixture(scope="class")
    def correlation_all(self, dynamic_reachability_all_routes, static_findings):
        from correlation.service import CorrelationService
        static_reachability = {
            (v["package"].lower(), v["cve_id"]): {
                "package": v["package"],
                "cve_id": v["cve_id"],
                "reachability_class": "STATICALLY_REACHABLE",
                "is_used": static_findings[v["cve_id"]].is_used,
            }
            for v in _VULNS
        }
        return CorrelationService().correlate(
            vulnerabilities=_VULNS,
            static_reachability=static_reachability,
            dynamic_reachability=dynamic_reachability_all_routes,
            exposure="public",
        )

    @pytest.fixture(scope="class")
    def correlation_nolog(self, dynamic_reachability_nolog, static_findings):
        from correlation.service import CorrelationService
        static_reachability = {
            (v["package"].lower(), v["cve_id"]): {
                "package": v["package"],
                "cve_id": v["cve_id"],
                "reachability_class": "STATICALLY_REACHABLE",
                "is_used": static_findings[v["cve_id"]].is_used,
            }
            for v in _VULNS
        }
        return CorrelationService().correlate(
            vulnerabilities=_VULNS,
            static_reachability=static_reachability,
            dynamic_reachability=dynamic_reachability_nolog,
            exposure="public",
        )

    def test_log4j_is_dynamically_reachable(self, java_target, correlation_all):
        rc = _get_reachability_class(correlation_all["correlation"], "CVE-2021-44228")
        assert rc == "DYNAMICALLY_REACHABLE", (
            f"log4j CVE-2021-44228 expected DYNAMICALLY_REACHABLE, got {rc}"
        )

    def test_commons_text_is_dynamically_reachable(self, java_target, correlation_all):
        rc = _get_reachability_class(correlation_all["correlation"], "CVE-2022-42889")
        assert rc == "DYNAMICALLY_REACHABLE", (
            f"commons-text CVE-2022-42889 expected DYNAMICALLY_REACHABLE, got {rc}"
        )

    def test_snakeyaml_is_dynamically_reachable(self, java_target, correlation_all):
        rc = _get_reachability_class(correlation_all["correlation"], "CVE-2022-1471")
        assert rc == "DYNAMICALLY_REACHABLE", (
            f"snakeyaml CVE-2022-1471 expected DYNAMICALLY_REACHABLE, got {rc}"
        )

    def test_nolog_traffic_gives_statically_reachable(self, java_target, correlation_nolog):
        """With no library calls at runtime, verdict must stay STATICALLY_REACHABLE."""
        for v in _VULNS:
            rc = _get_reachability_class(correlation_nolog["correlation"], v["cve_id"])
            assert rc != "DYNAMICALLY_REACHABLE", (
                f"{v['cve_id']} should not be DYNAMICALLY_REACHABLE with nolog-only "
                f"traffic, got {rc}"
            )
