import asyncio

from agents.runner import AgentRunner
from config.schema import default_config
from core.models import AgentResult, ScanContext


class _Storage:
    def __init__(self) -> None:
        self.raw_outputs = []
        self.reachability = []

    def store_raw_output(self, scan_id, tool_name, payload):
        self.raw_outputs.append((scan_id, tool_name, payload))

    def store_vulnerabilities(self, scan_id, findings):
        return None

    def store_reachability(self, scan_id, findings):
        self.reachability.append((scan_id, list(findings)))

    def store_semgrep_findings(self, scan_id, findings):
        return None

    def store_routes(self, scan_id, findings):
        return None


def test_runner_runs_taint_for_mixed_repo_but_skips_pytest(monkeypatch, tmp_path):
    """tainter analyzes JS/Go/Java too, so it runs for a python+javascript repo.

    pytest_coverage is genuinely Python-only and stays skipped for a mixed repo;
    dynamic_reachability is language-agnostic and always runs.
    """
    config = default_config()
    config.scan.tools = ["tainter", "pytest_coverage"]
    config.scan.runtime.enabled = True

    runner = AgentRunner(_Storage())
    calls = []

    def _make_runner(tool_name):
        async def _run(_context):
            calls.append(tool_name)
            return AgentResult(tool_name=tool_name, findings=[], metadata={"status": "ok"})
        return _run

    async def _should_not_run(_context):
        calls.append("pytest_called")
        return AgentResult(tool_name="unexpected", findings=[], metadata={})

    runner.tainter.run = _make_runner("tainter")
    runner.dynamic_reachability.run = _make_runner("dynamic_reachability")
    runner.pytest_coverage.run = _should_not_run

    monkeypatch.setattr(runner, "_detect_project_languages", lambda context: ["python", "javascript"])

    context = ScanContext(repo_path=str(tmp_path), config=config, scan_id="scan-1")
    results = asyncio.run(runner.run_all(context))

    statuses = {result.tool_name: result.metadata.get("status") for result in results}
    # tainter now runs (javascript is taint-supported); it must precede the
    # static/runtime stages so its flows are available.
    assert "tainter" in calls
    assert statuses["tainter"] == "ok"
    # pytest_coverage is Python-only and this repo is not python-only.
    assert "pytest_called" not in calls
    assert statuses["pytest_coverage"] == "skipped"
    assert statuses["dynamic_reachability"] == "ok"


def test_runner_skips_taint_for_unsupported_language_only_repo(monkeypatch, tmp_path):
    """A repo in a language tainter cannot analyze (e.g. PHP) skips taint cleanly."""
    config = default_config()
    config.scan.tools = ["tainter"]
    config.scan.runtime.enabled = False

    runner = AgentRunner(_Storage())
    calls = []

    async def _should_not_run(_context):
        calls.append("called")
        return AgentResult(tool_name="unexpected", findings=[], metadata={})

    runner.tainter.run = _should_not_run
    monkeypatch.setattr(runner, "_detect_project_languages", lambda context: ["php"])

    context = ScanContext(repo_path=str(tmp_path), config=config, scan_id="scan-3")
    results = asyncio.run(runner.run_all(context))

    assert "called" not in calls
    statuses = {result.tool_name: result.metadata.get("status") for result in results}
    assert statuses["tainter"] == "skipped"


def test_runner_allows_taint_and_runtime_for_python_only_repo(monkeypatch, tmp_path):
    config = default_config()
    config.scan.tools = ["tainter", "pytest_coverage"]
    config.scan.runtime.enabled = True

    runner = AgentRunner(_Storage())
    calls = []

    def _make_runner(tool_name):
        async def _run(_context):
            calls.append(tool_name)
            return AgentResult(tool_name=tool_name, findings=[], metadata={"status": "ok"})

        return _run

    runner.tainter.run = _make_runner("tainter")
    runner.dynamic_reachability.run = _make_runner("dynamic_reachability")
    runner.pytest_coverage.run = _make_runner("pytest_coverage")

    monkeypatch.setattr(runner, "_detect_project_languages", lambda context: ["python"])

    context = ScanContext(repo_path=str(tmp_path), config=config, scan_id="scan-2")
    results = asyncio.run(runner.run_all(context))

    assert calls == ["tainter", "dynamic_reachability", "pytest_coverage"]
    statuses = {result.tool_name: result.metadata.get("status") for result in results}
    assert statuses["tainter"] == "ok"
    assert statuses["dynamic_reachability"] == "ok"
    assert statuses["pytest_coverage"] == "ok"
