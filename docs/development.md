# Developer Guide

## Table of Contents

- [Project Layout](#project-layout)
- [Dev Environment](#dev-environment)
- [Running Tests](#running-tests)
- [How the Pipeline Works](#how-the-pipeline-works)
- [Adding a New Agent](#adding-a-new-agent)
- [Correlation Engine](#correlation-engine)
- [Tainter — Optional Taint Analysis](#tainter--optional-taint-analysis)
- [Database Schema](#database-schema)

---

## Project Layout

```
vulnreach-agent/
├── agents/                 # One file per agent
│   ├── agent_trivy.py
│   ├── agent_tainter.py
│   ├── agent_dynamic_reachability.py
│   └── ...
├── api/
│   ├── server.py           # FastAPI app, endpoints, middleware
│   ├── auth.py             # JWT, bcrypt, UserPrincipal
│   └── export.py           # PDF report builder
├── config/
│   ├── schema.py           # Pydantic config models + loader
│   ├── scan.sample.yml     # Annotated full config example
│   └── scan.test.yml       # Minimal test config
├── core/
│   ├── agent.py            # BaseAgent / BaseTool abstract classes
│   ├── models.py           # ScanContext, AgentResult, ReachabilityFinding
│   └── orchestrator.py     # Runs agents, builds evidence maps, calls correlation
├── correlation/
│   ├── engine.py           # Pure functions: verdicts, risk score, classify_reachability
│   └── service.py          # CorrelationService.correlate() — merges all evidence
├── storage/
│   └── repository.py       # PostgresRepository — all DB reads/writes
├── intelligent_dast/       # LLM-steered DAST runner
├── labs/                   # Vulnerable test apps (pygoat, python_vuln_app, multitier)
├── tests/                  # Unit tests
├── docs/                   # This documentation
├── Dockerfile
├── docker-compose.yml
└── requirements.txt
```

---

## Dev Environment

```bash
git clone https://github.com/OWASP/VulnReach.git
cd VulnReach

python -m venv .env
source .env/bin/activate
pip install -r requirements.txt
pip install schemathesis coverage pytest pytest-cov

cp .env.example .env.local
# Edit .env.local: DATABASE_URL, JWT_SECRET, SEED_ADMIN_USERNAME, SEED_ADMIN_PASSWORD

# Start Postgres (or use the bundled compose service):
docker compose up postgres -d

uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

---

## Running Tests

```bash
# All unit tests
pytest tests/ -v

# With coverage report
pytest tests/ --cov=. --cov-report=term-missing --cov-fail-under=60

# Single module
pytest tests/test_correlation.py -v
```

Test targets in `labs/python_vuln_app` and `labs/pygoat` can be used for manual integration testing.

---

## How the Pipeline Works

A scan request flows through three layers:

### 1. Agents (`agents/runner.py`)

`AgentRunner.run_all()` executes agents in dependency order. Each agent implements `BaseAgent.run(context: ScanContext) -> AgentResult`. Agents communicate only through `ScanContext` (shared mutable state) and their returned `AgentResult`.

Key context fields populated as the pipeline runs:

| Field | Set by | Used by |
|-------|--------|---------|
| `context.vulnerabilities` | TrivyAgent | All reachability agents |
| `context.repo_path` | GitAgent | All file-reading agents |
| `context.import_map` | MetadataAgent | Dynamic reachability agent |

### 2. Orchestrator (`core/orchestrator.py`)

After all agents complete, the orchestrator:

1. Builds `static_reach_map` — per-CVE static evidence from `tainter` + `python_reachability`
2. Builds `dynamic_reach_map` — per-CVE dynamic evidence from `dynamic_reachability` + `pytest_coverage`, gated on the full evidence chain (SCA → taint → routes → static → coverage)
3. Calls `CorrelationService.correlate()` with both maps

### 3. Correlation Engine (`correlation/`)

`engine.py` contains pure functions — no I/O, fully testable:

- `reachability_verdict()` — static evidence → CONFIRMED/LIKELY/POSSIBLE/NOT_OBSERVED
- `dynamic_reachability_verdict()` — taint + coverage → verdict
- `classify_reachability()` — assigns one of 4 reachability tiers
- `risk_score()` — severity × reachability multiplier × exposure modifier

`service.py` contains `CorrelationService.correlate()` which iterates all vulnerabilities, merges static + dynamic evidence per CVE, classifies each finding, and applies policy rules.

---

## Adding a New Agent

### 1. Create the agent file

```python
# agents/agent_myagent.py
from core.agent import BaseAgent
from core.models import AgentResult, ScanContext

class MyAgent(BaseAgent):
    tool_name = "my_agent"

    async def run(self, context: ScanContext) -> AgentResult:
        if not context.repo_path:
            return AgentResult(
                tool_name=self.tool_name,
                findings=[],
                metadata={"status": "skipped", "reason": "no_repo_path"},
            )

        # ... do work ...
        findings = [{"cve_id": "CVE-...", "package": "requests", ...}]

        return AgentResult(
            tool_name=self.tool_name,
            findings=findings,
            metadata={"status": "ok", "finding_count": len(findings)},
        )
```

### 2. Register in the runner

```python
# agents/runner.py — add to TOOL_REGISTRY
from agents.agent_myagent import MyAgent

TOOL_REGISTRY = {
    ...
    "my_agent": MyAgent,
}
```

### 3. Wire findings into the orchestrator (if needed)

If your agent produces reachability evidence, add a block in `core/orchestrator.py` similar to the `tainter` or `dynamic_reachability` blocks.

### 4. Write tests

```python
# tests/test_agent_myagent.py
import pytest
from unittest.mock import AsyncMock, patch
from agents.agent_myagent import MyAgent
from core.models import ScanContext

@pytest.mark.asyncio
async def test_skips_without_repo_path():
    agent = MyAgent()
    ctx = ScanContext(scan_id="test", repo_path="")
    result = await agent.run(ctx)
    assert result.metadata["status"] == "skipped"
```

### 5. Document it

Add a row to the tools table in [configuration.md](configuration.md) and a section in [architecture.md](architecture.md).

---

## Correlation Engine

The engine uses a confidence ladder to score findings:

| Confidence | Evidence |
|-----------|---------|
| 0.95–0.99 | Runtime call-site execution + taint flow (compounded) |
| 0.95 | Runtime call-site execution + taint flow |
| 0.75–0.82 | Runtime call-site execution, no taint; or taint + coverage (compounded) |
| 0.65 | Import-time execution confirmed |
| 0.40 | File-level coverage, import detected |
| 0.30 | Taint-only, no runtime confirmation |
| 0.10 | No evidence |

When both static (`tainter`/`python_reachability`) and dynamic (coverage) evidence agree on the same CVE, confidence is compounded: `min(0.99, base × 1.10)`.

---

## Tainter — Optional Taint Analysis

`tainter` is a static taint analysis CLI that traces user-controlled inputs to dangerous sinks (SQL queries, subprocess calls, YAML deserialization, pickle, etc.).

**VulnReach works without tainter.** The agent skips gracefully when `tainter` is not on PATH. Dynamic reachability, static AST analysis, and SCA all continue to function.

**Installing tainter:**

```bash
pip install tainter
```

**What tainter adds:**

- Identifies which CVE packages are in the call path of a tainted (user-controlled) input
- Elevates CVE confidence from `LIKELY` to `CONFIRMED` when combined with runtime coverage
- Enables `intelligent_dast` to generate targeted exploit payloads for confirmed flows

**Without tainter:**

- CVEs are still discovered (Trivy)
- Static reachability still works (AST analysis)
- Dynamic reachability still works (coverage only)
- Confidence scores are slightly lower (no taint compounding)
- `intelligent_dast` is unavailable (requires taint flows as input)

---

## Database Schema

Tables are auto-created on startup by `PostgresRepository._ensure_schema()`.

| Table | Purpose |
|-------|---------|
| `scans` | Top-level scan records (id, status, metadata JSONB, created_at) |
| `vulnerabilities` | CVEs from Trivy per scan |
| `reachability_evidence` | Per-CVE static + dynamic evidence |
| `correlation_results` | Final classified findings with risk scores |
| `raw_outputs` | Full JSON output from each agent |
| `semgrep_findings` | Semgrep SAST results |
| `routes_extracted` | HTTP routes from route_extractor |
| `users` | Auth users (id, username, password_hash, role) |
