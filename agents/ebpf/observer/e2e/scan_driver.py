"""Full-scan e2e harness: drive DynamicReachabilityAgent._run_observer_mode
against labs/python_vuln_app.

Not part of the auto pytest suite (heavy: builds the target image, needs host
networking + docker socket). Run it inside the scan-runner container — see
agents/ebpf/observer/README.md "Full-scan e2e".

Validated result (2026-08-01, Docker Desktop 6.12, R2+R4 active):
  CONFIRMED 0.9 : Flask, requests           (R1 load + R4 taint path)
  CONFIRMED 0.8 : PyYAML                    (R2 — _yaml C ext mapped PROT_EXEC)
  LIKELY    0.65: Jinja2, Werkzeug, urllib3 (loaded, no taint path)
  NOT_OBSERVED  : lxml, cryptography, SQLAlchemy, PyJWT, Pillow (never loaded)
"""
import asyncio
import json
import os
from pathlib import Path

os.environ["VULNREACH_ALLOW_EBPF"] = "1"
os.environ["VULNREACH_TARGET_HOST"] = "localhost"
os.environ.setdefault("VULNREACH_OBSERVER_BIN", "/repo/agents/ebpf/observer/bin/vulnreach-observer")

from core.models import ScanContext
from config.schema import RuntimeSettings, EbpfSettings
from agents.agent_dynamic_reachability import DynamicReachabilityAgent

APP = os.environ.get("VULNREACH_TARGET_APP", "/repo/labs/python_vuln_app")

VULN_PKGS = ["Flask", "requests", "lxml", "PyYAML", "cryptography",
             "Jinja2", "SQLAlchemy", "PyJWT", "Pillow", "Werkzeug", "urllib3"]
vulns = [{"package": p, "cve_id": [f"CVE-TEST-{p.upper()}"], "severity": "HIGH"}
         for p in VULN_PKGS]

# Real static taint flows produced by the tainter for this app (Rule R4 input).
try:
    with open(f"{APP}/findings.json", encoding="utf-8") as fh:
        taint_flows = json.load(fh).get("flows", [])
except (OSError, ValueError):
    taint_flows = []

ctx = ScanContext(repo_path=APP, repo_name="python_vuln_app", scan_id="obs-e2e",
                  vulnerabilities=vulns, import_map={}, taint_flows=taint_flows)
runtime = RuntimeSettings(enabled=True, timeout=90, coverage_wait=20, container_port=3000,
                          ebpf=EbpfSettings(enabled=True, engine="observer"))
preflight = {"mode": "dockerfile",
             "dockerfile_path": f"{APP}/Dockerfile",
             "openapi_path": f"{APP}/openapi.json"}

agent = DynamicReachabilityAgent(default_timeout=90)


async def main():
    res = await agent._run_observer_mode(ctx, Path(APP), runtime, preflight)
    print("\n===== AgentResult.metadata =====")
    print(json.dumps(res.metadata, indent=2, default=str))
    findings = res.findings or []
    print(f"\n===== findings ({len(findings)}) =====")
    reached = 0
    for f in findings:
        d = f if isinstance(f, dict) else f.model_dump()
        if d.get("verdict") in ("CONFIRMED", "LIKELY"):
            reached += 1
        print(f"  {str(d.get('verdict')):12} {str(d.get('package')):14} "
              f"import_time_hit={d.get('import_time_hit')} conf={d.get('confidence')} "
              f"files={len(d.get('files') or [])}")
    print(f"\nreached(CONFIRMED+LIKELY)={reached}  status={res.metadata.get('status')}")


asyncio.run(main())
