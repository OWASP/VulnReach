from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


@dataclass
class ScanContext:
    """Shared context passed to agents while scanning a repository."""

    repo_path: Optional[str] = None
    repo_url: Optional[str] = None
    repo_name: Optional[str] = None
    config_path: Optional[str] = None
    config: Optional[Any] = None  # Populated after config parsing
    scan_id: Optional[str] = None
    vulnerabilities: List[Dict[str, Any]] = field(default_factory=list)
    import_map: Dict[str, str] = field(default_factory=dict)
    taint_flows: List[Dict[str, Any]] = field(default_factory=list)
    routes: List[Dict[str, Any]] = field(default_factory=list)
    detected_languages: List[str] = field(default_factory=list)


class VulnerabilityFinding(BaseModel):
    package: Optional[str] = None
    version: Optional[str] = None
    cve_id: List[str] = Field(default_factory=list)
    severity: Optional[str] = None
    fix_version: Optional[str] = None


class ReachabilityFinding(BaseModel):
    cve_id: Optional[str] = None
    package: Optional[str] = None
    import_detected: bool = False
    call_chain_exists: bool = False
    sink_reachable: bool = False
    verdict: Optional[str] = None
    confidence: float = 0.1
    evidence_type: Optional[str] = None  # "static" or "dynamic"
    import_time_hit: bool = False  # package loaded at import time but no function called
    function: Optional[str] = None
    files: List[Any] = Field(default_factory=list)
    line: Optional[int] = None  # line number of the executed callsite / import
    # For a vulnerable package the app does not import directly but that a
    # directly-used package depends on: the chain from a used root to this
    # package (e.g. ["flask", "werkzeug"]). Present ⇒ the POSSIBLE verdict is
    # transitive (reachable via a parent), not a direct source usage.
    reachable_via: Optional[List[str]] = None


class SemgrepFinding(BaseModel):
    check_id: Optional[str] = None
    path: Optional[str] = None
    start: Optional[Any] = None
    end: Optional[Any] = None
    extra: Optional[Dict[str, Any]] = None
    severity: Optional[str] = None


class RouteFinding(BaseModel):
    method: str
    path: str
    handler: Optional[str]
    file: str
    framework: str
    prefix: Optional[str] = None


class ImportMappingFinding(BaseModel):
    import_name: str
    distribution: str


class AgentResult(BaseModel):
    """Standardized result shape expected from all agents."""

    tool_name: str
    findings: List[Dict[str, Any]] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)
