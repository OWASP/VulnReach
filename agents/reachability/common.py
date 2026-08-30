from dataclasses import dataclass, asdict
from enum import Enum
from typing import List, Optional


class CriticalityLevel(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    NOT_REACHABLE = "NOT_REACHABLE"


@dataclass
class UsageContext:
    file_path: str
    line_number: int
    context_line: str
    usage_type: str
    enclosing_scope: Optional[str] = None


@dataclass
class VulnAnalysis:
    package_name: str
    installed_version: str
    recommended_version: str
    is_used: bool
    usage_contexts: List[UsageContext]
    criticality: CriticalityLevel
    risk_reason: str
    call_chain_graph: Optional[str] = None


def normalize_severity(severity: str) -> CriticalityLevel:
    mapping = {
        "CRITICAL": CriticalityLevel.CRITICAL,
        "HIGH": CriticalityLevel.HIGH,
        "MEDIUM": CriticalityLevel.MEDIUM,
        "LOW": CriticalityLevel.LOW,
    }
    return mapping.get(severity.upper(), CriticalityLevel.MEDIUM)


def build_report_dict(
    analyses: List[VulnAnalysis],
    project_root: str,
    language: str,
) -> dict:
    return {
        "project_root": project_root,
        "language": language,
        "total_vulnerabilities": len(analyses),
        "reachable_vulnerabilities": sum(1 for a in analyses if a.is_used),
        "not_reachable_vulnerabilities": sum(1 for a in analyses if not a.is_used),
        "analyses": [
            {
                "package_name": a.package_name,
                "installed_version": a.installed_version,
                "recommended_version": a.recommended_version,
                "criticality": a.criticality.value,
                "is_used": a.is_used,
                "risk_reason": a.risk_reason,
                "call_chain_graph": a.call_chain_graph,
                "usage_count": len(a.usage_contexts),
                "usage_contexts": [asdict(uc) for uc in a.usage_contexts[:5]],
            }
            for a in analyses
        ],
    }


__all__ = [
    "CriticalityLevel",
    "UsageContext",
    "VulnAnalysis",
    "normalize_severity",
    "build_report_dict",
]
