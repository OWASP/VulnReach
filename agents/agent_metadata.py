# utils/get_metadata.py
import json
import re
from importlib import metadata as md
from typing import Dict

from core.agent import BaseTool
from core.models import AgentResult, ImportMappingFinding, ScanContext


def is_ident(s):
    return re.match(r"^[A-Za-z_]\w*$", s)


def guess_imports(dist):
    files = dist.files or []
    tops = set()
    for f in files:
        p = str(f)
        if ".dist-info" in p or ".data" in p:
            continue
        if p.endswith("__init__.py") and "/" in p:
            top = p.split("/", 1)[0]
            if is_ident(top):
                tops.add(top)
        elif "/" not in p and p.endswith(".py"):
            mod = p[:-3]
            if is_ident(mod):
                tops.add(mod)
    if not tops:
        guess = dist.metadata["Name"].lower().replace("-", "_")
        if is_ident(guess):
            tops.add(guess)
    return sorted(tops)


def get_package_mappings():
    """Return dictionary mapping import names to distribution names"""
    import_to_dist: Dict[str, str] = {}

    for dist in md.distributions():
        dist_name = dist.metadata["Name"].lower()
        guessed_imports = guess_imports(dist)

        # Map each guessed import name to the distribution name
        for import_name in guessed_imports:
            import_to_dist[import_name.lower()] = dist_name

    return import_to_dist


class MetadataAgent(BaseTool):
    tool_name = "metadata"

    async def run(self, context: ScanContext) -> AgentResult:  # type: ignore[override]
        try:
            mapping = get_package_mappings()
            findings = [ImportMappingFinding(import_name=k, distribution=v).model_dump() for k, v in mapping.items()]
            return AgentResult.model_validate(
                {
                    "tool_name": self.tool_name,
                    "findings": findings,
                    "metadata": {"status": "ok", "finding_count": len(findings), "raw": mapping},
                }
            )
        except Exception as exc:  # pragma: no cover
            return AgentResult(tool_name=self.tool_name, findings=[], metadata={"error": "metadata_failed", "details": str(exc)})


if __name__ == "__main__":
    mappings = get_package_mappings()
    print(json.dumps(mappings, indent=2))