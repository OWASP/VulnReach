#!/usr/bin/env python3
"""
Go Vulnerability Reachability Analyzer

Analyzes whether vulnerable Go packages are actually used in the codebase,
providing intelligent risk assessment beyond simple version checking.
"""

import json
import os
import re
from pathlib import Path
from typing import Dict, List, Set, Any

from .common import (CriticalityLevel, UsageContext, VulnAnalysis,
                     normalize_severity, build_report_dict)


class GoReachabilityAnalyzer:
    def __init__(self, project_root: str):
        self.project_root = Path(project_root)
        self._go_mod_dependencies: Dict[str, Dict[str, Any]] | None = None
        # Common Go import patterns
        self.import_patterns = [
            # Single import
            re.compile(r'^\s*import\s+"([^"]+)"'),
            # Aliased import
            re.compile(r'^\s*import\s+\w+\s+"([^"]+)"'),
            # Blank import
            re.compile(r'^\s*import\s+_\s+"([^"]+)"'),
            # Multi-line imports
            re.compile(r'^\s*"([^"]+)"'),
        ]

    def _normalize_module_name(self, package_name: str) -> str:
        raw = (package_name or "").strip()
        if not raw:
            return ""
        if raw.startswith("pkg:golang/"):
            raw = raw[len("pkg:golang/"):]
        return raw.split("@", 1)[0].strip()

    def find_go_files(self, include_tests: bool = False) -> List[Path]:
        """Find all Go source files in the project."""
        go_files = []
        for root, dirs, files in os.walk(self.project_root):
            # Skip common non-code directories
            dirs[:] = [d for d in dirs if d not in {
                '.git', 'vendor', 'bin', '.idea', '.vscode'
            }]
            for file in files:
                if file.endswith('.go'):
                    if include_tests or not file.endswith('_test.go'):
                        go_files.append(Path(root) / file)
        return go_files

    def extract_imports(self, file_path: Path) -> Set[str]:
        """Extract import statements from a Go file."""
        imports = set()
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                in_import_block = False
                for line in f:
                    # Check for import block start
                    if re.match(r'^\s*import\s*\(', line):
                        in_import_block = True
                        continue

                    # Check for import block end
                    if in_import_block and ')' in line:
                        in_import_block = False
                        continue

                    # Parse imports
                    for pattern in self.import_patterns:
                        match = pattern.match(line)
                        if match:
                            imports.add(match.group(1))
                            break
        except Exception as e:
            print(f"Warning: Could not parse {file_path}: {e}")
        return imports

    def find_package_usage(self, package_name: str) -> List[UsageContext]:
        """Find all usages of a package in the codebase."""
        if not package_name:
            return []

        usage_contexts = []
        go_files = self.find_go_files()

        block_import_pattern = re.compile(r'^\s*(?:\w+\s+|_\s+)?"([^"]+)"')

        for go_file in go_files:
            try:
                with open(go_file, 'r', encoding='utf-8', errors='ignore') as f:
                    # Phase 1: collect import paths from import blocks only
                    in_import_block = False
                    collected = []  # list of (line_num, import_path, raw_line)

                    for line_num, line in enumerate(f, 1):
                        if re.match(r'^\s*import\s*\(', line):
                            in_import_block = True
                            continue
                        if in_import_block and ')' in line:
                            in_import_block = False
                            continue
                        if in_import_block:
                            match = block_import_pattern.match(line)
                            if match:
                                collected.append((line_num, match.group(1), line))

                # Phase 2: check if package_name appears in any collected import path
                for line_num, import_path, raw_line in collected:
                    if self._module_paths_overlap(import_path, package_name):
                        usage_type = "import"
                        if "_ " in raw_line:
                            usage_type = "blank_import"
                        elif re.match(r'^\s*\w+\s+"', raw_line):
                            usage_type = "aliased_import"
                        usage_contexts.append(UsageContext(
                            file_path=str(go_file.relative_to(self.project_root)),
                            line_number=line_num,
                            context_line=raw_line.strip(),
                            usage_type=usage_type
                        ))
            except Exception as e:
                print(f"Warning: Could not read {go_file}: {e}")

        return usage_contexts

    def _module_paths_overlap(self, left: str, right: str) -> bool:
        lhs = self._normalize_module_name(left)
        rhs = self._normalize_module_name(right)
        if not lhs or not rhs:
            return False
        return lhs == rhs or lhs.startswith(rhs + "/") or rhs.startswith(lhs + "/")

    def parse_go_mod(self) -> Dict[str, Dict[str, Any]]:
        """Parse dependencies from go.mod."""
        if self._go_mod_dependencies is not None:
            return self._go_mod_dependencies

        dependencies: Dict[str, Dict[str, Any]] = {}
        go_mod_file = self.project_root / "go.mod"

        if not go_mod_file.exists():
            self._go_mod_dependencies = dependencies
            return dependencies

        try:
            with open(go_mod_file, 'r', encoding='utf-8') as f:
                in_require_block = False
                for line_num, raw_line in enumerate(f, 1):
                    line = raw_line.strip()

                    # Check for require block
                    if re.match(r'^require\s*\(', line):
                        in_require_block = True
                        continue
                    elif in_require_block and line == ')':
                        in_require_block = False
                        continue

                    # Parse require statements
                    if in_require_block or line.startswith('require '):
                        # Remove 'require ' prefix if single-line
                        if line.startswith('require '):
                            line = line[8:]

                        # Parse package and version
                        parts = line.split()
                        if len(parts) >= 2:
                            package = self._normalize_module_name(parts[0])
                            version = parts[1]
                            dependencies[package] = {
                                "version": version,
                                "line": line_num,
                                "raw": raw_line.strip(),
                            }
        except Exception as e:
            print(f"Warning: Could not parse go.mod: {e}")

        self._go_mod_dependencies = dependencies
        return dependencies

    def analyze_vulnerability(self, vuln_data: Dict) -> VulnAnalysis:
        """Analyze a single vulnerability for reachability."""
        package_name = self._normalize_module_name(
            vuln_data.get('package_name') or vuln_data.get('package') or ''
        )
        installed_version = vuln_data.get('installed_version') or vuln_data.get('version', '')
        recommended_version = (
            vuln_data.get('recommended_version')
            or vuln_data.get('recommended_fixed_version')
            or vuln_data.get('fixed_version', '')
        )

        # Find usages (imports + go.mod declaration)
        import_usages = self.find_package_usage(package_name)
        go_mod_deps = self.parse_go_mod()
        declared_usages: List[UsageContext] = []
        for dep_name, dep_meta in go_mod_deps.items():
            if self._module_paths_overlap(dep_name, package_name):
                declared_usages.append(
                    UsageContext(
                        file_path="go.mod",
                        line_number=int(dep_meta.get("line", 1)),
                        context_line=str(dep_meta.get("raw", f"require {dep_name} {dep_meta.get('version','')}")).strip(),
                        usage_type="declared_dependency",
                    )
                )

        usage_contexts = import_usages + declared_usages
        is_used = len(usage_contexts) > 0

        # Determine criticality
        if not is_used:
            criticality = CriticalityLevel.NOT_REACHABLE
            risk_reason = "Package not imported and not declared in go.mod"
        else:
            criticality = normalize_severity(vuln_data.get('severity', 'MEDIUM'))
            if import_usages and declared_usages:
                risk_reason = (
                    f"Package actively imported in {len(import_usages)} location(s) and "
                    f"declared in go.mod ({len(declared_usages)} location(s))"
                )
            elif import_usages:
                risk_reason = f"Package actively imported in {len(import_usages)} location(s)"
            else:
                risk_reason = f"Package declared in go.mod ({len(declared_usages)} location(s))"

        return VulnAnalysis(
            package_name=package_name,
            installed_version=installed_version,
            recommended_version=recommended_version,
            is_used=is_used,
            usage_contexts=usage_contexts,
            criticality=criticality,
            risk_reason=risk_reason
        )


def run_go_reachability_analysis(project_root: str, consolidated_path: str, output_path: str):
    """Main entry point for Go reachability analysis."""
    print(f"\n{'='*60}")
    print("Go Vulnerability Reachability Analysis")
    print(f"{'='*60}\n")

    # Load consolidated vulnerabilities
    try:
        with open(consolidated_path, 'r') as f:
            consolidated_data = json.load(f)
    except Exception as e:
        print(f"Error loading consolidated data: {e}")
        return

    analyzer = GoReachabilityAnalyzer(project_root)

    # Get installed dependencies
    installed_deps = analyzer.parse_go_mod()
    print(f"📦 Found {len(installed_deps)} Go packages")

    # Analyze each vulnerability
    analyses = []

    # Handle both list and dict formats
    if isinstance(consolidated_data, list):
        vulnerabilities = consolidated_data
    elif isinstance(consolidated_data, dict):
        vulnerabilities = consolidated_data.get('vulnerabilities', [])
    else:
        print("Error: consolidated data must be a list or dict")
        return

    print(f"🔍 Analyzing {len(vulnerabilities)} vulnerabilities...\n")

    for vuln in vulnerabilities:
        analysis = analyzer.analyze_vulnerability(vuln)
        analyses.append(analysis)

        # Print summary
        status = "✓ USED" if analysis.is_used else "✗ NOT USED"
        print(f"{status} | {analysis.package_name:30} | {analysis.criticality.value:15} | {analysis.risk_reason}")

    # Generate and save report
    report = build_report_dict(analyses, project_root, "go")

    os.makedirs(os.path.dirname(output_path) if os.path.dirname(output_path) else '.', exist_ok=True)
    with open(output_path, 'w') as f:
        json.dump(report, f, indent=2)

    print(f"\n{'='*60}")
    print(f"✓ Report saved to: {output_path}")
    print(f"{'='*60}\n")


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 3:
        print("Usage: python go_reachability_analyzer.py <project_root> <consolidated_json> [output_path]")
        sys.exit(1)

    project_root = sys.argv[1]
    consolidated_path = sys.argv[2]
    output_path = sys.argv[3] if len(sys.argv) > 3 else "go_vulnerability_reachability_report.json"

    run_go_reachability_analysis(project_root, consolidated_path, output_path)
