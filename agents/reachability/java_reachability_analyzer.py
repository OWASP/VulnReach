"""
Java Vulnerability Reachability Analyzer

Analyzes whether vulnerable Java libraries are used in the codebase.
"""

import os
import re
import json
from pathlib import Path
from typing import Dict, List, Tuple

from .common import (CriticalityLevel, UsageContext, VulnAnalysis,
                     normalize_severity, build_report_dict)

try:
    from .java_call_graph import JavaCallGraphBuilder
    HAS_CALL_GRAPH = True
except ImportError:
    HAS_CALL_GRAPH = False

class JavaReachabilityAnalyzer:
    def __init__(self, project_root: str):
        self.project_root = Path(project_root)
        self.import_pattern = re.compile(r'import\s+([\w\.]+);')
        self._declared_dependencies = self._collect_declared_dependencies()

        # Initialize Call Graph
        self.call_graph_builder = None
        if HAS_CALL_GRAPH:
            try:
                print(f"🕸️  Building static call graph for {self.project_root}...")
                self.call_graph_builder = JavaCallGraphBuilder(str(self.project_root))
                self.call_graph_builder.build_graph()
                print(f"   Graph built: {len(self.call_graph_builder.graph)} functions, {len(self.call_graph_builder.entry_points)} entry points")
            except Exception as e:
                print(f"Warning: Could not build call graph: {e}")

    def _coord_key(self, group: str, artifact: str) -> Tuple[str, str]:
        return (group.strip().lower(), artifact.strip().lower())

    def _parse_package_coordinates(self, package_name: str) -> Tuple[str, str]:
        raw = (package_name or "").strip()
        if not raw:
            return "", ""

        # Trivy may surface Maven packages as "group:artifact" or purl:
        # "pkg:maven/group/artifact@version"
        if raw.startswith("pkg:maven/"):
            raw = raw[len("pkg:maven/"):]
            raw = raw.split("@", 1)[0]
            if "/" in raw:
                group, artifact = raw.split("/", 1)
                return group.strip(), artifact.strip()

        if ":" in raw:
            group, artifact = raw.split(":", 1)
            artifact = artifact.split("@", 1)[0]
            return group.strip(), artifact.strip()

        if "/" in raw:
            group, artifact = raw.split("/", 1)
            artifact = artifact.split("@", 1)[0]
            return group.strip(), artifact.strip()

        return "", raw.split("@", 1)[0].strip()

    def _collect_declared_dependencies(self) -> Dict[Tuple[str, str], List[UsageContext]]:
        declared: Dict[Tuple[str, str], List[UsageContext]] = {}
        for root, dirs, files in os.walk(self.project_root):
            dirs[:] = [d for d in dirs if d not in {
                '.git', '.idea', '.vscode', 'target', 'build', '.gradle', 'node_modules'
            }]

            for file in files:
                full_path = Path(root) / file
                if file == "pom.xml":
                    for dep in self._parse_pom_dependencies(full_path):
                        key = self._coord_key(dep["group"], dep["artifact"])
                        declared.setdefault(key, []).append(
                            UsageContext(
                                file_path=str(full_path.relative_to(self.project_root)),
                                line_number=dep["line"],
                                context_line=f"{dep['group']}:{dep['artifact']}",
                                usage_type="declared_dependency",
                                enclosing_scope=None,
                            )
                        )
                elif file in {"build.gradle", "build.gradle.kts"}:
                    for dep in self._parse_gradle_dependencies(full_path):
                        key = self._coord_key(dep["group"], dep["artifact"])
                        declared.setdefault(key, []).append(
                            UsageContext(
                                file_path=str(full_path.relative_to(self.project_root)),
                                line_number=dep["line"],
                                context_line=dep["raw"],
                                usage_type="declared_dependency",
                                enclosing_scope=None,
                            )
                        )
        return declared

    def _parse_pom_dependencies(self, pom_file: Path) -> List[Dict[str, str | int]]:
        deps: List[Dict[str, str | int]] = []
        dep_block_pattern = re.compile(r'<dependency\b[^>]*>(.*?)</dependency>', re.IGNORECASE | re.DOTALL)
        group_pattern = re.compile(r'<groupId>\s*([^<]+)\s*</groupId>', re.IGNORECASE)
        artifact_pattern = re.compile(r'<artifactId>\s*([^<]+)\s*</artifactId>', re.IGNORECASE)

        try:
            with open(pom_file, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
        except Exception:
            return deps

        for match in dep_block_pattern.finditer(content):
            block = match.group(1)
            group_match = group_pattern.search(block)
            artifact_match = artifact_pattern.search(block)
            if not group_match or not artifact_match:
                continue

            group = group_match.group(1).strip()
            artifact = artifact_match.group(1).strip()
            if not group or not artifact:
                continue

            line_number = content.count('\n', 0, match.start()) + 1
            deps.append(
                {
                    "group": group,
                    "artifact": artifact,
                    "line": line_number,
                }
            )
        return deps

    def _parse_gradle_dependencies(self, gradle_file: Path) -> List[Dict[str, str | int]]:
        deps: List[Dict[str, str | int]] = []
        conf = r'(?:api|implementation|compileOnly|runtimeOnly|testImplementation|testRuntimeOnly|annotationProcessor|kapt)'
        string_notation = re.compile(
            rf'^\s*{conf}\s*\(?\s*["\']([^"\']+)["\']\s*\)?'
        )
        map_notation = re.compile(
            rf'^\s*{conf}\s*\(?\s*group\s*:\s*["\']([^"\']+)["\']\s*,\s*name\s*:\s*["\']([^"\']+)["\']'
        )
        kotlin_named_notation = re.compile(
            rf'^\s*{conf}\s*\(\s*group\s*=\s*["\']([^"\']+)["\']\s*,\s*name\s*=\s*["\']([^"\']+)["\']'
        )

        try:
            with open(gradle_file, 'r', encoding='utf-8', errors='ignore') as f:
                for line_num, line in enumerate(f, 1):
                    m = string_notation.search(line)
                    if m:
                        coordinate = m.group(1).strip()
                        # Ignore project/module references like project(":app-core")
                        if coordinate.startswith("project("):
                            continue
                        parts = coordinate.split(":")
                        if len(parts) >= 2:
                            deps.append(
                                {
                                    "group": parts[0].strip(),
                                    "artifact": parts[1].strip(),
                                    "line": line_num,
                                    "raw": line.strip(),
                                }
                            )
                        continue

                    m = map_notation.search(line)
                    if m:
                        deps.append(
                            {
                                "group": m.group(1).strip(),
                                "artifact": m.group(2).strip(),
                                "line": line_num,
                                "raw": line.strip(),
                            }
                        )
                        continue

                    m = kotlin_named_notation.search(line)
                    if m:
                        deps.append(
                            {
                                "group": m.group(1).strip(),
                                "artifact": m.group(2).strip(),
                                "line": line_num,
                                "raw": line.strip(),
                            }
                        )
        except Exception:
            return deps

        return deps

    def find_declared_dependency_usage(self, package_group: str, package_artifact: str) -> List[UsageContext]:
        if not package_artifact:
            return []

        target_group = package_group.strip().lower()
        target_artifact = package_artifact.strip().lower()
        matches: List[UsageContext] = []

        exact = self._declared_dependencies.get((target_group, target_artifact), [])
        if exact:
            matches.extend(exact)

        if not matches:
            for (dep_group, dep_artifact), contexts in self._declared_dependencies.items():
                if dep_artifact != target_artifact:
                    continue
                if not target_group or dep_group == target_group or dep_group in target_group or target_group in dep_group:
                    matches.extend(contexts)

        return matches

    def find_java_files(self) -> List[Path]:
        java_files = []
        for root, dirs, files in os.walk(self.project_root):
            for file in files:
                if file.endswith('.java'):
                    java_files.append(Path(root) / file)
        return java_files

    def find_package_usage(self, package_group: str, package_artifact: str) -> List[UsageContext]:
        """
        Find usage of a Java package.
        Java packages are often group:artifact (e.g. org.apache.logging.log4j:log4j-core).
        Usage is typically 'import org.apache.logging.log4j.Logger'.
        """
        usage_contexts = []
        java_files = self.find_java_files()

        # Simple heuristic mappings from artifactId to package prefix
        # e.g. "log4j-core" -> "org.apache.logging.log4j"
        # Since we don't have the JAR to inspect, we check if the import PATH
        # contains the artifact's signature words.

        # For artifacts like "spring-web", we look for "org.springframework.web"
        # We search for the artifact name parts in the import.
        keywords = [k for k in package_artifact.replace('-', '.').split('.') if k]
        if not keywords and package_group:
            keywords = [k for k in package_group.replace('-', '.').split('.') if k]

        for java_file in java_files:
            try:
                with open(java_file, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    lines = content.splitlines()

                    # Scope tracking for enclosing method
                    method_def_pattern = re.compile(r'(?:public|private|protected|static|final|native|synchronized|abstract|transient|\s)+[\w<>\[\]]+\s+([a-zA-Z0-9_$]+)\s*\([^\)]*\)\s*(?:throws\s+[\w,\s]+)?\s*\{')
                    brace_balance = 0
                    scope_stack = [] # (name, level)
                    current_method = None

                    for line_num, line in enumerate(lines, 1):
                        strip_line = line.strip()

                        # Brace tracking
                        brace_balance += line.count('{')
                        brace_balance -= line.count('}')

                        # Enter scope
                        match = method_def_pattern.search(strip_line)
                        if match:
                            method_name = match.group(1)
                            # filter keywords
                            if method_name not in {'if', 'for', 'switch', 'while', 'catch'}:
                                scope_stack.append({'name': method_name, 'level': brace_balance})
                                current_method = method_name

                        # Exit scope
                        if scope_stack:
                            if brace_balance < scope_stack[-1]['level']:
                                scope_stack.pop()
                                current_method = scope_stack[-1]['name'] if scope_stack else None

                        # Check Usage (Import)
                        import_match = self.import_pattern.search(strip_line)

                        if import_match:
                            imported_pkg = import_match.group(1)
                            segments = imported_pkg.split('.')
                            long_substring = any(k in imported_pkg for k in keywords if len(k) > 5)
                            exact_segment  = any(k in segments    for k in keywords if len(k) > 4)
                            if long_substring or exact_segment:
                                # Heuristic: match if artifact keyword is in import
                                usage_contexts.append(UsageContext(
                                    file_path=str(java_file.relative_to(self.project_root)),
                                    line_number=line_num,
                                    context_line=strip_line,
                                    usage_type="import",
                                    enclosing_scope=current_method
                                ))

                        # Check direct class usage if we know the class name?
                        # This is harder without mapping classes to packages.
                        # We stick to imports for now as primary signal.

            except Exception:
                pass

        return usage_contexts

    def analyze_vulnerability(self, vuln_data: Dict) -> VulnAnalysis:
        pkg_name = (
            vuln_data.get('package_name')
            or vuln_data.get('package')
            or ''
        )  # e.g. org.apache.logging.log4j:log4j-core
        version = vuln_data.get('installed_version') or vuln_data.get('version', '')
        fixed = (
            vuln_data.get('recommended_version')
            or vuln_data.get('recommended_fixed_version')
            or vuln_data.get('fixed_version', '')
        )

        # Parse group vs artifact
        group, artifact = self._parse_package_coordinates(pkg_name)

        import_usages = self.find_package_usage(group, artifact)
        declared_usages = self.find_declared_dependency_usage(group, artifact)
        usage_contexts = import_usages + declared_usages
        is_used = len(usage_contexts) > 0
        is_imported = len(import_usages) > 0
        is_declared = len(declared_usages) > 0

        criticality = CriticalityLevel.NOT_REACHABLE
        risk_reason = "Library not imported and not declared in build manifests"

        if is_used:
            criticality = normalize_severity(vuln_data.get('severity', 'MEDIUM'))
            if is_imported and is_declared:
                risk_reason = (
                    f"Library imported in {len(import_usages)} location(s) and "
                    f"declared in {len(declared_usages)} build file location(s)"
                )
            elif is_imported:
                risk_reason = f"Library imported in {len(import_usages)} location(s)"
            else:
                risk_reason = f"Library declared in build manifests ({len(declared_usages)} location(s))"

        # Generate Call Graph Trace
        call_graph_mermaid = None
        if self.call_graph_builder and is_imported:
            target_methods = {ctx.enclosing_scope for ctx in import_usages if ctx.enclosing_scope}
            if target_methods:
                traces = self.call_graph_builder.find_trace_to_usage(list(target_methods))
                if traces:
                    call_graph_mermaid = self.call_graph_builder.get_mermaid_graph(traces)
                    path_count = len(traces)
                    risk_reason += f" [VERIFIED: {path_count} paths from endpoints]"

                    if criticality in [CriticalityLevel.HIGH, CriticalityLevel.MEDIUM]:
                        criticality = CriticalityLevel.CRITICAL

        return VulnAnalysis(pkg_name, version, fixed, is_used, usage_contexts, criticality, risk_reason, call_graph_mermaid)

def run_java_reachability_analysis(project_root: str, consolidated_path: str, output_path: str):
    print(f"\n{'='*60}")
    print("☕ JAVA VULNERABILITY REACHABILITY ANALYSIS")
    print(f"{'='*60}\n")

    try:
        with open(consolidated_path, 'r') as f:
            data = json.load(f)
            vulns = data if isinstance(data, list) else data.get('vulnerabilities', [])
    except Exception as e:
        print(f"Error loading data: {e}")
        return

    analyzer = JavaReachabilityAnalyzer(project_root)
    analyses = []

    for v in vulns:
        res = analyzer.analyze_vulnerability(v)
        analyses.append(res)
        status = "✓ USED" if res.is_used else "✗ NOT USED"
        print(f"{status} | {res.package_name:40} | {res.criticality.value:15} | {res.risk_reason}")

    report = build_report_dict(analyses, project_root, "java")

    os.makedirs(os.path.dirname(output_path) if os.path.dirname(output_path) else '.', exist_ok=True)
    with open(output_path, 'w') as f:
        json.dump(report, f, indent=2)
    print(f"\nSaved report to {output_path}")
    print(f"  Total: {report['total_vulnerabilities']}  "
          f"Reachable: {report['reachable_vulnerabilities']}  "
          f"Not reachable: {report['not_reachable_vulnerabilities']}")

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 3:
        print("Usage: python java_reachability_analyzer.py <root> <vulns.json> <out.json>")
        sys.exit(1)
    run_java_reachability_analysis(sys.argv[1], sys.argv[2], sys.argv[3])
