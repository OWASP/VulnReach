"""Dynamic Reachability Agent — Docker-based coverage approach.

Flow (per DYNAMIC_ANALYSIS.MD):
  Step 1 — Pre-flight checks (Dockerfile + openapi spec exist)
  Step 2 — Patch Dockerfile, build instrumented image, start container
  Step 3 — Run Schemathesis (triggers traffic with custom headers)
  Step 4 — Collect coverage.json from container
  Step 5 — Correlate static findings with dynamic hit set
"""

from __future__ import annotations

import ast
import asyncio
import json
import logging
import os
import re
import shutil
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

# When running inside Docker (DooD), all temp dirs must live on a path that is
# bind-mounted to the host so the host Docker daemon can resolve volume paths.
# Set VULNREACH_WORK_DIR to that mount point (default: system temp dir for
# native / non-Docker use).
_WORK_BASE = os.environ.get("VULNREACH_WORK_DIR") or tempfile.gettempdir()

# When vulnreach runs inside Docker (DooD), sibling containers' published ports
# are on the HOST — not reachable via 'localhost' from inside the container.
# On macOS/Windows Docker Desktop, host.docker.internal resolves to the host.
# On Linux we fall back to the default bridge gateway (172.17.0.1).
def _target_host() -> str:
    """Return the hostname to use when connecting to sibling Docker containers."""
    if not Path("/.dockerenv").exists():
        return "localhost"
    # Prefer an explicit override
    override = os.environ.get("VULNREACH_TARGET_HOST")
    if override:
        return override
    # host.docker.internal is available on Docker Desktop (macOS/Windows) and
    # on Linux when --add-host=host.docker.internal:host-gateway is set.
    return "host.docker.internal"


def _safe_compose_project_name(repo_path: Path) -> str:
    """Return a Docker image-safe Compose project name for temp clone paths."""
    raw = repo_path.name.lower()
    safe = re.sub(r"[^a-z0-9]+", "-", raw).strip("-")
    safe = re.sub(r"-{2,}", "-", safe)
    return (safe or "vulnreach-scan")[:63].strip("-") or "vulnreach-scan"


try:
    import aiohttp
except ImportError:
    aiohttp = None

try:
    from agents.ebpf.compose_injector import (
        detect_primary_service as _ebpf_detect_service,
        inject_sidecar as _ebpf_inject_sidecar,
        get_compose_up_command as _ebpf_compose_up_cmd,
        get_compose_down_command as _ebpf_compose_down_cmd,
    )
    from agents.ebpf.coverage_normaliser import to_coverage_py_format as _ebpf_to_coverage_py
    _EBPF_SIDECAR_AVAILABLE = True
except ImportError:
    _EBPF_SIDECAR_AVAILABLE = False

from core.agent import BaseTool  # noqa: E402
from core.models import AgentResult, ReachabilityFinding, ScanContext  # noqa: E402

logger = logging.getLogger(__name__)

# Known PyPI name → importable package name mappings for correlation
_PYPI_TO_IMPORT: Dict[str, str] = {
    # Image / media
    "pillow": "PIL",
    "opencv-python": "cv2",
    "opencv-python-headless": "cv2",
    # ML / data science
    "scikit-learn": "sklearn",
    "tensorflow-cpu": "tensorflow",
    "tf-nightly": "tensorflow",
    # HTML / XML parsing
    "beautifulsoup4": "bs4",
    "lxml": "lxml",
    "defusedxml": "defusedxml",
    # Config / serialization
    "pyyaml": "yaml",
    "python-multipart": "multipart",
    "python-dotenv": "dotenv",
    "python-decouple": "decouple",
    # Date / time
    "python-dateutil": "dateutil",
    # Database drivers
    "mysqlclient": "MySQLdb",
    "psycopg2-binary": "psycopg2",
    "psycopg2": "psycopg2",
    "asyncpg": "asyncpg",
    "aiomysql": "aiomysql",
    "pymysql": "pymysql",
    "cx-oracle": "cx_Oracle",
    # Auth / crypto
    "pyjwt": "jwt",
    "python-jose": "jose",
    "pycryptodome": "Crypto",
    "pycryptodomex": "Cryptodome",
    "pyopenssl": "OpenSSL",
    "argon2-cffi": "argon2",
    "python-ldap": "ldap",
    # Web frameworks / extensions
    "djangorestframework": "rest_framework",
    "django-rest-framework": "rest_framework",
    "django-allauth": "allauth",
    "django-cors-headers": "corsheaders",
    "flask-login": "flask_login",
    "flask-sqlalchemy": "flask_sqlalchemy",
    "flask-wtf": "flask_wtf",
    "flask-cors": "flask_cors",
    "flask-jwt-extended": "flask_jwt_extended",
    "flask-restful": "flask_restful",
    # ORM / data
    "tortoise-orm": "tortoise",
    "elasticsearch-dsl": "elasticsearch_dsl",
    # Messaging
    "kafka-python": "kafka",
    "confluent-kafka": "confluent_kafka",
    # gRPC / protobuf
    "grpcio": "grpc",
    # Serialization
    "attrs": "attr",
    "pydantic-settings": "pydantic_settings",
    # Slugify / text
    "python-slugify": "slugify",
    "unidecode": "unidecode",
    # Testing
    "factory-boy": "factory",
    "vcrpy": "vcr",
    # Serial
    "pyserial": "serial",
    # Misc
    "charset-normalizer": "charset_normalizer",
    "faker": "faker",
    "markdown": "markdown",
}

# Minimum package name length to use as a substring match (avoids 're', 'os', etc.)
_MIN_PKG_MATCH_LEN = 4


def _parse_file_imports(source: str) -> Tuple[Dict[str, str], Dict[str, str]]:
    """Parse import statements from Python source using the AST.

    Returns:
        alias_to_pkg:    {alias_or_module_name → top_level_pkg}
                         Covers `import X`, `import X as Y`, `import X.Y as Z`
        imported_names:  {bare_name → top_level_pkg}
                         Covers `from X import Y`, `from X import Y as Z`

    All keys/values are lowercased.  Call-site resolution works like this:
        `alias.method(...)`  → look up alias in alias_to_pkg
        `bare_name(...)`     → look up bare_name in imported_names
    """
    alias_to_pkg: Dict[str, str] = {}
    imported_names: Dict[str, str] = {}
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return alias_to_pkg, imported_names

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                top = alias.name.split(".")[0].lower()
                key = (alias.asname or alias.name.split(".")[0]).lower()
                alias_to_pkg[key] = top
        elif isinstance(node, ast.ImportFrom) and node.module:
            top = node.module.split(".")[0].lower()
            for alias in node.names:
                key = (alias.asname or alias.name).lower()
                imported_names[key] = top

    return alias_to_pkg, imported_names


class DynamicReachabilityAgent(BaseTool):
    tool_name = "dynamic_reachability"

    def __init__(self, default_timeout: int = 60) -> None:
        self.default_timeout = default_timeout

    # ------------------------------------------------------------------
    # Entry point
    # ------------------------------------------------------------------

    async def run(self, context: ScanContext) -> AgentResult:  # type: ignore[override]
        if not context.config or not context.config.scan.runtime.enabled:
            return AgentResult(
                tool_name=self.tool_name,
                findings=[],
                metadata={"status": "disabled", "reason": "runtime.enabled is false"},
            )

        # Dynamic analysis talks to a container runtime (Docker daemon). Require
        # explicit operator opt-in to avoid high-privilege defaults.
        docker_opt_in = (os.environ.get("VULNREACH_ALLOW_DOCKER_DAEMON", "") or "").strip().lower() in {
            "1", "true", "yes", "on"
        }
        if not docker_opt_in:
            return AgentResult(
                tool_name=self.tool_name,
                findings=[],
                metadata={
                    "status": "skipped",
                    "reason": "docker_daemon_requires_opt_in_env:VULNREACH_ALLOW_DOCKER_DAEMON",
                    "container_started": {"status": "no", "id": "na"},
                },
            )

        if not context.repo_path:
            return AgentResult(
                tool_name=self.tool_name,
                findings=[],
                metadata={"error": "missing_repo_path"},
            )

        repo_path = Path(context.repo_path).resolve()
        if not repo_path.exists():
            return AgentResult(
                tool_name=self.tool_name,
                findings=[],
                metadata={"error": "repo_path_not_found", "repo_path": str(repo_path)},
            )

        runtime = context.config.scan.runtime
        timeout = runtime.timeout or self.default_timeout
        coverage_wait = runtime.coverage_wait
        container_port = runtime.container_port

        # ------------------------------------------------------------------
        # Step 1 — Pre-flight checks
        # ------------------------------------------------------------------
        preflight = self._preflight(repo_path)
        if not preflight["passed"]:
            return AgentResult(
                tool_name=self.tool_name,
                findings=[],
                metadata={
                    "status": "skipped",
                    "container_started": {"status": "no", "id": "na"},
                    **preflight,
                },
            )

        # Dispatch to eBPF mode when enabled and the tracer is available.
        # Falls back to coverage mode when unavailable.
        ebpf_cfg = runtime.ebpf
        if ebpf_cfg.enabled:
            ebpf_opt_in = (os.environ.get("VULNREACH_ALLOW_EBPF", "") or "").strip().lower() in {
                "1", "true", "yes", "on"
            }
            if not ebpf_opt_in:
                return AgentResult(
                    tool_name=self.tool_name,
                    findings=[],
                    metadata={
                        "status": "skipped",
                        "reason": "ebpf_requires_opt_in_env:VULNREACH_ALLOW_EBPF",
                        "container_started": {"status": "no", "id": "na"},
                    },
                )
            logger.warning(
                "[dynamic] eBPF mode is EXPERIMENTAL — Linux only, untested in CI. "
                "Set runtime.ebpf.enabled=false to use the stable Dockerfile-patch mode."
            )
            # Kernel version advisory — logged once per run, never blocks
            if ebpf_cfg.kernel_check:
                if not self._kernel_version_ok(4, 9):
                    logger.warning(
                        "[dynamic][ebpf] Kernel < 4.9 detected — uprobes unavailable. "
                        "eBPF tracing will likely fail entirely."
                    )
                elif not self._kernel_version_ok(5, 2):
                    logger.warning(
                        "[dynamic][ebpf] Kernel < 5.2 detected — BTF may be unavailable. "
                        "bpftrace may need --no-btf. Upgrading to 5.2+ is recommended."
                    )

            # Language-agnostic CO-RE observer engine (P0–P5). Bypasses the
            # legacy bpftrace/LinuxKit gate — it has its own availability check.
            if getattr(ebpf_cfg, "engine", "legacy") == "observer":
                logger.info("[dynamic] eBPF observer engine active (language-agnostic CO-RE)")
                return await self._run_observer_mode(context, repo_path, runtime, preflight)

            if self._ebpf_available(ebpf_cfg.tracer):
                logger.info(
                    f"[dynamic] eBPF mode active (tracer={ebpf_cfg.tracer}, mode={ebpf_cfg.mode})"
                )
                return await self._run_ebpf_mode(context, repo_path, runtime, preflight)
            # _ebpf_available() already logged why eBPF is unavailable; no second warning needed.

        openapi_path = preflight["openapi_path"]

        # ------------------------------------------------------------------
        # Dispatch: docker-compose or Dockerfile mode
        # ------------------------------------------------------------------
        if preflight.get("mode") == "compose":
            return await self._run_compose_mode(
                context, repo_path, runtime, preflight
            )

        dockerfile_path = Path(preflight["dockerfile_path"])

        # ------------------------------------------------------------------
        # Step 2 — Patch Dockerfile, build image, start container
        # ------------------------------------------------------------------
        image_tag, workdir, patch_meta = await self._build_instrumented_image(
            dockerfile_path, repo_path
        )
        if not image_tag:
            return AgentResult(
                tool_name=self.tool_name,
                findings=[],
                metadata={
                    "status": "failed",
                    "step": "dockerfile_patch",
                    "container_started": {"status": "no", "id": "na"},
                    **patch_meta,
                },
            )

        # _start_container now returns (container_id, coverage_host_dir)
        # so there are no hidden side-effects on instance state.
        start_result = await self._start_container(image_tag, container_port, timeout)
        if start_result is None:
            return AgentResult(
                tool_name=self.tool_name,
                findings=[],
                metadata={
                    "status": "failed",
                    "step": "container_start",
                    "container_started": {"status": "no", "id": "na"},
                    "image": image_tag,
                },
            )

        container_id, coverage_host_dir = start_result
        container_started: Dict[str, str] = {"status": "no", "id": "na"}
        coverage_data: Optional[Dict[str, Any]] = None
        coverage_meta: Dict[str, Any] = {}
        schemathesis_meta: Dict[str, Any] = {}

        try:
            # Wait for container to become healthy
            base_url = f"http://{_target_host()}:{container_port}"
            healthy = await self._wait_for_healthy(base_url, timeout=30)
            if not healthy:
                return AgentResult(
                    tool_name=self.tool_name,
                    findings=[],
                    metadata={
                        "status": "failed",
                        "step": "health_check",
                        "container_started": {"status": "no", "id": container_id[:12]},
                        "url": base_url,
                    },
                )

            container_started = {"status": "yes-running", "id": container_id[:12]}

            # ------------------------------------------------------------------
            # Step 3 — Schemathesis
            # ------------------------------------------------------------------
            schemathesis_meta = await self._run_schemathesis(
                base_url, openapi_path, container_port, workdir
            )

            # Wait for coverage data to flush
            logger.info(f"[dynamic] Waiting {coverage_wait}s for coverage to flush...")
            await asyncio.sleep(coverage_wait)

        finally:
            # Always stop the running container before extraction or cleanup.
            await self._stop_container(container_id)
            if workdir and Path(workdir).exists():
                shutil.rmtree(workdir, ignore_errors=True)

        # ------------------------------------------------------------------
        # Step 4 — Extract coverage from the shared volume using a fresh
        #           short-lived container (no running container needed here).
        # ------------------------------------------------------------------
        taint_events: List[Dict[str, Any]] = []
        try:
            coverage_data, coverage_meta, taint_events = (
                await self._extract_coverage_from_volume(image_tag, coverage_host_dir)
            )
            # Persist coverage.json next to the repo so it survives cleanup.
            src = Path(coverage_host_dir) / "coverage.json"
            if src.exists():
                dest = repo_path / "coverage.json"
                shutil.copy2(src, dest)
                logger.info(f"[dynamic][coverage] Saved coverage.json to {dest}")
                coverage_meta["saved_to"] = str(dest)
        finally:
            # Always clean up the coverage host directory.
            if coverage_host_dir and Path(coverage_host_dir).exists():
                shutil.rmtree(coverage_host_dir, ignore_errors=True)

        if not coverage_data:
            return AgentResult(
                tool_name=self.tool_name,
                findings=[],
                metadata={
                    "status": "skipped",
                    "step": "coverage_collection",
                    "container_started": container_started,
                    "reason": coverage_meta.get("error", "empty coverage"),
                    "schemathesis": schemathesis_meta,
                },
            )

        # ------------------------------------------------------------------
        # Step 5 — Correlate static + dynamic (coverage + taint events)
        # ------------------------------------------------------------------
        findings = self._correlate(coverage_data, context.vulnerabilities, taint_events, static_findings=context.taint_flows, repo_path=repo_path, import_map=context.import_map, container_workdir=getattr(context.config.scan.runtime, "container_workdir", ""))

        return AgentResult.model_validate({
            "tool_name": self.tool_name,
            "findings": [f.model_dump() for f in findings],
            "metadata": {
                "status": "ok",
                "finding_count": len(findings),
                "container_started": container_started,
                "image_tag": image_tag,
                "schemathesis": schemathesis_meta,
                "coverage": coverage_meta,
            },
        })

    # ------------------------------------------------------------------
    # Step 1 — Pre-flight
    # ------------------------------------------------------------------

    def _preflight(self, repo_path: Path) -> Dict[str, Any]:
        """Check that Dockerfile/docker-compose and an OpenAPI spec exist.

        Detection priority:
          1. docker-compose.yml / docker-compose.yaml / compose.yml
          2. Dockerfile
        When a compose file is found, ``compose_path`` is set and
        ``dockerfile_path`` may still be populated (but compose takes precedence).
        """
        # --- Docker detection ---
        dockerfile: Optional[Path] = None
        compose_path: Optional[Path] = None

        for name in ("docker-compose.yml", "docker-compose.yaml", "compose.yml"):
            candidate = repo_path / name
            if candidate.exists():
                compose_path = candidate
                break

        dockerfile_candidate = repo_path / "Dockerfile"
        if dockerfile_candidate.exists():
            dockerfile = dockerfile_candidate

        if not dockerfile and not compose_path:
            reason = f"No Dockerfile or docker-compose file found in {repo_path}"
            logger.warning(f"[dynamic][preflight] SKIP — {reason}")
            return {"passed": False, "reason": reason}

        # --- OpenAPI detection ---
        openapi_path: Optional[str] = None
        for name in ("openapi.json", "openapi.yaml", "openapi.yml"):
            candidate = repo_path / name
            if candidate.exists():
                openapi_path = str(candidate)
                break

        if not openapi_path:
            reason = f"No openapi.json / openapi.yaml found in {repo_path}"
            logger.warning(f"[dynamic][preflight] SKIP — {reason}")
            return {
                "passed": False,
                "reason": reason,
                "dockerfile_path": str(dockerfile) if dockerfile else None,
                "compose_path": str(compose_path) if compose_path else None,
            }

        result: Dict[str, Any] = {
            "passed": True,
            "openapi_path": openapi_path,
            "dockerfile_path": str(dockerfile) if dockerfile else None,
            "compose_path": str(compose_path) if compose_path else None,
            "mode": "compose" if compose_path else "dockerfile",
        }
        logger.info(
            f"[dynamic][preflight] PASS — mode={result['mode']}, "
            f"docker={compose_path or dockerfile}, OpenAPI: {openapi_path}"
        )
        return result

    # ------------------------------------------------------------------
    # Step 2 — Patch Dockerfile + build + start
    # ------------------------------------------------------------------

    def _patch_dockerfile(
        self, original: Path, inject_hooks: bool = False
    ) -> Tuple[Optional[str], str]:
        """
        Ensure the Dockerfile is instrumented for coverage collection.

        - If COVERAGE_PROCESS_START already present → pass-through (no-op).
        - If CMD is gunicorn/uvicorn → inject sitecustomize + env block.
        - Otherwise → return (None, reason) so the caller can abort cleanly.

        Multi-stage Dockerfiles are handled correctly: only the final stage is
        patched.  The WORKDIR of the final stage is detected and used in the
        coverage block so the .coveragerc path is always valid.

        When inject_hooks=True, the sitecustomize.py also installs runtime_hooks
        (audit, imports, sinks) and registers an atexit handler to flush taint
        events to /coverage/runtime_events.<pid>.json on container shutdown.
        Requires .vulnreach_hooks/ to be present in the Docker build context.
        """
        content = original.read_text(encoding="utf-8")

        if "COVERAGE_PROCESS_START" in content:
            logger.info("[dynamic][patch] COVERAGE_PROCESS_START found — pass-through")
            return content, "already_patched"

        lines = content.splitlines()

        # --- Multi-stage awareness ---
        # Find the index where the final stage begins (last FROM line).
        # Only the final stage's CMD and WORKDIR are relevant.
        final_stage_start = 0
        for i, line in enumerate(lines):
            if re.match(r"^\s*FROM\s+", line, re.IGNORECASE):
                final_stage_start = i

        # --- Non-Python base image guard ---
        # If the final stage is based on a Java/Node/Go/Rust image, Python is not
        # available in the container, so injecting "RUN python -c ..." would break
        # the Docker build. Return the original content unchanged — the container
        # will still start and Schemathesis will drive traffic; we simply won't
        # collect Python coverage (which is fine for non-Python runtimes).
        _NON_PYTHON_BASE_PREFIXES = (
            "eclipse-temurin", "openjdk", "amazoncorretto", "adoptopenjdk",
            "azul/zulu", "bellsoft/liberica",
            "node:", "node-alpine", "node-slim",
            "golang:", "go-alpine",
            "rust:", "rust-alpine",
            "mcr.microsoft.com/dotnet", "microsoft/dotnet",
            "ruby:", "php:",
        )
        final_from_line = lines[final_stage_start] if final_stage_start < len(lines) else ""
        _base_match = re.search(r"FROM\s+(\S+)", final_from_line, re.IGNORECASE)
        if _base_match:
            _base = _base_match.group(1).lower().split(":")[0]  # strip tag
            _base_with_tag = _base_match.group(1).lower()
            if any(
                _base_with_tag.startswith(p.lower()) or _base.startswith(p.lower().split(":")[0])
                for p in _NON_PYTHON_BASE_PREFIXES
            ):
                logger.info(
                    f"[dynamic][patch] Non-Python base image '{_base_match.group(1)}' — "
                    "skipping coverage injection; container will start but no Python coverage"
                )
                return None, "non_python_base_image"

        # Detect WORKDIR from the final stage (default /app for safety)
        detected_workdir = "/app"
        for line in lines[final_stage_start:]:
            m = re.match(r"^\s*WORKDIR\s+(\S+)", line, re.IGNORECASE)
            if m:
                detected_workdir = m.group(1).rstrip("/") or detected_workdir

        workdir = detected_workdir
        logger.debug(f"[dynamic][patch] Final stage WORKDIR detected as '{workdir}'")

        patched_lines: List[str] = []
        found_target_cmd = False

        for i, line in enumerate(lines):
            stripped = line.strip()
            # Only consider CMD lines in the final stage
            if i < final_stage_start or not stripped.upper().startswith("CMD"):
                patched_lines.append(line)
                continue

            cmd_args = self._parse_cmd_line(stripped)
            if not cmd_args:
                patched_lines.append(line)
                continue

            first = cmd_args[0].lower()
            # Support: gunicorn, uvicorn, python, flask, django manage.py
            is_python_cmd = first in ("python", "python3") or first.startswith("python3.")
            is_server_cmd = first in ("gunicorn", "uvicorn")
            is_flask_cmd = first == "flask"
            is_manage_py = "manage.py" in " ".join(cmd_args).lower()

            if is_server_cmd or is_python_cmd or is_flask_cmd or is_manage_py:
                found_target_cmd = True
                logger.info(f"[dynamic][patch] Found CMD '{first}' — injecting coverage env")

            patched_lines.append(line)

        if not found_target_cmd:
            # Last resort: inject anyway — coverage env vars are harmless if
            # the CMD doesn't import coverage.  Let Docker build decide.
            logger.warning(
                "[dynamic][patch] CMD not a recognised Python server — "
                "injecting coverage env anyway (best-effort)"
            )
            found_target_cmd = True

        # sitecustomize.py content written via printf \n sequences.
        # Single-quoted printf args pass double quotes through literally, so
        # "/runtime_hooks" and the atexit path string are safe.
        if inject_hooks:
            # Extended: coverage.py + runtime_hooks (audit/imports/sinks)
            # Each worker gets its own events file keyed by PID.
            sitecustomize_printf = (
                "import coverage\\ncoverage.process_startup()\\n"
                "import sys\\nsys.path.insert(0, \"/runtime_hooks\")\\n"
                "try:\\n"
                "    from hooks import audit, imports, sinks\\n"
                "    from hooks.events import flush_to_file\\n"
                "    import atexit, os\\n"
                "    audit.install()\\n"
                "    imports.install()\\n"
                "    sinks.install()\\n"
                "    atexit.register(flush_to_file,"
                " \"/coverage/runtime_events.\" + str(os.getpid()) + \".json\")\\n"
                "except Exception:\\n    pass\\n"
            )
            copy_hooks_line = "COPY .vulnreach_hooks/ /runtime_hooks/\n"
            logger.info("[dynamic][patch] Injecting runtime_hooks alongside coverage.py")
        else:
            sitecustomize_printf = "import coverage\\ncoverage.process_startup()\\n"
            copy_hooks_line = ""

        coveragerc_path = f"{workdir}/.coveragerc"
        coverage_block = (
            "\n# Injected by VulnReach dynamic agent\n"
            + copy_hooks_line
            + "RUN printf '[run]\\n"
            "omit = */pip/*,*/setuptools/*,*/pkg_resources/*,*/coverage/*,"
            "*/distutils/*,*/ensurepip/*,*/site-packages/test*,"
            "*/site-packages/_*\\n"
            "data_file = /tmp/.coverage\\n"
            "parallel = true\\nsigterm = true\\nconcurrency = multiprocessing\\n'"
            f" > {coveragerc_path}\n"
            "RUN python -c \"import sysconfig; print(sysconfig.get_path('purelib'))\""
            " > /tmp/sp.txt \\\n"
            f" && printf '{sitecustomize_printf}'"
            " > \"$(cat /tmp/sp.txt)/sitecustomize.py\"\n"
            f"ENV COVERAGE_PROCESS_START={coveragerc_path}\n"
        )

        full = "\n".join(patched_lines)
        # Insert coverage block before the last CMD in the final stage
        last_cmd_idx = full.rfind("\nCMD ")
        if last_cmd_idx != -1:
            full = full[:last_cmd_idx] + coverage_block + full[last_cmd_idx:]
        else:
            full += coverage_block

        return full, ""

    def _parse_cmd_line(self, line: str) -> List[str]:
        """Parse a Dockerfile CMD line — handles JSON array and shell form."""
        rest = re.sub(r"^CMD\s+", "", line, flags=re.IGNORECASE).strip()

        # JSON array form: CMD ["gunicorn", ...]
        if rest.startswith("["):
            try:
                return json.loads(rest)
            except json.JSONDecodeError:
                pass

        # Shell form: CMD gunicorn ...
        import shlex
        try:
            return shlex.split(rest)
        except ValueError:
            return []

    async def _build_instrumented_image(
        self, dockerfile_path: Path, repo_path: Path
    ) -> Tuple[Optional[str], Optional[str], Dict[str, Any]]:
        """Patch Dockerfile, build image. Returns (image_tag, workdir, meta).

        Attempts to copy runtime_hooks/ into the Docker build context as
        .vulnreach_hooks/ so the patched Dockerfile can COPY it into the image.
        Falls back to coverage-only instrumentation if the directory is missing
        or the copy fails.
        """
        # Locate runtime_hooks relative to this agent file.
        hooks_src = Path(__file__).parent.parent / "runtime_hooks"
        hooks_dst = repo_path / ".vulnreach_hooks"
        inject_hooks = False

        if hooks_src.exists() and hooks_src.is_dir():
            try:
                if hooks_dst.exists():
                    shutil.rmtree(hooks_dst)
                shutil.copytree(hooks_src, hooks_dst)
                inject_hooks = True
                logger.info("[dynamic][build] Copied runtime_hooks into build context")
            except Exception as exc:
                logger.warning(f"[dynamic][build] Failed to copy runtime_hooks: {exc}")

        try:
            patched_content, skip_reason = self._patch_dockerfile(
                dockerfile_path, inject_hooks=inject_hooks
            )
            if patched_content is None:
                return None, None, {"error": skip_reason}

            # Write patched Dockerfile to a temp dir — NEVER overwrite the original.
            workdir = tempfile.mkdtemp(prefix="vulnreach_dynamic_", dir=_WORK_BASE)
            patched_path = Path(workdir) / "Dockerfile"
            patched_path.write_text(patched_content, encoding="utf-8")

            repo_name = repo_path.name.lower().replace(" ", "_")
            image_tag = f"{repo_name}:instrumented"

            logger.info(f"[dynamic][build] Building image {image_tag} from {workdir}")

            proc = await asyncio.create_subprocess_exec(
                "docker", "build",
                "-t", image_tag,
                "-f", str(patched_path),
                str(repo_path),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            try:
                stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=300)
            except asyncio.TimeoutError:
                proc.kill()
                await proc.wait()
                return None, workdir, {"error": "docker_build_timeout"}

            if proc.returncode != 0:
                err = stderr.decode("utf-8", errors="replace")[-2000:]
                return None, workdir, {"error": "docker_build_failed", "stderr": err}

            logger.info(f"[dynamic][build] Image built: {image_tag}")
            return image_tag, workdir, {
                "image_tag": image_tag,
                "skip_reason": skip_reason,
                "hooks_injected": inject_hooks,
            }

        finally:
            # Remove the temporary .vulnreach_hooks from the repo build context.
            if inject_hooks and hooks_dst.exists():
                shutil.rmtree(hooks_dst, ignore_errors=True)

    async def _start_container(
        self, image_tag: str, container_port: int, timeout: int
    ) -> Optional[Tuple[str, str]]:
        """
        Start the instrumented container with a coverage volume mount.

        Returns (container_id, coverage_host_dir) so callers manage the
        coverage directory explicitly — no hidden instance-variable side effects.
        Returns None on failure.
        """
        # Kill any orphaned containers from previous runs on the same port.
        await self._cleanup_port_conflicts(container_port)

        coverage_dir = tempfile.mkdtemp(prefix="vulnreach_cov_", dir=_WORK_BASE)

        proc = await asyncio.create_subprocess_exec(
            "docker", "run", "-d",
            "-p", f"{container_port}:{container_port}",
            "-v", f"{coverage_dir}:/coverage",
            "-e", "COVERAGE_FILE=/coverage/.coverage",
            image_tag,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=30)
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            shutil.rmtree(coverage_dir, ignore_errors=True)
            logger.error("[dynamic][container] Timed out starting container")
            return None

        if proc.returncode != 0:
            err = stderr.decode("utf-8", errors="replace")
            logger.error(f"[dynamic][container] Failed to start: {err}")
            shutil.rmtree(coverage_dir, ignore_errors=True)
            return None

        container_id = stdout.decode("utf-8").strip()
        logger.info(f"[dynamic][container] Started: {container_id[:12]}")
        return container_id, coverage_dir

    async def _wait_for_healthy(self, base_url: str, timeout: int = 30) -> bool:
        """Poll /health then base URL until a sub-500 response or timeout."""
        if aiohttp is None:
            logger.warning(
                "[dynamic][health] aiohttp not available — waiting 5s and assuming healthy"
            )
            await asyncio.sleep(5)
            return True

        deadline = time.monotonic() + timeout
        for endpoint in (f"{base_url}/health", base_url):
            while time.monotonic() < deadline:
                try:
                    async with aiohttp.ClientSession() as session:
                        async with session.get(
                            endpoint, timeout=aiohttp.ClientTimeout(total=3)
                        ) as resp:
                            if resp.status < 500:
                                logger.info(
                                    f"[dynamic][health] Healthy at {endpoint} ({resp.status})"
                                )
                                return True
                except Exception:
                    pass
                await asyncio.sleep(2)

        logger.warning(f"[dynamic][health] Container not healthy after {timeout}s")
        return False

    # ------------------------------------------------------------------
    # Step 3 — Schemathesis
    # ------------------------------------------------------------------

    async def _run_schemathesis(
        self,
        base_url: str,
        openapi_path: str,
        port: int,
        workdir: Optional[str],
    ) -> Dict[str, Any]:
        """Run Schemathesis against the live container to generate coverage."""
        # Ensure the OpenAPI spec is accessible from workdir
        schema_path = openapi_path
        if workdir:
            try:
                dest = Path(workdir) / "openapi.json"
                shutil.copy(openapi_path, dest)
                schema_path = str(dest)
            except Exception as e:
                logger.warning(f"[dynamic][schemathesis] Failed to copy OpenAPI to workdir: {e}")

        cmd = [
            "schemathesis", "run",
            schema_path,
            f"--url={base_url}",
            "--max-examples=10",
            "--header=AGENT: VulnReach",
            "--workers=1",
        ]

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            try:
                stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=60)
            except asyncio.TimeoutError:
                proc.kill()
                await proc.wait()
                return {"status": "timeout", "note": "schemathesis timed out", "cmd": " ".join(cmd)}

            stdout_text = stdout.decode("utf-8", errors="replace")[-1000:]
            stderr_text = stderr.decode("utf-8", errors="replace")[-1000:]

            # Schemathesis exit codes:
            #   0 = all tests passed
            #   1 = test failures found (API issues — expected for vuln scanning)
            #   2 = internal/CLI error (actual failure)
            if proc.returncode in (0, 1):
                # rc=1 means schemathesis found API issues — that's expected
                # and means it successfully exercised the API.
                status = "completed" if proc.returncode == 0 else "completed_with_findings"
                logger.info(
                    f"[dynamic][schemathesis] {status} (rc={proc.returncode})"
                )
                return {
                    "status": status,
                    "returncode": proc.returncode,
                    "stdout": stdout_text,
                    "cmd": " ".join(cmd),
                }

            logger.warning(f"[dynamic][schemathesis] Internal error (rc={proc.returncode})")
            return {
                "status": "error",
                "returncode": proc.returncode,
                "stdout": stdout_text,
                "stderr": stderr_text,
                "cmd": " ".join(cmd),
            }

        except FileNotFoundError:
            # schemathesis binary not on PATH — fall back to manual requests
            logger.warning("[dynamic][schemathesis] schemathesis not found — using manual requests")
            await self._make_manual_requests(base_url)
            return {
                "status": "fallback_used",
                "note": "schemathesis not available, used manual requests",
                "would_run": " ".join(cmd),
            }
        except Exception as e:
            logger.error(f"[dynamic][schemathesis] Unexpected error: {e}")
            return {"status": "error", "error": str(e), "would_run": " ".join(cmd)}

    async def _make_manual_requests(self, base_url: str) -> None:
        """Fallback: hit common endpoints to exercise code paths."""
        if aiohttp is None:
            logger.warning("[dynamic][manual] aiohttp not available for manual requests")
            return

        endpoints = ["/", "/health", "/yaml-test", "/request-test"]
        async with aiohttp.ClientSession() as session:
            for endpoint in endpoints:
                url = f"{base_url}{endpoint}"
                try:
                    async with session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                        content = await resp.text()
                        logger.info(
                            f"[dynamic][manual] {endpoint} → {resp.status} ({len(content)} bytes)"
                        )
                except Exception as e:
                    logger.warning(f"[dynamic][manual] Request to {endpoint} failed: {e}")

    # ------------------------------------------------------------------
    # Step 4 — Extract coverage from volume
    # ------------------------------------------------------------------

    async def _extract_coverage_from_volume(
        self, image_tag: str, coverage_dir: str
    ) -> Tuple[Optional[Dict[str, Any]], Dict[str, Any], List[Dict[str, Any]]]:
        """
        Spin up a short-lived container to combine coverage files and export
        coverage.json to the shared host volume.  Also collects runtime_events
        written by the taint/sink hooks (runtime_events.<pid>.json files).

        The running container must already be stopped before calling this so
        all worker processes have had a chance to flush their .coverage files
        and trigger their atexit handlers.

        Returns (coverage_data, metadata, taint_events).
        """
        if not coverage_dir or not Path(coverage_dir).exists():
            return None, {"error": "coverage_dir_missing"}, []

        coverage_files = list(Path(coverage_dir).glob(".coverage*"))
        if not coverage_files:
            return None, {
                "error": "no_coverage_files_found",
                "files_in_dir": os.listdir(coverage_dir),
            }, []

        proc = await asyncio.create_subprocess_exec(
            "docker", "run", "--rm",
            "-v", f"{coverage_dir}:/coverage",
            image_tag,
            "/bin/sh", "-c",
            "coverage combine /coverage/.coverage* && coverage json -o /coverage/coverage.json",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=60)
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            return None, {"error": "coverage_combine_timeout"}, []

        if proc.returncode != 0:
            return None, {
                "error": "coverage_combine_failed",
                "stderr": stderr.decode("utf-8", errors="replace")[-1000:],
            }, []

        json_path = Path(coverage_dir) / "coverage.json"
        if not json_path.exists():
            return None, {"error": "coverage_json_not_created"}, []

        try:
            with open(json_path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception as e:
            return None, {"error": "coverage_json_parse_failed", "details": str(e)}, []

        if not data.get("files"):
            return None, {"error": "coverage_empty"}, []

        # Collect taint/sink events written by runtime_hooks atexit handlers.
        # Each worker process writes its own file (keyed by PID) to avoid races.
        taint_events: List[Dict[str, Any]] = []
        for events_file in sorted(Path(coverage_dir).glob("runtime_events.*.json")):
            try:
                with open(events_file, "r", encoding="utf-8") as f:
                    batch = json.load(f)
                if isinstance(batch, list):
                    taint_events.extend(batch)
            except Exception as exc:
                logger.warning(
                    f"[dynamic][coverage] Failed to parse {events_file.name}: {exc}"
                )

        if taint_events:
            logger.info(
                f"[dynamic][coverage] Collected {len(taint_events)} runtime hook events"
            )

        logger.info(f"[dynamic][coverage] Collected {len(data['files'])} files")
        return data, {
            "files_count": len(data["files"]),
            "raw_files_count": len(coverage_files),
            "taint_events_count": len(taint_events),
        }, taint_events

    async def _stop_container(self, container_id: str) -> None:
        """Stop and force-remove a container, waiting for completion."""
        # docker stop first (graceful SIGTERM → SIGKILL after 10s)
        stop_proc = await asyncio.create_subprocess_exec(
            "docker", "stop", container_id,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )
        try:
            await asyncio.wait_for(stop_proc.wait(), timeout=30)
        except asyncio.TimeoutError:
            stop_proc.kill()
            await stop_proc.wait()
            logger.warning(f"[dynamic][container] docker stop timed out for {container_id[:12]}")

        # docker rm -f ensures removal even if stop didn't fully work
        rm_proc = await asyncio.create_subprocess_exec(
            "docker", "rm", "-f", container_id,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )
        try:
            await asyncio.wait_for(rm_proc.wait(), timeout=15)
        except asyncio.TimeoutError:
            rm_proc.kill()
            await rm_proc.wait()
            logger.warning(f"[dynamic][container] docker rm timed out for {container_id[:12]}")

    async def _cleanup_port_conflicts(self, container_port: int) -> None:
        """
        Kill any containers already bound to container_port from previous
        crashed or orphaned runs. Called before starting a new container.
        """
        proc = await asyncio.create_subprocess_exec(
            "docker", "ps", "-q", "--filter", f"publish={container_port}",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            logger.warning("[dynamic][cleanup] Timed out listing containers for port cleanup")
            return

        ids = stdout.decode("utf-8").split()
        if not ids:
            return

        logger.warning(
            f"[dynamic][cleanup] Found {len(ids)} orphaned container(s) on port "
            f"{container_port} — stopping: {', '.join(c[:12] for c in ids)}"
        )
        await asyncio.gather(*[self._stop_container(cid) for cid in ids])

    # ------------------------------------------------------------------
    # Step 5 — Correlate static + dynamic
    # ------------------------------------------------------------------

    def _correlate(
        self,
        coverage_data: Dict[str, Any],
        vulnerabilities: List[Dict[str, Any]],
        taint_events: Optional[List[Dict[str, Any]]] = None,
        static_findings: Optional[List[Dict[str, Any]]] = None,
        repo_path: Optional[Path] = None,
        import_map: Optional[Dict[str, str]] = None,
        container_workdir: str = "",
    ) -> List[ReachabilityFinding]:
        """
        Cross-reference dynamically executed (file, function) pairs from
        coverage.json with static vulnerability findings.  Taint sink events
        from runtime_hooks are used as a second evidence stream.

        Three strategies are used (only packages with actual evidence are emitted):

        Strategy 1 — Direct library match:
            Package import path (e.g. site-packages/django/...) appears in
            coverage file list.  Strongest signal.
            → sink_reachable=True, confidence=0.95

        Strategy 2 — Import-in-executed-file:
            An app source file (e.g. api/views.py) was executed AND imports
            the vulnerable package.  This is indirect evidence — the app code
            that *uses* the library ran, but the library's own code isn't in
            coverage.  Treated as import-time observation, NOT a full sink hit.
            → import_time_hit=True, sink_reachable=False, confidence=0.40

        Strategy 3 — Taint event stack:
            Package name found in a taint sink event stack frame.
            → sink_reachable=True, confidence=0.90

        Packages with NO evidence from any strategy are NOT emitted.
        The orchestrator gates dynamic reachability on the FULL evidence chain
        (SCA → taint → route → static → coverage).
        """
        # Build hit sets from coverage data
        hit_functions: set[str] = set()
        hit_files: set[str] = set()
        hit_files_full: set[str] = set()  # full paths for import scanning

        for file_path, file_data in coverage_data.get("files", {}).items():
            rel = Path(file_path).name
            hit_files.add(rel)
            hit_files_full.add(file_path)

            for func_name, func_data in file_data.get("functions", {}).items():
                if func_data.get("executed_lines"):
                    hit_functions.add(func_name)
                    hit_functions.add(f"{rel}:{func_name}")

        # Strategy 2 prep: AST-aware import + call-site line analysis.
        #
        # For each executed file we build:
        #   pkg_import_lines[pkg]   → {(file_path, lineno)} where `import pkg` / `from pkg` appears
        #   pkg_callsite_lines[pkg] → {(file_path, lineno)} where pkg is actively called
        #   runtime_imported_packages → fallback set of all imported top-level pkg names
        #
        # Confidence levels (strongest first):
        #   call-site line executed  → 0.80  (pkg was actively called at a confirmed line)
        #   import line executed     → 0.65  (pkg was loaded at runtime)
        #   file-level fallback      → 0.40  (file ran + imports pkg, but line unconfirmed)
        #
        # AST parsing resolves aliases:
        #   `import sqlalchemy as sa`  → sa.execute( maps to sqlalchemy
        #   `from flask import render_template` → render_template( maps to flask

        # Per-file executed line sets keyed by the path as it appears in coverage.json
        file_executed_lines: Dict[str, Set[int]] = {}
        for file_path, file_data in coverage_data.get("files", {}).items():
            file_executed_lines[file_path] = set(file_data.get("executed_lines", []))

        pkg_import_lines: Dict[str, Set[Tuple[str, int]]] = {}
        pkg_callsite_lines: Dict[str, Set[Tuple[str, int]]] = {}
        runtime_imported_packages: Set[str] = set()

        # Common container WORKDIR prefixes to strip when resolving paths against repo_path.
        # Coverage.json from inside a container has paths like /app/api/views.py but the
        # file lives at <repo_path>/api/views.py on the host.
        # `container_workdir` from config takes priority; common defaults are appended as fallback.
        _default_prefixes = ("/app/", "/code/", "/srv/", "/usr/src/app/", "/home/app/")
        if container_workdir:
            _wd = container_workdir.rstrip("/") + "/"
            _CONTAINER_PREFIXES = (_wd,) + tuple(p for p in _default_prefixes if p != _wd)
        else:
            _CONTAINER_PREFIXES = _default_prefixes

        # Build a reverse mapping from dist name → import name using the runtime
        # import_map produced by MetadataAgent.  This covers niche packages that
        # are missing from the hardcoded _PYPI_TO_IMPORT dict.
        _dist_to_import: Dict[str, str] = {}
        if import_map:
            for imp_name, dist_name in import_map.items():
                # Prefer the first (shortest) import name seen for each dist
                if dist_name not in _dist_to_import or len(imp_name) < len(_dist_to_import[dist_name]):
                    _dist_to_import[dist_name] = imp_name

        for file_path in hit_files_full:
            try:
                p = Path(file_path)
                # 1. Try the path as-is (works when vulnreach runs natively, not in Docker)
                if not p.exists() and repo_path is not None:
                    # 2. Strip known container WORKDIR prefixes and join with repo_path
                    resolved = None
                    for prefix in _CONTAINER_PREFIXES:
                        if file_path.startswith(prefix):
                            candidate = repo_path / file_path[len(prefix):]
                            if candidate.exists():
                                resolved = candidate
                                break
                    # 3. Fallback: treat path as relative to repo_path
                    if resolved is None:
                        rel = p.name  # last resort: just the filename
                        candidate = repo_path / p.relative_to(p.anchor) if p.is_absolute() else repo_path / file_path
                        if not candidate.exists():
                            candidate = repo_path / rel
                        if candidate.exists():
                            resolved = candidate
                    p = resolved if resolved else p
                if not p or not p.exists() or p.suffix != ".py":
                    continue
                source = p.read_text(encoding="utf-8", errors="replace")

                # --- AST pass: build alias maps for this file ---
                alias_to_pkg, imported_names = _parse_file_imports(source)

                # Record all resolved top-level packages (for fallback)
                for pkg in alias_to_pkg.values():
                    runtime_imported_packages.add(pkg)
                for pkg in imported_names.values():
                    runtime_imported_packages.add(pkg)

                # --- Line pass: record import lines and call-site lines ---
                lines = source.splitlines()
                for lineno, line in enumerate(lines, start=1):
                    stripped = line.strip()

                    # Import line: resolve to top-level pkg via AST alias map
                    if stripped.startswith("import ") or stripped.startswith("from "):
                        m = re.match(
                            r"^\s*(?:import|from)\s+([a-zA-Z_][a-zA-Z0-9_]*)", line
                        )
                        if m:
                            raw = m.group(1).lower()
                            # Prefer AST-resolved name, fall back to raw token
                            pkg = alias_to_pkg.get(raw) or imported_names.get(raw) or raw
                            pkg_import_lines.setdefault(pkg, set()).add((file_path, lineno))

                    # Call-site line: `alias.method(` or `bare_name(`
                    # Use AST alias maps so `sa.execute(` → sqlalchemy
                    for cm in re.finditer(
                        r"\b([a-zA-Z_][a-zA-Z0-9_]*)(?:\.([a-zA-Z_]\w*))?\s*\(", line
                    ):
                        caller = cm.group(1).lower()
                        # Resolve via alias_to_pkg (e.g. sa → sqlalchemy)
                        resolved = alias_to_pkg.get(caller)
                        if resolved:
                            pkg_callsite_lines.setdefault(resolved, set()).add((file_path, lineno))
                        # Resolve via imported_names (e.g. render_template → flask)
                        resolved2 = imported_names.get(caller)
                        if resolved2:
                            pkg_callsite_lines.setdefault(resolved2, set()).add((file_path, lineno))
            except Exception:
                pass

        # Build a flat lowercased corpus of all stack frame text from taint sink
        # events so we can do a single substring scan per package later.
        taint_stack_corpus: List[str] = []
        if taint_events:
            for event in taint_events:
                if event.get("event_type") == "taint_sink_reached":
                    stack = event.get("data", {}).get("stack", [])
                    for frame in stack:
                        taint_stack_corpus.append(frame.lower())

        # Strategy 2b — function-level cross-reference.
        # Static analysis produces call chains like "home → flask.render_template_string".
        # Coverage only shows app code (home, yaml_test, ...) — not library files.
        # If coverage confirms the app-side caller ran, the library is reachable.
        # Build: CVE → {lowercased app function names from static findings}
        static_fn_index: Dict[str, set] = {}
        hit_fns_lower = {fn.lower() for fn in hit_functions}
        for sf in (static_findings or []):
            cve = sf.get("cve_id")
            if not cve:
                continue
            raw_fn = sf.get("function") or ""
            for fn in raw_fn.split(","):
                fn = fn.strip().lower()
                if fn:
                    static_fn_index.setdefault(cve, set()).add(fn)
                    static_fn_index[cve].add(fn.rsplit(".", 1)[-1])

        findings: List[ReachabilityFinding] = []

        for vuln in vulnerabilities:
            pypi_name = (vuln.get("package") or "").lower()
            if not pypi_name:
                continue

            # Resolve PyPI name → importable name (e.g. pillow → PIL).
            # Lookup order: hardcoded dict → runtime import_map → pypi name as-is.
            import_name = (
                _PYPI_TO_IMPORT.get(pypi_name)
                or _dist_to_import.get(pypi_name)
                or pypi_name
            ).lower()

            # For Maven coordinates (group:artifact) build alternate path-style match keys
            # so that e.g. "org.apache.logging.log4j:log4j-core" matches against eBPF
            # coverage paths like "org/apache/logging/log4j/core/Logger.java".
            # Two alternatives are generated:
            #   1. group as Unix path  — "org/apache/logging/log4j"
            #   2. artifact keywords  — tokens from "log4j-core" with len ≥ 5: ["log4j"]
            # "core", "text", "api", etc. are intentionally excluded (too generic).
            _maven_alt_names: list[str] = []
            if ":" in import_name:
                _group_part, _artifact_part = import_name.split(":", 1)
                _maven_alt_names.append(_group_part.replace(".", "/"))
                for _kw in re.split(r"[.\-]", _artifact_part):
                    if len(_kw) >= _MIN_PKG_MATCH_LEN + 1:
                        _maven_alt_names.append(_kw)

            cves = vuln.get("cve_id", [])
            if isinstance(cves, str):
                cves = [cves]
            if not cves:
                cves = [None]

            # Strategy 1: Direct library path/function in coverage.
            # Now that coveragerc no longer restricts source to app-only, site-packages
            # files appear in coverage data. Match against full paths (hit_files_full)
            # so that e.g. "requests" matches
            # "/usr/local/lib/python3.11/site-packages/requests/adapters.py".
            # For Java/Maven packages the Maven alt names are also checked against
            # hit_files_full (e.g. "log4j" in "org/apache/logging/log4j/core/Logger.java").
            dynamically_hit = False
            if len(import_name) >= _MIN_PKG_MATCH_LEN:
                dynamically_hit = (
                    any(import_name in f.lower() for f in hit_files)
                    or any(import_name in f.lower() for f in hit_functions)
                    or any(
                        f"/site-packages/{import_name}" in f.lower()
                        or f"/site-packages/{import_name}/" in f.lower()
                        for f in hit_files_full
                    )
                    or any(
                        any(alt in f.lower() for f in hit_files_full)
                        for alt in _maven_alt_names
                        if len(alt) >= _MIN_PKG_MATCH_LEN
                    )
                )

            # Strategy 2a: Line-level import / call-site check.
            # Sub-levels (strongest first):
            #   2a-call: a call-site line for this pkg was in executed_lines → 0.80
            #   2a-import: an import line for this pkg was in executed_lines  → 0.65
            #   2a-file: file ran and imports pkg but line not confirmed       → 0.40
            import_in_executed = False
            import_line_hit = False    # import line itself executed
            callsite_line_hit = False  # call-site line executed
            evidence_line: Optional[int] = None  # best line number for the finding
            if not dynamically_hit:
                # Check call-site lines
                for (fp, ln) in pkg_callsite_lines.get(import_name, set()):
                    if ln in file_executed_lines.get(fp, set()):
                        callsite_line_hit = True
                        evidence_line = ln
                        break
                # Check import lines
                if not callsite_line_hit:
                    for (fp, ln) in pkg_import_lines.get(import_name, set()):
                        if ln in file_executed_lines.get(fp, set()):
                            import_line_hit = True
                            evidence_line = ln
                            break
                # Fallback: file-level
                import_in_executed = (
                    callsite_line_hit
                    or import_line_hit
                    or import_name in runtime_imported_packages
                )

            # Strategy 2b: App-side caller from static call chain was executed.
            # e.g. static says home() → flask.render_template_string(); if home()
            # appears in coverage hit_functions, Flask is runtime-confirmed even
            # though Flask's own files are not in coverage (site-packages).
            if not dynamically_hit:
                for cve in cves:
                    if cve and cve in static_fn_index:
                        if static_fn_index[cve] & hit_fns_lower:
                            dynamically_hit = True
                            import_in_executed = False
                            break

            # Strategy 3: Package in taint sink event stack frames
            taint_confirmed = False
            if not dynamically_hit and not import_in_executed:
                if len(import_name) >= _MIN_PKG_MATCH_LEN:
                    taint_confirmed = any(
                        import_name in frame for frame in taint_stack_corpus
                    )

            # Only emit findings for packages with ACTUAL coverage evidence.
            # Packages with no evidence are skipped — the orchestrator will
            # only see them via static reach map.
            if not dynamically_hit and not import_in_executed and not taint_confirmed:
                continue

            if dynamically_hit:
                # Direct library code in coverage → strongest signal
                verdict, confidence = "CONFIRMED", 0.95
                sink_reachable = True
                import_time_hit = False
            elif import_in_executed:
                if callsite_line_hit:
                    # Call to pkg executed at a confirmed line → strong indirect signal
                    verdict, confidence = "LIKELY", 0.80
                    sink_reachable = True
                    import_time_hit = False
                elif import_line_hit:
                    # Import line itself was executed → pkg loaded at runtime
                    verdict, confidence = "LIKELY", 0.65
                    sink_reachable = False
                    import_time_hit = True
                else:
                    # File ran and imports pkg, but which lines ran is unknown
                    verdict, confidence = "LIKELY", 0.40
                    sink_reachable = False
                    import_time_hit = True
            else:
                # Taint stack evidence
                verdict, confidence = "CONFIRMED", 0.90
                sink_reachable = True
                import_time_hit = False

            for cve in cves:
                findings.append(
                    ReachabilityFinding(
                        cve_id=cve,
                        package=vuln.get("package"),
                        import_detected=True,
                        call_chain_exists=dynamically_hit or taint_confirmed,
                        sink_reachable=sink_reachable,
                        verdict=verdict,
                        confidence=confidence,
                        evidence_type="dynamic",
                        import_time_hit=import_time_hit,
                        function=None,
                        files=list(hit_files)[:5],
                        line=evidence_line,
                    )
                )

        return findings

    # ------------------------------------------------------------------
    # Docker-compose mode
    # ------------------------------------------------------------------

    async def _run_compose_mode(
        self,
        context: ScanContext,
        repo_path: Path,
        runtime: Any,
        preflight: Dict[str, Any],
    ) -> AgentResult:
        """Run dynamic reachability using docker-compose.

        Flow:
          1. Patch Dockerfile (if build context) to inject coverage instrumentation
          2. Patch docker-compose.yml to mount coverage volume + set env
          3. `docker compose up -d --build`
          4. Wait for healthy
          5. Run schemathesis
          6. `docker compose down`
          7. Extract coverage from volume (or via `docker compose exec`)
          8. Correlate
        """
        compose_path = Path(preflight["compose_path"])
        openapi_path = preflight["openapi_path"]
        coverage_wait = runtime.coverage_wait
        container_port = runtime.container_port

        # eBPF sidecar dispatch — non-invasive path (no Dockerfile patching).
        # Only activates when: ebpf.enabled AND ebpf.sidecar_mode AND modules available.
        ebpf_cfg = runtime.ebpf
        if (
            ebpf_cfg.enabled
            and ebpf_cfg.sidecar_mode
            and _EBPF_SIDECAR_AVAILABLE
            and self._ebpf_available(ebpf_cfg.tracer)
        ):
            logger.info(
                "[dynamic][compose] eBPF sidecar mode active — "
                "injecting compose override (no Dockerfile patching)"
            )
            return await self._run_ebpf_sidecar_mode(context, repo_path, runtime, preflight)

        coverage_dir = tempfile.mkdtemp(prefix="vulnreach_cov_", dir=_WORK_BASE)
        patched_dockerfile_path: Optional[str] = None

        # Step 1 — Patch the Dockerfile used by the target service
        dockerfile_path = preflight.get("dockerfile_path")
        dockerfile_already_instrumented = False
        if dockerfile_path and Path(dockerfile_path).exists():
            content = Path(dockerfile_path).read_text(encoding="utf-8")
            if "COVERAGE_PROCESS_START" in content:
                dockerfile_already_instrumented = True
                logger.info("[dynamic][compose] Dockerfile already has coverage instrumentation")
            else:
                # Patch Dockerfile to inject coverage
                patched_content, skip_reason = self._patch_dockerfile(Path(dockerfile_path))
                if patched_content:
                    # Write to the coverage tempdir, not repo_path, so we never
                    # mutate the user's source tree. Docker Compose accepts an
                    # absolute path for `build.dockerfile`.
                    patched_dockerfile_path = str(Path(coverage_dir) / "Dockerfile.patched")
                    Path(patched_dockerfile_path).write_text(patched_content, encoding="utf-8")
                    logger.info("[dynamic][compose] Wrote patched Dockerfile to tempdir (not repo)")
                else:
                    logger.warning(f"[dynamic][compose] Could not patch Dockerfile: {skip_reason}")

        # Step 2 — Patch compose file
        patched_compose_path, patch_meta = self._patch_compose_file(
            compose_path, repo_path, coverage_dir, container_port,
            patched_dockerfile=patched_dockerfile_path,
            already_instrumented=dockerfile_already_instrumented,
        )
        if patched_compose_path is None:
            shutil.rmtree(coverage_dir, ignore_errors=True)
            if patched_dockerfile_path:
                Path(patched_dockerfile_path).unlink(missing_ok=True)
            return AgentResult(
                tool_name=self.tool_name, findings=[],
                metadata={"status": "failed", "step": "compose_patch", **patch_meta},
            )

        container_started: Dict[str, str] = {"status": "no", "id": "na"}
        schemathesis_meta: Dict[str, Any] = {}
        target_svc = patch_meta.get("target_service", "backend")
        compose_project = _safe_compose_project_name(repo_path)

        try:
            # Step 3 — docker compose up
            logger.info("[dynamic][compose] Building and starting services...")
            proc = await asyncio.create_subprocess_exec(
                "docker", "compose", "-p", compose_project, "-f", str(patched_compose_path),
                "up", "-d", "--build",
                cwd=str(repo_path),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            try:
                stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=300)
            except asyncio.TimeoutError:
                proc.kill()
                await proc.wait()
                return AgentResult(
                    tool_name=self.tool_name, findings=[],
                    metadata={"status": "failed", "step": "compose_up_timeout"},
                )

            if proc.returncode != 0:
                err = stderr.decode("utf-8", errors="replace")[-2000:]
                return AgentResult(
                    tool_name=self.tool_name, findings=[],
                    metadata={"status": "failed", "step": "compose_up", "stderr": err},
                )

            # Step 4 — Wait for healthy
            base_url = f"http://{_target_host()}:{container_port}"
            healthy = await self._wait_for_healthy(base_url, timeout=30)
            if not healthy:
                return AgentResult(
                    tool_name=self.tool_name, findings=[],
                    metadata={"status": "failed", "step": "health_check", "url": base_url},
                )

            container_started = {"status": "yes-running", "id": "compose"}

            # Step 5 — Schemathesis
            schemathesis_meta = await self._run_schemathesis(
                base_url, openapi_path, container_port, None
            )

            # Wait for coverage flush
            logger.info(f"[dynamic][compose] Waiting {coverage_wait}s for coverage flush...")
            await asyncio.sleep(coverage_wait)

            # Step 6a — Extract coverage via docker compose exec BEFORE stopping.
            # This runs `coverage combine && coverage json` inside the running
            # container, writing the result to the mounted /coverage volume.
            await self._extract_coverage_via_compose(
                patched_compose_path, repo_path, target_svc, coverage_dir, compose_project
            )

        finally:
            # Step 6b — docker compose down
            down_proc = await asyncio.create_subprocess_exec(
                "docker", "compose", "-p", compose_project, "-f", str(patched_compose_path),
                "down", "--remove-orphans",
                cwd=str(repo_path),
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
            )
            try:
                await asyncio.wait_for(down_proc.wait(), timeout=60)
            except asyncio.TimeoutError:
                down_proc.kill()
                await down_proc.wait()

            # Cleanup patched files
            if patched_compose_path and Path(patched_compose_path).exists():
                Path(patched_compose_path).unlink(missing_ok=True)
            if patched_dockerfile_path and Path(patched_dockerfile_path).exists():
                Path(patched_dockerfile_path).unlink(missing_ok=True)

        # Step 7 — Parse coverage
        coverage_data: Optional[Dict[str, Any]] = None
        coverage_meta: Dict[str, Any] = {}
        taint_events: List[Dict[str, Any]] = []

        cov_json = Path(coverage_dir) / "coverage.json"
        if cov_json.exists():
            try:
                coverage_data = json.loads(cov_json.read_text(encoding="utf-8"))
                shutil.copy2(cov_json, repo_path / "coverage.json")
                coverage_meta = {"files_count": len(coverage_data.get("files", {}))}
            except Exception as e:
                coverage_meta = {"error": f"coverage_parse_failed: {e}"}

        # Also try combining raw .coverage files on the host if coverage.json wasn't produced
        if not coverage_data:
            coverage_files = list(Path(coverage_dir).glob(".coverage*"))
            if coverage_files:
                coverage_data, coverage_meta = await self._combine_coverage_on_host(
                    coverage_dir, repo_path
                )

        # Collect taint events
        for ef in sorted(Path(coverage_dir).glob("runtime_events.*.json")):
            try:
                batch = json.loads(ef.read_text(encoding="utf-8"))
                if isinstance(batch, list):
                    taint_events.extend(batch)
            except Exception:
                pass

        shutil.rmtree(coverage_dir, ignore_errors=True)

        if not coverage_data:
            return AgentResult(
                tool_name=self.tool_name, findings=[],
                metadata={
                    "status": "skipped", "step": "coverage_collection",
                    "container_started": container_started,
                    "reason": coverage_meta.get("error", "empty coverage"),
                    "schemathesis": schemathesis_meta,
                    "coverage_dir_files": os.listdir(coverage_dir) if Path(coverage_dir).exists() else [],
                },
            )

        # Step 8 — Correlate
        findings = self._correlate(coverage_data, context.vulnerabilities, taint_events, static_findings=context.taint_flows, repo_path=repo_path, import_map=context.import_map, container_workdir=getattr(context.config.scan.runtime, "container_workdir", ""))
        return AgentResult.model_validate({
            "tool_name": self.tool_name,
            "findings": [f.model_dump() for f in findings],
            "metadata": {
                "status": "ok",
                "mode": "compose",
                "finding_count": len(findings),
                "container_started": container_started,
                "schemathesis": schemathesis_meta,
                "coverage": coverage_meta,
            },
        })

    async def _extract_coverage_via_compose(
        self,
        compose_path: str,
        repo_path: Path,
        service_name: str,
        coverage_dir: str,
        compose_project: str,
        retries: int = 3,
        retry_wait: float = 5.0,
    ) -> bool:
        """Run coverage combine + json inside the running container via docker compose exec.

        Retries up to `retries` times with `retry_wait` seconds between attempts so that
        in-flight async handlers and lazy coverage flushes have time to settle.
        Returns True when coverage.json is successfully written with content.
        """
        cov_json = Path(coverage_dir) / "coverage.json"

        for attempt in range(1, retries + 1):
            proc = await asyncio.create_subprocess_exec(
                "docker", "compose", "-p", compose_project, "-f", compose_path,
                "exec", "-T", service_name,
                "sh", "-c",
                # 1. Copy .coverage* from /tmp (written by COVERAGE_PROCESS_START) to mount
                # 2. Also copy from /app (some frameworks write relative to workdir)
                # 3. Combine all parallel coverage files into one
                # 4. Export as JSON to the shared mount
                "cp /tmp/.coverage* /coverage/ 2>/dev/null || true; "
                "cp /app/.coverage* /coverage/ 2>/dev/null || true; "
                "cd /coverage && "
                "coverage combine .coverage* 2>/dev/null; "
                "coverage json -o /coverage/coverage.json; "
                "echo __done__",
                cwd=str(repo_path),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            try:
                stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=30)
                logger.info(
                    f"[dynamic][compose] Coverage extraction attempt {attempt}/{retries}: "
                    f"rc={proc.returncode}"
                )
                if stderr:
                    logger.debug(f"[dynamic][compose] stderr: {stderr.decode()[:500]}")
            except asyncio.TimeoutError:
                proc.kill()
                await proc.wait()
                logger.warning(
                    f"[dynamic][compose] Coverage extraction attempt {attempt}/{retries} timed out"
                )
                if attempt < retries:
                    await asyncio.sleep(retry_wait)
                continue

            # Success check: coverage.json must exist and have real content
            if cov_json.exists() and cov_json.stat().st_size > 50:
                logger.info(
                    f"[dynamic][compose] coverage.json ready "
                    f"({cov_json.stat().st_size} bytes) after attempt {attempt}"
                )
                return True

            if attempt < retries:
                logger.info(
                    f"[dynamic][compose] coverage.json not ready yet — "
                    f"waiting {retry_wait}s before retry {attempt + 1}"
                )
                await asyncio.sleep(retry_wait)

        logger.warning(
            f"[dynamic][compose] Coverage extraction failed after {retries} attempts"
        )
        return False

    async def _combine_coverage_on_host(
        self, coverage_dir: str, repo_path: Path
    ) -> tuple[Optional[Dict[str, Any]], Dict[str, Any]]:
        """Fallback: combine coverage files on the host using local Python."""
        cov_json = Path(coverage_dir) / "coverage.json"
        combine_proc = await asyncio.create_subprocess_exec(
            "python", "-m", "coverage", "combine",
            "--data-file", str(Path(coverage_dir) / ".coverage"),
            cwd=str(coverage_dir),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            await asyncio.wait_for(combine_proc.communicate(), timeout=30)
        except asyncio.TimeoutError:
            combine_proc.kill()
            await combine_proc.wait()
            return None, {"error": "coverage_combine_timeout"}

        json_proc = await asyncio.create_subprocess_exec(
            "python", "-m", "coverage", "json",
            "--data-file", str(Path(coverage_dir) / ".coverage"),
            "-o", str(cov_json),
            cwd=str(coverage_dir),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            await asyncio.wait_for(json_proc.communicate(), timeout=30)
        except asyncio.TimeoutError:
            json_proc.kill()
            await json_proc.wait()
            return None, {"error": "coverage_json_timeout"}

        if cov_json.exists():
            try:
                data = json.loads(cov_json.read_text(encoding="utf-8"))
                shutil.copy2(cov_json, repo_path / "coverage.json")
                return data, {"files_count": len(data.get("files", {}))}
            except Exception as e:
                return None, {"error": f"coverage_parse_failed: {e}"}

        return None, {"error": "coverage_json_not_created"}

    def _patch_compose_file(
        self,
        compose_path: Path,
        repo_path: Path,
        coverage_dir: str,
        container_port: int,
        patched_dockerfile: Optional[str] = None,
        already_instrumented: bool = False,
    ) -> Tuple[Optional[str], Dict[str, Any]]:
        """Patch docker-compose file to inject coverage instrumentation.

        Adds to the target web service:
          - COVERAGE_PROCESS_START env var
          - /coverage volume mount  (host → container)
          - Port mapping if not present
          - Dockerfile override (if a patched Dockerfile was generated)
        Writes a patched copy; never modifies the original.

        Returns (patched_path, meta). patched_path is None on failure.
        """
        try:
            import yaml as _yaml
        except ImportError:
            return None, {"error": "pyyaml_not_installed"}

        try:
            content = compose_path.read_text(encoding="utf-8")
            data = _yaml.safe_load(content)
        except Exception as exc:
            return None, {"error": "compose_parse_failed", "details": str(exc)}

        services = data.get("services")
        if not services or not isinstance(services, dict):
            return None, {"error": "no_services_in_compose"}

        # Find the primary web service — prefer names 'web', 'app', 'api',
        # otherwise pick the first service that exposes a port.
        target_svc = None
        for preferred in ("web", "app", "api", "server", "backend"):
            if preferred in services:
                target_svc = preferred
                break
        if not target_svc:
            for svc_name, svc_cfg in services.items():
                if svc_cfg.get("ports"):
                    target_svc = svc_name
                    break
        if not target_svc:
            target_svc = next(iter(services))

        svc = services[target_svc]
        logger.info(f"[dynamic][compose] Patching service '{target_svc}'")

        # Override Dockerfile if we generated a patched one
        if patched_dockerfile:
            build = svc.get("build")
            if isinstance(build, str):
                # build: . → build: {context: ., dockerfile: ...}
                svc["build"] = {
                    "context": build,
                    "dockerfile": patched_dockerfile,
                }
            elif isinstance(build, dict):
                build["dockerfile"] = patched_dockerfile
            else:
                svc["build"] = {"context": ".", "dockerfile": patched_dockerfile}

        # Inject environment variables
        env = svc.get("environment")
        cov_env_vars = {
            "COVERAGE_PROCESS_START": "/app/.coveragerc",
        }
        if isinstance(env, list):
            for k, v in cov_env_vars.items():
                if not any(k in e for e in env):
                    env.append(f"{k}={v}")
        elif isinstance(env, dict):
            for k, v in cov_env_vars.items():
                env.setdefault(k, v)
        else:
            svc["environment"] = dict(cov_env_vars)

        # Inject /coverage volume mount
        volumes = svc.get("volumes", [])
        cov_mount = f"{coverage_dir}:/coverage"
        if not any("/coverage" in str(v) for v in volumes):
            volumes.append(cov_mount)

        # Write a VulnReach-controlled .coveragerc into the coverage_dir and
        # mount it over the app's own .coveragerc.  This removes any restrictive
        # "source = ." directive so site-packages are measured, which is required
        # for correlating CVEs in third-party libraries.
        vulnreach_coveragerc = Path(coverage_dir) / ".coveragerc"
        vulnreach_coveragerc.write_text(
            "[run]\n"
            "omit = */migrations/*,manage.py,*/pip/*,*/setuptools/*,"
            "*/pkg_resources/*,*/coverage/*,*/distutils/*\n"
            "data_file = /tmp/.coverage\n"
            "parallel = true\n"
            "concurrency = multiprocessing\n"
            "\n[json]\n"
            "output = /tmp/coverage.json\n",
            encoding="utf-8",
        )
        coveragerc_mount = f"{vulnreach_coveragerc}:/app/.coveragerc"
        if not any(".coveragerc" in str(v) for v in volumes):
            volumes.append(coveragerc_mount)

        svc["volumes"] = volumes

        # Ensure port is exposed
        ports = svc.get("ports", [])
        port_str = f"{container_port}:{container_port}"
        if not any(str(container_port) in str(p) for p in ports):
            ports.append(port_str)
        svc["ports"] = ports

        # Write patched file (never overwrite original)
        patched_path = repo_path / ".vulnreach_compose.yml"
        try:
            patched_path.write_text(
                _yaml.dump(data, default_flow_style=False), encoding="utf-8"
            )
        except Exception as exc:
            return None, {"error": "compose_write_failed", "details": str(exc)}

        return str(patched_path), {
            "target_service": target_svc,
            "patched": True,
            "dockerfile_patched": patched_dockerfile is not None,
            "dockerfile_already_instrumented": already_instrumented,
        }

    # ------------------------------------------------------------------
    # eBPF non-invasive tracing (alternative to Dockerfile patching)
    # ------------------------------------------------------------------

    def _kernel_version_ok(self, min_major: int, min_minor: int) -> bool:
        """Return True if the host kernel is at least min_major.min_minor.

        Reads /proc/version and parses the version string.
        Fails open (returns True) on any parse error so scans are never
        blocked by a version detection failure.
        """
        try:
            version_str = Path("/proc/version").read_text(encoding="utf-8")
            # Format: "Linux version 5.15.0-91-generic ..."
            import re as _re
            m = _re.search(r"Linux version (\d+)\.(\d+)", version_str)
            if m:
                major, minor = int(m.group(1)), int(m.group(2))
                return (major, minor) >= (min_major, min_minor)
        except Exception:  # noqa: BLE001
            pass
        return True  # fail open

    def _ebpf_available(self, tracer: str = "bpftrace") -> bool:
        """Return True if eBPF tracing can be attempted on this host.

        Checks:
          1. Must be Linux (Docker Desktop macOS runs LinuxKit but syscall
             tracepoints are not exposed there).
          2. tracer binary must be in PATH.
          3. The syscall tracepoint required for openat mode must exist —
             Docker Desktop's LinuxKit kernel only exposes hardware perf events,
             not syscall/kprobe/uprobe tracepoints.  A quick dry-run probe
             detects this before we waste a scan attempt.
        """
        import platform
        if platform.system() != "Linux":
            logger.info("[dynamic][ebpf] Not Linux — eBPF unavailable")
            return False

        # Fast-path: detect Docker Desktop (LinuxKit) via /proc/version.
        # LinuxKit does not expose syscalls/kprobe/uprobe tracepoints to guests.
        # Checking here avoids spawning a bpftrace dry-run that will always fail.
        try:
            with open("/proc/version") as _pv:
                if "linuxkit" in _pv.read().lower():
                    logger.warning(
                        "[dynamic][ebpf] Running under Docker Desktop (LinuxKit) — "
                        "syscall tracepoints are not available. "
                        "eBPF requires a native Linux host. "
                        "Set runtime.ebpf.enabled=false to suppress this warning."
                    )
                    return False
        except OSError:
            pass

        if shutil.which(tracer) is None:
            logger.info(f"[dynamic][ebpf] {tracer} not found in PATH")
            return False

        # Probe check: verify the openat tracepoint actually exists.
        # On Docker Desktop (LinuxKit), only hardware: perf events are available.
        try:
            result = subprocess.run(
                [tracer, "-e",
                 "tracepoint:syscalls:sys_enter_openat { exit(); }"],
                capture_output=True,
                timeout=5,
            )
            if result.returncode != 0:
                err = result.stderr.decode("utf-8", errors="replace").strip()
                logger.warning(
                    "[dynamic][ebpf] syscall tracepoints unavailable "
                    "(likely Docker Desktop / LinuxKit kernel) — "
                    "falling back to Dockerfile-patch coverage mode. "
                    "bpftrace error: %s", err
                )
                return False
        except Exception as exc:  # noqa: BLE001
            logger.warning("[dynamic][ebpf] probe check failed: %s — skipping eBPF", exc)
            return False

        return True

    async def _get_container_pid(self, container_id: str) -> Optional[int]:
        """Return the host-namespace PID of the container's init process."""
        proc = await asyncio.create_subprocess_exec(
            "docker", "inspect", "--format", "{{.State.Pid}}", container_id,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            return None
        pid_str = stdout.decode("utf-8").strip()
        return int(pid_str) if pid_str.isdigit() and int(pid_str) > 0 else None

    def _build_bpftrace_script(
        self, pid: int, mode: str
    ) -> str:
        """Generate a bpftrace script scoped to the container's PID.

        openat mode (default, portable):
            Traces every file-open syscall in the container process tree.
            We filter matching lines in Python after collection.

        usdt mode (higher fidelity, requires CPython built with --with-dtrace):
            Intercepts Python's function__entry USDT probe, emitting the
            filename and function name for every Python call.
        """
        if mode == "line":
            # USDT python:line — fires on every executed Python line.
            # arg0 = filename (char*), arg1 = funcname (char*), arg2 = lineno (int).
            # (int64) cast required: without it some bpftrace versions print hex.
            return (
                f"usdt:/proc/{pid}/exe:python:line\n"
                "{{\n"
                '  printf("line:%s:%d\\n", str(arg0), (int64)arg2);\n'
                "}}\n"
            )
        if mode == "usdt":
            return (
                f"usdt:/proc/{pid}/exe:python:function__entry\n"
                "{{\n"
                '  printf("func:%s:%s\\n", str(arg0), str(arg1));\n'
                "}}\n"
            )
        # openat — trace openat syscalls for the entire container process tree.
        # We walk up from each syscall's task to find whether any ancestor has
        # the same host-namespace PID as the container's init process.  This
        # catches gunicorn/uWSGI worker forks and any sub-processes spawned by
        # the app, not just the single init PID.
        return (
            "tracepoint:syscalls:sys_enter_openat\n"
            "{{\n"
            f"  $target = (uint64){pid};\n"
            "  $t = curtask;\n"
            "  $found = (uint8)0;\n"
            "  unroll(10) {\n"
            "    if ($t->tgid == $target) { $found = 1; }\n"
            "    $t = $t->real_parent;\n"
            "  }\n"
            "  if ($found) {\n"
            '    printf("open:%s\\n", str(args->filename));\n'
            "  }\n"
            "}}\n"
        )

    async def _start_ebpf_tracer(
        self, pid: int, mode: str, tracer: str
    ) -> Optional[asyncio.subprocess.Process]:
        """Write a bpftrace script to a temp file and start the tracer."""
        script = self._build_bpftrace_script(pid, mode)
        script_path = Path(tempfile.mktemp(suffix=".bt"))
        script_path.write_text(script, encoding="utf-8")

        try:
            proc = await asyncio.create_subprocess_exec(
                tracer, str(script_path),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,  # capture stderr so startup errors are logged
            )
            logger.info(
                f"[dynamic][ebpf] Tracer started (pid={pid}, mode={mode}, tracer={tracer})"
            )
            return proc
        except Exception as exc:
            logger.warning(f"[dynamic][ebpf] Failed to start {tracer}: {exc}")
            script_path.unlink(missing_ok=True)
            return None

    async def _collect_ebpf_hits(
        self,
        tracer_proc: asyncio.subprocess.Process,
        vuln_packages: List[str],
    ) -> set[str]:
        """Stop the tracer and return the set of vulnerable package names hit."""
        try:
            tracer_proc.terminate()
            stdout, stderr = await asyncio.wait_for(tracer_proc.communicate(), timeout=10)
        except (asyncio.TimeoutError, ProcessLookupError):
            try:
                tracer_proc.kill()
            except ProcessLookupError:
                pass
            stdout = b""
            stderr = b""

        if stderr:
            err_text = stderr.decode("utf-8", errors="replace").strip()
            if err_text:
                logger.warning("[dynamic][ebpf] bpftrace stderr: %s", err_text)

        output = stdout.decode("utf-8", errors="replace")
        hit_packages: set[str] = set()

        for line in output.splitlines():
            line_lower = line.lower()
            for pkg in vuln_packages:
                import_name = _PYPI_TO_IMPORT.get(pkg.lower(), pkg.lower()).lower()
                if len(import_name) >= _MIN_PKG_MATCH_LEN and import_name in line_lower:
                    hit_packages.add(pkg.lower())

        logger.info(f"[dynamic][ebpf] Packages hit: {hit_packages or 'none'}")
        return hit_packages

    async def _build_plain_image(
        self, dockerfile_path: Path, repo_path: Path
    ) -> Tuple[Optional[str], Dict[str, Any]]:
        """Build the original image without instrumentation (for eBPF mode)."""
        repo_name = repo_path.name.lower().replace(" ", "_")
        image_tag = f"{repo_name}:plain"

        logger.info(f"[dynamic][ebpf] Building plain image {image_tag}")

        proc = await asyncio.create_subprocess_exec(
            "docker", "build",
            "-t", image_tag,
            "-f", str(dockerfile_path),
            str(repo_path),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=300)
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            return None, {"error": "docker_build_timeout"}

        if proc.returncode != 0:
            err = stderr.decode("utf-8", errors="replace")[-2000:]
            return None, {"error": "docker_build_failed", "stderr": err}

        return image_tag, {"image_tag": image_tag}

    async def _start_container_plain(
        self, image_tag: str, container_port: int, timeout: int
    ) -> Optional[str]:
        """Start the container without any coverage volume (eBPF mode)."""
        await self._cleanup_port_conflicts(container_port)

        proc = await asyncio.create_subprocess_exec(
            "docker", "run", "-d",
            "-p", f"{container_port}:{container_port}",
            image_tag,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=30)
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            logger.error("[dynamic][ebpf] Timed out starting plain container")
            return None

        if proc.returncode != 0:
            err = stderr.decode("utf-8", errors="replace")
            logger.error(f"[dynamic][ebpf] Failed to start container: {err}")
            return None

        container_id = stdout.decode("utf-8").strip()
        logger.info(f"[dynamic][ebpf] Started plain container: {container_id[:12]}")
        return container_id

    async def _run_observer_mode(
        self,
        context: "ScanContext",
        repo_path: Path,
        runtime: Any,
        preflight: Dict[str, Any],
    ) -> "AgentResult":
        """Language-agnostic CO-RE observer flow (P0–P5).

        Builds the plain image, runs it, drives Schemathesis traffic while a
        host-level cgroup-scoped observer records syscalls, then correlates
        file-open events to packages (Rule R1) and emits canonical findings.

        Requires Dockerfile mode + the built observer binary on the host.
        """
        from agents.ebpf.observer_runner import (
            observer_available,
            run_observer_reachability,
        )

        ebpf_cfg = runtime.ebpf
        container_port = runtime.container_port
        timeout = runtime.timeout
        openapi_path = preflight.get("openapi_path")
        dockerfile_path = preflight.get("dockerfile_path")

        if not dockerfile_path:
            return AgentResult(
                tool_name=self.tool_name, findings=[],
                metadata={"status": "skipped", "reason": "observer_requires_dockerfile_mode",
                          "container_started": {"status": "no", "id": "na"}},
            )

        available, reason = observer_available()
        if not available:
            return AgentResult(
                tool_name=self.tool_name, findings=[],
                metadata={"status": "skipped", "reason": f"observer_unavailable:{reason}",
                          "container_started": {"status": "no", "id": "na"}},
            )

        image_tag, build_meta = await self._build_plain_image(Path(dockerfile_path), repo_path)
        if not image_tag:
            return AgentResult(
                tool_name=self.tool_name, findings=[],
                metadata={"status": "failed", "step": "observer_image_build",
                          "container_started": {"status": "no", "id": "na"}, **build_meta},
            )

        container_id = await self._start_container_plain(image_tag, container_port, timeout)
        if not container_id:
            return AgentResult(
                tool_name=self.tool_name, findings=[],
                metadata={"status": "failed", "step": "observer_container_start",
                          "container_started": {"status": "no", "id": "na"}, "image": image_tag},
            )

        obs_meta: Dict[str, Any] = {}
        findings: List[Any] = []
        try:
            base_url = f"http://{_target_host()}:{container_port}"

            # Attach the observer BEFORE the app finishes booting: a host-level
            # observer that attaches after health-wait misses the interpreter's
            # startup import storm (openat fires once, at first import). We fold
            # the health-wait + traffic into the traffic callback so the observer
            # is already recording while the target imports its dependencies.
            async def traffic() -> None:
                healthy = await self._wait_for_healthy(base_url, timeout=30)
                if healthy:
                    await self._run_schemathesis(
                        base_url, openapi_path, container_port, workdir=None
                    )
                else:
                    logger.warning(
                        "[dynamic][observer] target never became healthy — "
                        "reporting startup-only observation"
                    )

            findings, obs_meta = await run_observer_reachability(
                container_id,
                context.vulnerabilities,
                import_map=context.import_map,
                taint_flows=context.taint_flows,
                duration=max(timeout, runtime.coverage_wait),
                traffic=traffic,
            )
        finally:
            await self._stop_container(container_id)

        return AgentResult.model_validate({
            "tool_name": self.tool_name,
            "findings": [f.model_dump() for f in findings],
            "metadata": {
                "status": "ok",
                "mode": "ebpf_observer",
                "finding_count": len(findings),
                "container_started": {"status": "yes-running", "id": container_id[:12]},
                "image_tag": image_tag,
                "observer": obs_meta,
            },
        })

    async def _run_ebpf_mode(
        self,
        context: "ScanContext",
        repo_path: Path,
        runtime: Any,
        preflight: Dict[str, Any],
    ) -> "AgentResult":
        """Full eBPF tracing flow: no Dockerfile patching, host-side tracing.

        The container is started from the original image.  A bpftrace script
        (scoped to the container's host PID) runs in parallel with Schemathesis
        traffic.  Package hits from the tracer output feed _correlate() directly.
        """
        ebpf_cfg = runtime.ebpf
        dockerfile_path = Path(preflight["dockerfile_path"])
        openapi_path = preflight["openapi_path"]
        container_port = runtime.container_port
        timeout = runtime.timeout

        image_tag, build_meta = await self._build_plain_image(dockerfile_path, repo_path)
        if not image_tag:
            return AgentResult(
                tool_name=self.tool_name,
                findings=[],
                metadata={
                    "status": "failed",
                    "step": "ebpf_image_build",
                    "container_started": {"status": "no", "id": "na"},
                    **build_meta,
                },
            )

        container_id = await self._start_container_plain(image_tag, container_port, timeout)
        if not container_id:
            return AgentResult(
                tool_name=self.tool_name,
                findings=[],
                metadata={
                    "status": "failed",
                    "step": "ebpf_container_start",
                    "container_started": {"status": "no", "id": "na"},
                    "image": image_tag,
                },
            )

        tracer_proc: Optional[asyncio.subprocess.Process] = None
        schemathesis_meta: Dict[str, Any] = {}

        try:
            base_url = f"http://{_target_host()}:{container_port}"
            healthy = await self._wait_for_healthy(base_url, timeout=30)
            if not healthy:
                return AgentResult(
                    tool_name=self.tool_name,
                    findings=[],
                    metadata={
                        "status": "failed",
                        "step": "ebpf_health_check",
                        "container_started": {"status": "no", "id": container_id[:12]},
                    },
                )

            container_pid = await self._get_container_pid(container_id)
            if container_pid:
                tracer_proc = await self._start_ebpf_tracer(
                    container_pid, ebpf_cfg.mode, ebpf_cfg.tracer
                )
            else:
                logger.warning(
                    "[dynamic][ebpf] Could not get container PID — tracing skipped"
                )

            schemathesis_meta = await self._run_schemathesis(
                base_url, openapi_path, container_port, workdir=None
            )

        finally:
            # Collect hits before the container disappears.
            ebpf_hits: set[str] = set()
            if tracer_proc is not None:
                vuln_packages = [
                    (v.get("package") or "").lower()
                    for v in context.vulnerabilities
                    if v.get("package")
                ]
                ebpf_hits = await self._collect_ebpf_hits(tracer_proc, vuln_packages)

            await self._stop_container(container_id)

        findings = self._correlate_from_ebpf(ebpf_hits, context.vulnerabilities)

        return AgentResult.model_validate({
            "tool_name": self.tool_name,
            "findings": [f.model_dump() for f in findings],
            "metadata": {
                "status": "ok",
                "mode": "ebpf",
                "finding_count": len(findings),
                "container_started": {"status": "yes-running", "id": container_id[:12]},
                "image_tag": image_tag,
                "schemathesis": schemathesis_meta,
                "ebpf": {
                    "tracer": ebpf_cfg.tracer,
                    "mode": ebpf_cfg.mode,
                    "packages_hit": sorted(ebpf_hits),
                },
            },
        })

    # ------------------------------------------------------------------
    # eBPF sidecar mode (compose-override, non-invasive)
    # ------------------------------------------------------------------

    async def _run_ebpf_sidecar_mode(
        self,
        context: ScanContext,
        repo_path: Path,
        runtime: Any,
        preflight: Dict[str, Any],
    ) -> AgentResult:
        """Run eBPF coverage via a compose-override sidecar container.

        The user's docker-compose.yml is never modified.  A companion
        override file is generated in the VulnReach work directory and passed
        to ``docker compose -f original -f override up``.

        The sidecar container (vulnreach-ebpf-sidecar) shares the target's
        PID namespace, runs bpftrace against the detected runtime, and writes
        /coverage/ebpf_coverage.json to a shared volume.  VulnReach reads
        that file after compose exits and feeds it through the existing
        coverage correlator.
        """
        ebpf_cfg = runtime.ebpf
        compose_path = Path(preflight["compose_path"])
        timeout = (runtime.timeout or self.default_timeout) * 2  # compose needs more time

        # Work directory for this run (under the bind-mounted VULNREACH_WORK_DIR
        # so the host Docker daemon can resolve volume paths).
        scan_id = getattr(context, "scan_id", None) or "run"
        output_dir = Path(_WORK_BASE) / f"vulnreach-ebpf-{scan_id}"
        output_dir.mkdir(parents=True, exist_ok=True)

        try:
            # --- Detect primary service and generate override ---
            try:
                target_service = _ebpf_detect_service(compose_path)
                logger.info("[dynamic][ebpf-sidecar] Target service: %s", target_service)
            except Exception as exc:  # noqa: BLE001
                logger.warning("[dynamic][ebpf-sidecar] Service detection failed: %s", exc)
                target_service = "app"  # best-effort default

            # Propagate language hint and traffic wait into the sidecar env
            # by passing them through the override file environment block.
            # inject_sidecar() uses defaults; we write the override then patch it.
            override_path = _ebpf_inject_sidecar(
                compose_path,
                target_service,
                output_dir,
            )

            # Patch LANGUAGE and TRAFFIC_WAIT into the generated override
            if ebpf_cfg.language != "auto" or runtime.coverage_wait != 10:
                raw = override_path.read_text(encoding="utf-8")
                raw = raw.replace(
                    "LANGUAGE=auto",
                    f"LANGUAGE={ebpf_cfg.language}",
                )
                raw = raw.replace(
                    "TRAFFIC_WAIT=30",
                    f"TRAFFIC_WAIT={runtime.coverage_wait}",
                )
                override_path.write_text(raw, encoding="utf-8")

            logger.info(
                "[dynamic][ebpf-sidecar] Override: %s", override_path
            )

            # --- Run compose stack ---
            cmd = _ebpf_compose_up_cmd(compose_path, override_path)
            logger.info("[dynamic][ebpf-sidecar] Running: %s", " ".join(cmd))

            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            try:
                stdout, stderr = await asyncio.wait_for(
                    proc.communicate(), timeout=float(timeout)
                )
            except asyncio.TimeoutError:
                proc.kill()
                await proc.wait()
                logger.error("[dynamic][ebpf-sidecar] Compose timed out after %ds", timeout)
                return AgentResult(
                    tool_name=self.tool_name,
                    findings=[],
                    metadata={
                        "status": "failed",
                        "step": "ebpf_sidecar_timeout",
                        "container_started": {"status": "unknown", "id": "na"},
                        "timeout_seconds": timeout,
                    },
                )

            stderr_text = stderr.decode("utf-8", errors="replace")
            if proc.returncode not in (0, 1):
                # returncode 1 is acceptable: sidecar exited 0 but another
                # service exited 1 (e.g. the target failed after coverage).
                # We still try to read the coverage file.
                logger.warning(
                    "[dynamic][ebpf-sidecar] compose exited %d — stderr: %s",
                    proc.returncode,
                    stderr_text[-1000:],
                )

            # --- Read coverage output ---
            ebpf_json_path = output_dir / "coverage" / "ebpf_coverage.json"
            if not ebpf_json_path.exists():
                return AgentResult(
                    tool_name=self.tool_name,
                    findings=[],
                    metadata={
                        "status": "failed",
                        "step": "ebpf_sidecar_no_output",
                        "container_started": {"status": "yes", "id": "na"},
                        "compose_exit_code": proc.returncode,
                        "ebpf_stderr": stderr_text[-2000:],
                    },
                )

            import json as _json
            normalised = _json.loads(ebpf_json_path.read_text(encoding="utf-8"))

            # Graceful skip — sidecar found no viable probe
            if normalised.get("skip"):
                logger.warning(
                    "[dynamic][ebpf-sidecar] Sidecar skipped: %s",
                    normalised.get("skip_reason", "unknown"),
                )
                return AgentResult(
                    tool_name=self.tool_name,
                    findings=[],
                    metadata={
                        "status": "skipped",
                        "step": "ebpf_sidecar_no_probe",
                        "skip_reason": normalised.get("skip_reason"),
                        "runtime": normalised.get("runtime"),
                        "container_started": {"status": "yes", "id": "na"},
                    },
                )

            # --- Convert and correlate ---
            coverage_data = _ebpf_to_coverage_py(normalised)
            file_count = len(coverage_data.get("files", {}))
            logger.info(
                "[dynamic][ebpf-sidecar] Coverage: %d files from %s runtime",
                file_count, normalised.get("runtime", "unknown"),
            )

            findings = self._correlate(
                coverage_data,
                context.vulnerabilities,
                taint_events=[],
                static_findings=context.taint_flows,
                repo_path=repo_path,
                import_map=context.import_map,
                container_workdir=getattr(
                    context.config.scan.runtime, "container_workdir", ""
                ),
            )

            return AgentResult.model_validate({
                "tool_name": self.tool_name,
                "findings": [f.model_dump() for f in findings],
                "metadata": {
                    "status": "ok",
                    "mode": "ebpf_sidecar",
                    "finding_count": len(findings),
                    "container_started": {"status": "yes", "id": "na"},
                    "ebpf": {
                        "runtime": normalised.get("runtime"),
                        "file_count": file_count,
                        "target_service": target_service,
                        "language_hint": ebpf_cfg.language,
                    },
                },
            })

        finally:
            # Always tear down the compose stack and clean up work dir
            down_cmd = _ebpf_compose_down_cmd(compose_path, override_path)
            try:
                down_proc = await asyncio.create_subprocess_exec(
                    *down_cmd,
                    stdout=asyncio.subprocess.DEVNULL,
                    stderr=asyncio.subprocess.DEVNULL,
                )
                await asyncio.wait_for(down_proc.communicate(), timeout=30.0)
            except Exception as exc:  # noqa: BLE001
                logger.debug("[dynamic][ebpf-sidecar] compose down failed (ignored): %s", exc)

            shutil.rmtree(output_dir, ignore_errors=True)

    def _correlate_from_ebpf(
        self,
        ebpf_hits: "set[str]",
        vulnerabilities: List[Dict[str, Any]],
    ) -> List[ReachabilityFinding]:
        """Build ReachabilityFindings from eBPF hit set.

        Verdicts:
          CONFIRMED 0.85 — package path observed in eBPF tracer output
          LIKELY    0.60 — package not observed (eBPF ran but no hit)
        """
        findings: List[ReachabilityFinding] = []

        for vuln in vulnerabilities:
            pypi_name = (vuln.get("package") or "").lower()
            if not pypi_name:
                continue

            hit = pypi_name in ebpf_hits
            verdict = "CONFIRMED" if hit else "LIKELY"
            confidence = 0.85 if hit else 0.60

            cves = vuln.get("cve_id", [])
            if isinstance(cves, str):
                cves = [cves]
            if not cves:
                cves = [None]

            for cve in cves:
                findings.append(
                    ReachabilityFinding(
                        cve_id=cve,
                        package=vuln.get("package"),
                        import_detected=hit,
                        call_chain_exists=hit,
                        sink_reachable=False,  # eBPF tracks file loads, not sink calls
                        verdict=verdict,
                        confidence=confidence,
                        evidence_type="dynamic",
                        function=None,
                        files=[],
                    )
                )

        return findings
