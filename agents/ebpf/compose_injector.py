"""Compose override injector for the VulnReach eBPF sidecar.

Generates a ``docker-compose.vulnreach-sidecar.yml`` override file that
injects the eBPF sidecar service alongside the user's existing compose stack.

Design constraints
------------------
* The user's docker-compose.yml is NEVER modified or overwritten.
* The override file is written to ``output_dir`` (under VULNREACH_WORK_DIR),
  not into the user's repository.
* The sidecar shares the target service's PID namespace
  (``pid: "service:<target>"``), mounts ``/sys/kernel/debug`` read-only,
  and mounts the coverage output directory.
* ``privileged: true`` is used for broad compatibility.  On Linux kernels ≥ 5.8
  this can be replaced with ``cap_add: [CAP_BPF, CAP_PERFMON, SYS_PTRACE]``
  plus ``security_opt: [no-new-privileges:false]`` — documented in the
  generated file as a comment.

Public API
----------
detect_primary_service(compose_path)                  → str
inject_sidecar(compose_path, target_service,
               output_dir, sidecar_image)             → Path
get_compose_up_command(original, override)            → list[str]
get_compose_down_command(original, override)          → list[str]
"""
from __future__ import annotations

import logging
import shutil
from pathlib import Path

import yaml

logger = logging.getLogger(__name__)

# Source files for the sidecar image — copied into output_dir (which lives
# under VULNREACH_WORK_DIR, a bind mount visible to the host Docker daemon).
_SIDECAR_SRC = Path(__file__).parent / "sidecar"

# Service names that are strong hints for the "primary" app service
_PRIMARY_NAME_HINTS = {"web", "app", "api", "server", "backend", "service"}

# Port numbers that indicate a primary HTTP service
_PRIMARY_PORTS = {80, 443, 3000, 5000, 8000, 8080, 8443}


# ── Service detection ─────────────────────────────────────────────────────────

def _score_service(name: str, definition: dict) -> int:
    """Return a heuristic score; higher = more likely to be the primary app."""
    score = 0

    # Name hint
    if name.lower() in _PRIMARY_NAME_HINTS:
        score += 2

    # Published ports
    for port_entry in definition.get("ports", []) or []:
        port_str = str(port_entry)
        # Handles "host:container", "container", and integer forms
        for part in port_str.replace('"', "").split(":"):
            try:
                if int(part) in _PRIMARY_PORTS:
                    score += 3
                    break
            except ValueError:
                pass

    # Has a healthcheck — a good signal of a primary service
    if definition.get("healthcheck"):
        score += 1

    return score


def detect_primary_service(compose_path: Path) -> str:
    """Return the name of the most likely primary application service.

    Heuristics (descending priority):
      1. Only one service defined — return it.
      2. Service with a port published to a well-known HTTP port (+3).
      3. Service named "web", "app", "api", "server", or "backend" (+2).
      4. Service with a healthcheck block (+1).
      5. Ties broken by YAML key order (first wins).

    Never modifies compose_path.
    """
    raw = yaml.safe_load(compose_path.read_text(encoding="utf-8")) or {}
    services: dict = raw.get("services", {})

    if not services:
        raise ValueError(f"No services found in {compose_path}")

    if len(services) == 1:
        name = next(iter(services))
        logger.debug("[ebpf][inject] Single service detected: %s", name)
        return name

    best_name = ""
    best_score = -1

    for name, definition in services.items():
        defn = definition or {}
        score = _score_service(name, defn)
        logger.debug("[ebpf][inject] service=%s score=%d", name, score)
        if score > best_score:
            best_score = score
            best_name = name

    logger.info("[ebpf][inject] Primary service detected: %s (score=%d)", best_name, best_score)
    return best_name


# ── Override file generation ──────────────────────────────────────────────────

def inject_sidecar(
    compose_path: Path,
    target_service: str,
    output_dir: Path,
) -> Path:
    """Write a compose override file that injects the VulnReach eBPF sidecar.

    The override adds a single ``vulnreach-sidecar`` service that:
      - Builds from agents/ebpf/sidecar/ (Dockerfile + sidecar_entrypoint.py
        are copied into output_dir so the host Docker daemon can reach them
        via the VULNREACH_WORK_DIR bind mount)
      - Shares the target service's PID namespace
      - Mounts /sys/kernel/debug read-only (required for eBPF tracepoints)
      - Mounts the coverage output directory (read-write)
      - Waits for the target service to become healthy before starting
      - Exits with code 0 on success so ``--exit-code-from vulnreach-sidecar``
        terminates the compose stack cleanly

    Parameters
    ----------
    compose_path:    Path to the user's docker-compose.yml (never modified).
    target_service:  Name of the service to attach the sidecar to.
    output_dir:      Working directory under VULNREACH_WORK_DIR.  The sidecar
                     Dockerfile and entrypoint are staged here so the host
                     Docker daemon can build the image without needing /app.

    Returns the path of the written override file.
    """
    # Stage the sidecar build files into output_dir.
    # output_dir is under VULNREACH_WORK_DIR which is bind-mounted to the host,
    # so the host Docker daemon can resolve these paths when building.
    shutil.copy(_SIDECAR_SRC / "Dockerfile",             output_dir / "Dockerfile")
    shutil.copy(_SIDECAR_SRC / "sidecar_entrypoint.py",  output_dir / "sidecar_entrypoint.py")
    logger.debug("[ebpf][inject] Sidecar build files staged in %s", output_dir)

    # Ensure the coverage output sub-directory exists so Docker bind-mount
    # doesn't create it as root-owned.
    coverage_dir = output_dir / "coverage"
    coverage_dir.mkdir(parents=True, exist_ok=True)

    # Absolute path required: Docker resolves volumes relative to the host,
    # not relative to the compose file location.
    coverage_host_path = str(coverage_dir.resolve())
    build_context_path = str(output_dir.resolve())

    override: dict = {
        "services": {
            "vulnreach-sidecar": {
                # Build from the staged context under VULNREACH_WORK_DIR.
                # This avoids requiring a pre-built image on the host.
                "build": {
                    "context": build_context_path,
                    "dockerfile": "Dockerfile",
                },
                # On kernels >= 5.8, replace 'privileged: true' with:
                #   cap_add: [CAP_BPF, CAP_PERFMON, SYS_PTRACE]
                #   security_opt: ["no-new-privileges:false"]
                "privileged": True,
                "pid": f"service:{target_service}",
                "volumes": [
                    "/sys/kernel/debug:/sys/kernel/debug:ro",
                    f"{coverage_host_path}:/coverage",
                ],
                "environment": [
                    f"TARGET_SERVICE={target_service}",
                    "COVERAGE_DIR=/coverage",
                    "LANGUAGE=auto",
                    # VulnReach overwrites TRAFFIC_WAIT in _run_ebpf_sidecar_mode
                    # to match runtime.coverage_wait from the scan config.
                    "TRAFFIC_WAIT=30",
                ],
                "depends_on": {
                    target_service: {"condition": "service_healthy"},
                },
                "restart": "no",
            }
        }
    }

    # Prepend a header comment by building the YAML string manually.
    # yaml.dump doesn't support leading comments, so we prepend the block.
    header = (
        "# VulnReach eBPF sidecar override — auto-generated, do not edit.\n"
        "# This file is injected alongside the user's docker-compose.yml.\n"
        "# The user's compose file is NEVER modified.\n"
        "#\n"
        "# Kernel requirements:\n"
        "#   >= 4.9  uprobes (minimum)\n"
        "#   >= 5.2  BTF / modern bpftrace (recommended)\n"
        "#   >= 5.8  CAP_BPF replaces privileged: true (hardened alternative)\n"
        "#\n"
        "# To harden on kernel >= 5.8, replace 'privileged: true' with:\n"
        "#   cap_add: [CAP_BPF, CAP_PERFMON, SYS_PTRACE]\n"
        "#   security_opt: [\"no-new-privileges:false\"]\n"
        "#\n"
    )

    yaml_body = yaml.dump(override, default_flow_style=False, sort_keys=False)
    override_path = output_dir / "docker-compose.vulnreach-sidecar.yml"
    override_path.write_text(header + yaml_body, encoding="utf-8")

    logger.info(
        "[ebpf][inject] Override written: %s  (target=%s, build_ctx=%s)",
        override_path, target_service, build_context_path,
    )
    return override_path


# ── Compose command builders ──────────────────────────────────────────────────

def get_compose_up_command(
    original_compose: Path,
    override_path: Path,
) -> list[str]:
    """Return the ``docker compose up`` command that runs both files together.

    ``--abort-on-container-exit`` stops the stack when any container exits.
    ``--exit-code-from vulnreach-sidecar`` propagates the sidecar's exit code
    so VulnReach can distinguish clean completion (0) from errors (non-zero).
    """
    return [
        "docker", "compose",
        "-f", str(original_compose),
        "-f", str(override_path),
        "up",
        "--abort-on-container-exit",
        "--exit-code-from", "vulnreach-sidecar",
        "--no-color",
    ]


def get_compose_down_command(
    original_compose: Path,
    override_path: Path,
) -> list[str]:
    """Return the ``docker compose down`` command for cleanup."""
    return [
        "docker", "compose",
        "-f", str(original_compose),
        "-f", str(override_path),
        "down",
        "--remove-orphans",
    ]
