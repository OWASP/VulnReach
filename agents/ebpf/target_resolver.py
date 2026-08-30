"""Container → cgroup-id resolution for the eBPF observer (P0, D1: Docker).

The observer filters events in-kernel by cgroup id (``bpf_get_current_cgroup_id()``).
To populate that filter we must compute, from the host/node, the cgroup id of a
target container.  On cgroup v2 that id equals the **inode of the container's
cgroup directory** under ``/sys/fs/cgroup``.

Derivation (must run on the Linux host/node, cgroup-namespace = host):
    1. ``docker inspect`` → container Id + host-ns init PID
    2. read ``/proc/<pid>/cgroup`` → the ``0::<path>`` unified-hierarchy line
    3. ``os.stat("/sys/fs/cgroup" + <path>").st_ino`` → the cgroup id

``DockerTargetResolver`` is the v1 implementation behind the ``TargetResolver``
protocol; a containerd/CRI implementation is added at P9 without touching callers.
"""
from __future__ import annotations

import os
import subprocess
from dataclasses import dataclass
from typing import Protocol, runtime_checkable


@dataclass(frozen=True)
class ResolvedTarget:
    container_id: str
    cgroup_id: int      # cgroup v2 inode == bpf_get_current_cgroup_id()
    cgroup_path: str     # absolute path under /sys/fs/cgroup
    init_pid: int        # host-ns PID (for /proc/<pid>/root in P2+; unused in P0)
    runtime: str = "docker"


@runtime_checkable
class TargetResolver(Protocol):
    def resolve(self, container_ref: str) -> ResolvedTarget: ...


class ResolveError(RuntimeError):
    """Raised when a container's cgroup id cannot be determined."""


class DockerTargetResolver:
    """Resolve a Docker container reference to its cgroup id (D1, cgroup v2)."""

    def __init__(self, cgroup_root: str = "/sys/fs/cgroup", docker: str = "docker"):
        self._cgroup_root = cgroup_root.rstrip("/")
        self._docker = docker

    def resolve(self, container_ref: str) -> ResolvedTarget:
        cid, pid = self._inspect(container_ref)
        rel = self._unified_cgroup_path(pid)
        cgroup_path = self._cgroup_root + rel
        try:
            cgroup_id = os.stat(cgroup_path).st_ino
        except OSError as exc:
            raise ResolveError(f"cannot stat cgroup dir {cgroup_path}: {exc}") from exc
        return ResolvedTarget(
            container_id=cid,
            cgroup_id=cgroup_id,
            cgroup_path=cgroup_path,
            init_pid=pid,
        )

    # -- internals ---------------------------------------------------------

    def _inspect(self, ref: str) -> tuple[str, int]:
        try:
            out = subprocess.run(
                [self._docker, "inspect", "--format", "{{.Id}} {{.State.Pid}}", ref],
                capture_output=True, text=True, timeout=15,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise ResolveError(f"docker inspect failed for {ref}: {exc}") from exc
        if out.returncode != 0:
            raise ResolveError(f"docker inspect {ref}: {out.stderr.strip()}")
        parts = out.stdout.split()
        if len(parts) != 2 or not parts[1].isdigit():
            raise ResolveError(f"unexpected docker inspect output: {out.stdout!r}")
        pid = int(parts[1])
        if pid <= 0:
            raise ResolveError(f"container {ref} is not running (pid={pid})")
        return parts[0], pid

    def _unified_cgroup_path(self, pid: int) -> str:
        """Return the cgroup v2 path from /proc/<pid>/cgroup (the ``0::`` line)."""
        try:
            text = open(f"/proc/{pid}/cgroup", encoding="utf-8").read()
        except OSError as exc:
            raise ResolveError(f"cannot read /proc/{pid}/cgroup: {exc}") from exc
        for line in text.splitlines():
            # cgroup v2 unified line: "0::/<path>"
            if line.startswith("0::"):
                path = line[3:].strip()
                if path == "/" or not path:
                    raise ResolveError(
                        "cgroup path is '/' — resolver must run with cgroup-namespace=host "
                        "so the absolute container cgroup path is visible"
                    )
                return path
        raise ResolveError(
            f"no cgroup v2 (0::) entry in /proc/{pid}/cgroup — cgroup v1 is unsupported (A1)"
        )
