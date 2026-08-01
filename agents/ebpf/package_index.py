"""Package Index — maps container file paths back to the package that owns them.

The eBPF observer emits raw ``open:<path>`` events (P1). To turn those into
"package X was reached" (Rule R1), we need a path-prefix → package map. This
generalizes the existing hardcoded ``/site-packages/<pkg>/`` match in
agent_dynamic_reachability.py to every ecosystem.

Built from **filesystem enumeration** of the container root (``/proc/<pid>/root``),
which is authoritative for on-disk layout. An optional SBOM version map can enrich
entries. Paths stored are **container-absolute** (the ``/proc/<pid>/root`` prefix is
stripped) so they match what the observer emits from inside the container's mount ns.

Ecosystems in v1 (D4 lean: Python + Node first): python (site/dist-packages),
node (node_modules). Extend by adding a ``build_<eco>()`` function.
"""
from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from typing import Iterable, Optional

_PY_SITE_DIRS = ("site-packages", "dist-packages")
_PRUNE_DIRS = {"proc", "sys", "dev", "__pycache__"}


def _norm(name: str) -> str:
    """PEP 503-ish normalization for matching dist-info names to import names."""
    return re.sub(r"[-_.]+", "-", name).lower()


@dataclass(frozen=True)
class PackageEntry:
    name: str
    ecosystem: str                 # "python" | "node"
    path_prefix: str               # container-absolute; dirs end with "/"
    version: Optional[str] = None
    kind: str = "pure"             # "pure" | "native" (native detection is P4/R2)


class PackageIndex:
    """Longest-prefix path → PackageEntry lookup."""

    def __init__(self) -> None:
        self._entries: list[PackageEntry] = []
        self._sorted = True

    def add(self, entry: PackageEntry) -> None:
        self._entries.append(entry)
        self._sorted = False

    def extend(self, entries: Iterable[PackageEntry]) -> None:
        for e in entries:
            self.add(e)

    def entries(self) -> list[PackageEntry]:
        return list(self._entries)

    def __len__(self) -> int:
        return len(self._entries)

    def match(self, path: str) -> Optional[PackageEntry]:
        """Return the entry whose prefix is the longest match for *path*."""
        if not self._sorted:
            self._entries.sort(key=lambda e: len(e.path_prefix), reverse=True)
            self._sorted = True
        for e in self._entries:
            prefix = e.path_prefix
            if path == prefix.rstrip("/") or path.startswith(prefix):
                return e
        return None


# ── FS helpers ────────────────────────────────────────────────────────────────

def _strip_root(container_root: str, path: str) -> str:
    """Convert a /proc/<pid>/root/... path to a container-absolute path."""
    root = container_root.rstrip("/")
    if path.startswith(root):
        rel = path[len(root):]
        return rel if rel.startswith("/") else "/" + rel
    return path


def _find_dirs(container_root: str, names: tuple[str, ...], max_depth: int) -> list[str]:
    """Bounded search for directories whose basename is in *names*.

    Prunes noisy trees and does not descend into a matched dir (children are
    enumerated separately by the caller).
    """
    root = container_root.rstrip("/")
    base_depth = root.count("/")
    found: list[str] = []
    for dirpath, dirs, _files in os.walk(root):
        depth = dirpath.count("/") - base_depth
        if depth >= max_depth:
            dirs[:] = []
            continue
        dirs[:] = [d for d in dirs if d not in _PRUNE_DIRS]
        if os.path.basename(dirpath) in names:
            found.append(dirpath)
            dirs[:] = []  # don't descend into the package root itself
    return found


# ── Python ────────────────────────────────────────────────────────────────────

def build_python(container_root: str, max_depth: int = 9) -> list[PackageEntry]:
    entries: list[PackageEntry] = []
    for sp in _find_dirs(container_root, _PY_SITE_DIRS, max_depth):
        try:
            children = os.listdir(sp)
        except OSError:
            continue

        # dist-info / egg-info → version, keyed by normalized name
        versions: dict[str, str] = {}
        for c in children:
            m = re.match(r"(?P<n>.+?)-(?P<v>\d[^-]*)\.(?:dist|egg)-info$", c)
            if m:
                versions[_norm(m.group("n"))] = m.group("v")

        for c in children:
            if c.endswith((".dist-info", ".egg-info")) or c in _PRUNE_DIRS:
                continue
            full = os.path.join(sp, c)
            cabs = _strip_root(container_root, full)
            if os.path.isdir(full):
                entries.append(PackageEntry(
                    name=c, ecosystem="python",
                    path_prefix=cabs.rstrip("/") + "/",
                    version=versions.get(_norm(c)),
                ))
            elif c.endswith(".py"):
                name = c[:-3]
                entries.append(PackageEntry(
                    name=name, ecosystem="python", path_prefix=cabs,
                    version=versions.get(_norm(name)),
                ))
    return entries


# ── Node ──────────────────────────────────────────────────────────────────────

def _node_entry(container_root: str, full: str, name: str) -> PackageEntry:
    version: Optional[str] = None
    try:
        with open(os.path.join(full, "package.json"), encoding="utf-8") as fh:
            version = json.load(fh).get("version")
    except (OSError, ValueError):
        pass
    cabs = _strip_root(container_root, full)
    return PackageEntry(name=name, ecosystem="node",
                        path_prefix=cabs.rstrip("/") + "/", version=version)


def build_node(container_root: str, max_depth: int = 12) -> list[PackageEntry]:
    entries: list[PackageEntry] = []
    for nm in _find_dirs(container_root, ("node_modules",), max_depth):
        try:
            children = os.listdir(nm)
        except OSError:
            continue
        for c in children:
            if c.startswith("."):
                continue
            full = os.path.join(nm, c)
            if not os.path.isdir(full):
                continue
            if c.startswith("@"):  # scoped: @scope/pkg
                try:
                    for s in os.listdir(full):
                        sfull = os.path.join(full, s)
                        if os.path.isdir(sfull):
                            entries.append(_node_entry(container_root, sfull, f"{c}/{s}"))
                except OSError:
                    continue
            else:
                entries.append(_node_entry(container_root, full, c))
    return entries


# ── Public builder ────────────────────────────────────────────────────────────

def build_index(container_root: str,
                ecosystems: tuple[str, ...] = ("python", "node")) -> PackageIndex:
    """Build a PackageIndex from a container root (e.g. /proc/<pid>/root)."""
    idx = PackageIndex()
    if "python" in ecosystems:
        idx.extend(build_python(container_root))
    if "node" in ecosystems:
        idx.extend(build_node(container_root))
    return idx
