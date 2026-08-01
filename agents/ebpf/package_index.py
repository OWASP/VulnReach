"""Package Index — maps container file paths back to the package that owns them.

The eBPF observer emits raw ``open:<path>`` events (P1). To turn those into
"package X was reached" (Rule R1), we need a path-prefix → package map. This
generalizes the existing hardcoded ``/site-packages/<pkg>/`` match in
agent_dynamic_reachability.py to every ecosystem.

Built from **filesystem enumeration** of the container root (``/proc/<pid>/root``),
which is authoritative for on-disk layout. An optional SBOM version map can enrich
entries. Paths stored are **container-absolute** (the ``/proc/<pid>/root`` prefix is
stripped) so they match what the observer emits from inside the container's mount ns.

Ecosystems: python (site/dist-packages), node (node_modules), java (jars, keyed by
*class-name* prefix rather than file path — see the Java section). Extend by adding
a ``build_<eco>()`` function.
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
    ecosystem: str                 # "python" | "node" | "java"
    path_prefix: str               # container-absolute path, or a Java class-name
                                   # prefix like "com/fasterxml/jackson/"; dirs end "/"
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


# ── Java ──────────────────────────────────────────────────────────────────────
#
# Java is indexed by *class-name prefix*, not file path: the JVM's class__loaded
# probe reports "com/fasterxml/jackson/databind/ObjectMapper", never a path. That
# shares the PackageIndex's longest-prefix machinery because the two namespaces
# are naturally disjoint — class names never start with "/".

_JAR_NAME_RE = re.compile(r"^(?P<n>.+?)-(?P<v>\d[\w.]*(?:-[A-Za-z][\w.]*)?)\.jar$")
_MAVEN_PROPS_RE = re.compile(r"^META-INF/maven/[^/]+/[^/]+/pom\.properties$")


def _minimal_prefixes(dirs: set[str]) -> list[str]:
    """Drop any package dir that already sits under another one from the same jar.

    A jar owning com/foo/ and com/foo/bar/ only needs com/foo/ — this keeps the
    index small and the longest-prefix match unambiguous.
    """
    out: list[str] = []
    for d in sorted(dirs, key=len):
        if not any(d.startswith(k) for k in out):
            out.append(d)
    return out


def _jar_coordinates(zf, jar_path: str) -> tuple[str, Optional[str]]:
    """(artifactId, version) from the jar's embedded Maven metadata, else its name."""
    for entry in zf.namelist():
        if _MAVEN_PROPS_RE.match(entry):
            try:
                props = dict(
                    line.split("=", 1)
                    for line in zf.read(entry).decode("utf-8", "replace").splitlines()
                    if "=" in line and not line.startswith("#")
                )
            except (OSError, ValueError, KeyError):
                continue
            artifact = (props.get("artifactId") or "").strip()
            if artifact:
                return artifact, (props.get("version") or "").strip() or None
    base = os.path.basename(jar_path)
    m = _JAR_NAME_RE.match(base)
    if m:
        return m.group("n"), m.group("v")
    return base[:-4] if base.endswith(".jar") else base, None


def _index_jar(zf, jar_path: str, entries: list[PackageEntry], depth: int = 0) -> None:
    import io
    import zipfile

    names = zf.namelist()
    artifact, version = _jar_coordinates(zf, jar_path)

    pkg_dirs = {
        n.rsplit("/", 1)[0] + "/"
        for n in names
        if n.endswith(".class") and "/" in n and not n.startswith("META-INF/")
    }
    # Spring Boot fat jars nest the real dependencies under BOOT-INF/lib/ and the
    # application's own classes under BOOT-INF/classes/. Without this, every class
    # in a Boot app would be attributed to the single outer jar.
    pkg_dirs = {d[len("BOOT-INF/classes/"):] if d.startswith("BOOT-INF/classes/") else d
                for d in pkg_dirs}
    pkg_dirs = {d for d in pkg_dirs if d and not d.startswith(("BOOT-INF/", "WEB-INF/"))}

    for prefix in _minimal_prefixes(pkg_dirs):
        entries.append(PackageEntry(name=artifact, ecosystem="java",
                                    path_prefix=prefix, version=version))

    if depth == 0:
        for n in names:
            if n.startswith(("BOOT-INF/lib/", "WEB-INF/lib/")) and n.endswith(".jar"):
                try:
                    with zipfile.ZipFile(io.BytesIO(zf.read(n))) as nested:
                        _index_jar(nested, n, entries, depth + 1)
                except (OSError, ValueError, zipfile.BadZipFile):
                    continue


def build_java(container_root: str, max_depth: int = 9,
               max_jars: int = 2000) -> list[PackageEntry]:
    """Index every jar reachable under *container_root* by class-name prefix."""
    import zipfile

    entries: list[PackageEntry] = []
    root = container_root.rstrip("/")
    base_depth = root.count("/")
    seen = 0
    for dirpath, dirs, files in os.walk(root):
        if dirpath.count("/") - base_depth >= max_depth:
            dirs[:] = []
            continue
        dirs[:] = [d for d in dirs if d not in _PRUNE_DIRS]
        for f in files:
            if not f.endswith(".jar") or seen >= max_jars:
                continue
            seen += 1
            full = os.path.join(dirpath, f)
            try:
                with zipfile.ZipFile(full) as zf:
                    _index_jar(zf, full, entries)
            except (OSError, ValueError, zipfile.BadZipFile):
                continue
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
    if "java" in ecosystems:
        idx.extend(build_java(container_root))
    return idx
