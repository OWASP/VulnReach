"""Shared taint→package matching for static reachability verdicts.

A static call chain proves a package is *reached*, not that the *vulnerable
sink* inside it is. Only a taint flow whose sink lives in the package's own
namespace supports the ``sink_reachable`` claim that lifts a finding to
CONFIRMED — this is the static-side analogue of eBPF Rule R4.

Matching is deliberately conservative: when it cannot confidently associate a
taint sink with a package it returns False, so the finding stays LIKELY rather
than becoming a false CONFIRMED. Distribution names are not sink namespaces
(``PyYAML`` → ``yaml``; Maven ``org.freemarker:freemarker`` → sink
``freemarker.template``; scoped npm ``@a/b`` → ``b``), so each language resolves
its own candidate identifiers.
"""
from __future__ import annotations

from typing import Iterable, Optional

from agents.utils.import_resolver import resolve_import_name

# Generic Maven artifact tokens that appear as a segment in unrelated namespaces
# (`com.foo.core`, `com.bar.client`). Matching Java taint by these alone would
# be a coin toss, so they are never sufficient on their own.
_JAVA_GENERIC_TOKENS = {
    "core", "api", "common", "commons", "util", "utils", "client", "server",
    "base", "lang", "runtime", "engine", "impl", "spi", "annotations",
}


def sink_modules(taint_flows) -> set[str]:
    """Full, lowercased sink module strings from taint flows.

    NOT reduced to a top-level token: Java sinks like ``com.google.gson`` and
    ``org.apache.velocity`` would collapse to ``com`` / ``org`` and then match
    either nothing or everything.
    """
    out: set[str] = set()
    for flow in taint_flows or []:
        sink = flow.get("sink") or {}
        definition = sink.get("definition") or {}
        module = (definition.get("module") or "").strip().lower()
        if module:
            out.add(module)
    return out


def _python_idents(package_name: str, import_map: Optional[dict]) -> set[str]:
    ids = {package_name.strip().lower()}
    try:
        resolved = resolve_import_name(package_name, import_map or {})
        if resolved:
            ids.add(resolved.strip().lower())
    except Exception:
        pass
    return ids


def _js_idents(package_name: str) -> set[str]:
    raw = package_name.strip().lower()
    # npm sink modules are bare names ("axios", "mysql2"); a package may be
    # "@scope/pkg" or "pkg".
    return {raw, raw.split("/")[-1]}


def _java_idents(package_name: str) -> tuple[set[str], set[str]]:
    """Return (namespaces, artifact_tokens) for a Maven coordinate.

    ``group:artifact[:version]`` — the group is a namespace prefix; the artifact
    is a token that frequently appears as a segment of the true package
    namespace (``org.freemarker:freemarker`` is used under ``freemarker.*``).
    """
    raw = package_name.strip().lower()
    namespaces: set[str] = set()
    tokens: set[str] = set()
    parts = raw.split(":")
    if len(parts) >= 2:
        namespaces.add(parts[0])                       # group, e.g. org.apache.velocity
        tokens.add(parts[1])                           # artifact, e.g. velocity / gson
    else:
        (namespaces if "." in raw else tokens).add(raw)
    return namespaces, {t for t in tokens if t}


def _matches_python(sink: str, ident: str) -> bool:
    # Preserve the original top-level semantics: sink "lxml.etree" credits "lxml".
    return sink == ident or sink.split(".")[0] == ident


def _matches_js(sink: str, ident: str) -> bool:
    return sink == ident


def _matches_java(sink: str, namespaces: set[str], tokens: set[str]) -> bool:
    for ns in namespaces:
        if sink == ns or sink.startswith(ns + ".") or ns.startswith(sink + "."):
            return True
    # gson / freemarker: group != namespace, so credit the artifact token when it
    # is a *specific* dotted segment of the sink namespace.
    segments = set(sink.split("."))
    for tok in tokens:
        if tok in _JAVA_GENERIC_TOKENS or len(tok) < 4:
            continue
        if sink == tok or tok in segments:
            return True
    return False


def package_taint_reachable(
    package_name: str,
    language: str,
    tainted: Iterable[str],
    import_map: Optional[dict] = None,
) -> bool:
    """True if any taint sink module corresponds to *package_name*.

    ``tainted`` is the set from :func:`sink_modules` (full module strings).
    """
    tainted = {t for t in (tainted or ()) if t}
    if not package_name or not tainted:
        return False
    lang = (language or "").strip().lower()

    if lang == "java":
        namespaces, tokens = _java_idents(package_name)
        return any(_matches_java(s, namespaces, tokens) for s in tainted)
    if lang in ("javascript", "js", "node", "typescript"):
        idents = _js_idents(package_name)
        return any(_matches_js(s, i) for s in tainted for i in idents)
    # python and anything else: top-level module comparison via the resolver.
    idents = _python_idents(package_name, import_map)
    return any(_matches_python(s, i) for s in tainted for i in idents)
