"""PDF report builder for VulnReach scan findings.

Generates a structured PDF using reportlab.platypus:
  1. Header  — title, scan metadata
  2. Summary — counts by reachability class and severity
  3. Findings Table — one row per CVE
  4. Evidence Details — files/functions for confirmed/likely findings
"""

from __future__ import annotations

import io
from datetime import datetime, timezone
from typing import Any, Dict, List

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    HRFlowable,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

# ── Colour palette (matches dashboard CSS variables) ─────────────────────────
_C_BG        = colors.HexColor("#0f1117")
_C_SURFACE   = colors.HexColor("#1a1d27")
_C_BORDER    = colors.HexColor("#2a2d3a")
_C_GREEN     = colors.HexColor("#00ff88")
_C_RED       = colors.HexColor("#ff4d6d")
_C_ORANGE    = colors.HexColor("#ff8c42")
_C_AMBER     = colors.HexColor("#ffd166")
_C_BLUE      = colors.HexColor("#4d9fff")
_C_MUTE      = colors.HexColor("#6b7280")
_C_TEXT      = colors.HexColor("#e2e8f0")
_C_WHITE     = colors.white
_C_LIGHT_ROW = colors.HexColor("#1e2130")

_SEV_COLOR = {
    "CRITICAL": _C_RED,
    "HIGH":     _C_ORANGE,
    "MEDIUM":   _C_AMBER,
    "LOW":      _C_MUTE,
}
_REACH_COLOR = {
    "DYNAMICALLY_REACHABLE": _C_RED,
    "STATICALLY_REACHABLE":  _C_ORANGE,
    "UNCERTAIN":             _C_AMBER,
    "NOT_REACHABLE":         _C_MUTE,
}

# ── Styles ────────────────────────────────────────────────────────────────────
_styles = getSampleStyleSheet()

def _style(name: str, **kwargs) -> ParagraphStyle:
    base = _styles["Normal"]
    return ParagraphStyle(name, parent=base, **kwargs)

_S_TITLE   = _style("vr_title",   fontSize=22, textColor=_C_TEXT,  leading=28, fontName="Helvetica-Bold")
_S_H2      = _style("vr_h2",      fontSize=13, textColor=_C_GREEN, leading=18, fontName="Helvetica-Bold", spaceAfter=4)
_S_BODY    = _style("vr_body",    fontSize=8,  textColor=_C_TEXT,  leading=11)
_S_MUTE    = _style("vr_mute",    fontSize=7,  textColor=_C_MUTE,  leading=10)
_S_CELL    = _style("vr_cell",    fontSize=7.5, textColor=_C_TEXT, leading=10)
_S_CELL_B  = _style("vr_cell_b",  fontSize=7.5, textColor=_C_TEXT, leading=10, fontName="Helvetica-Bold")
_S_MONO    = _style("vr_mono",    fontSize=6.5, textColor=_C_TEXT, leading=9,  fontName="Courier")
_S_SECTION = _style("vr_section", fontSize=8,  textColor=_C_MUTE, leading=10, fontName="Helvetica-Bold",
                    textTransform="uppercase", spaceBefore=6)


def build_pdf(scan_id: str, scan: Dict[str, Any]) -> io.BytesIO:
    """Build a PDF report for a scan and return it as a BytesIO buffer."""
    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf,
        pagesize=A4,
        leftMargin=15 * mm,
        rightMargin=15 * mm,
        topMargin=15 * mm,
        bottomMargin=15 * mm,
        title=f"VulnReach Report — {scan_id[:8]}",
    )

    # ── Pre-process data ─────────────────────────────────────────────────────
    meta        = scan.get("metadata") or {}
    repo        = meta.get("repo_path") or meta.get("repo_url") or "—"
    status      = (scan.get("status") or "—").upper()
    created_at  = scan.get("created_at")
    scan_date   = (
        created_at.strftime("%Y-%m-%d %H:%M UTC")
        if hasattr(created_at, "strftime")
        else str(created_at or "—")
    )

    # Build vuln map: cve_id → {package, severity, fix_version}
    vuln_map: Dict[str, Dict[str, Any]] = {}
    for v in (scan.get("vulnerabilities") or []):
        cve_list = v.get("cve_id") or []
        if isinstance(cve_list, str):
            cve_list = [cve_list]
        for cve in cve_list:
            if cve and cve not in vuln_map:
                vuln_map[cve] = {
                    "package":     v.get("package") or "—",
                    "severity":    (v.get("severity") or "—").upper(),
                    "fix_version": v.get("fix_version") or "—",
                }

    # Enrich correlation rows with package/severity/fix_version
    correlation = scan.get("correlation") or []
    enriched: List[Dict[str, Any]] = []
    for c in correlation:
        cve = c.get("cve_id") or ""
        v   = vuln_map.get(cve, {})
        ev  = c.get("evidence") or {}
        enriched.append({
            **c,
            "package":     c.get("package")  or v.get("package")     or "—",
            "severity":    c.get("severity") or v.get("severity")     or "—",
            "fix_version": v.get("fix_version") or "—",
            "reachability_class": c.get("reachability_class") or ev.get("reachability_class") or "—",
            "files":     (ev.get("files") or []),
            "function":  ev.get("function") or "",
        })

    # Summary counts
    reach_counts = {k: 0 for k in ("DYNAMICALLY_REACHABLE", "STATICALLY_REACHABLE", "UNCERTAIN", "NOT_REACHABLE")}
    sev_counts   = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    pkg_seen: set = set()
    for e in enriched:
        if e.get("finding_type") == "dast":
            continue
        rc = e.get("reachability_class", "")
        if rc in reach_counts:
            reach_counts[rc] += 1
        sev = e.get("severity", "")
        if sev in sev_counts:
            sev_counts[sev] += 1
        if e.get("package"):
            pkg_seen.add(e["package"])

    story = []

    # ── 1. Header ─────────────────────────────────────────────────────────────
    story.append(Paragraph("VulnReach Security Report", _S_TITLE))
    story.append(Spacer(1, 3 * mm))
    story.append(HRFlowable(width="100%", thickness=0.5, color=_C_GREEN, spaceAfter=4))

    hdr_data = [
        [Paragraph("Scan ID",     _S_MUTE), Paragraph(scan_id, _S_BODY)],
        [Paragraph("Repository",  _S_MUTE), Paragraph(_esc(repo), _S_BODY)],
        [Paragraph("Status",      _S_MUTE), Paragraph(status, _S_BODY)],
        [Paragraph("Generated",   _S_MUTE), Paragraph(scan_date, _S_BODY)],
        [Paragraph("Generated by",_S_MUTE), Paragraph("VulnReach v2", _S_BODY)],
    ]
    hdr_table = Table(hdr_data, colWidths=[30 * mm, None], hAlign="LEFT")
    hdr_table.setStyle(TableStyle([
        ("VALIGN",    (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING",  (0, 0), (-1, -1), 0),
        ("RIGHTPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING",(0, 0), (-1, -1), 2),
        ("TOPPADDING",   (0, 0), (-1, -1), 2),
    ]))
    story.append(hdr_table)
    story.append(Spacer(1, 5 * mm))

    # ── 2. Executive Summary ──────────────────────────────────────────────────
    story.append(Paragraph("Executive Summary", _S_H2))

    sum_data = [
        [Paragraph("Metric", _S_CELL_B),  Paragraph("Count", _S_CELL_B)],
        [Paragraph("Total affected packages", _S_CELL), Paragraph(str(len(pkg_seen)), _S_CELL_B)],
        [Paragraph("Dynamically Reachable", _S_CELL),   Paragraph(str(reach_counts["DYNAMICALLY_REACHABLE"]), _S_CELL_B)],
        [Paragraph("Statically Reachable",  _S_CELL),   Paragraph(str(reach_counts["STATICALLY_REACHABLE"]),  _S_CELL_B)],
        [Paragraph("Uncertain",             _S_CELL),   Paragraph(str(reach_counts["UNCERTAIN"]),             _S_CELL_B)],
        [Paragraph("Not Reachable",         _S_CELL),   Paragraph(str(reach_counts["NOT_REACHABLE"]),         _S_CELL_B)],
        [Paragraph("CRITICAL severity",     _S_CELL),   Paragraph(str(sev_counts["CRITICAL"]), _S_CELL_B)],
        [Paragraph("HIGH severity",         _S_CELL),   Paragraph(str(sev_counts["HIGH"]),     _S_CELL_B)],
    ]
    sum_table = Table(sum_data, colWidths=[80 * mm, 30 * mm], hAlign="LEFT")
    sum_table.setStyle(_base_table_style() + [
        ("BACKGROUND", (0, 0), (-1, 0), _C_SURFACE),
        ("TEXTCOLOR",  (0, 0), (-1, 0), _C_GREEN),
        ("BACKGROUND", (1, 2), (1, 2), _color_cell(_C_RED,    reach_counts["DYNAMICALLY_REACHABLE"])),
        ("BACKGROUND", (1, 3), (1, 3), _color_cell(_C_ORANGE, reach_counts["STATICALLY_REACHABLE"])),
        ("BACKGROUND", (1, 6), (1, 6), _color_cell(_C_RED,    sev_counts["CRITICAL"])),
        ("BACKGROUND", (1, 7), (1, 7), _color_cell(_C_ORANGE, sev_counts["HIGH"])),
    ])
    story.append(sum_table)
    story.append(Spacer(1, 5 * mm))

    # ── 3. Findings Table ─────────────────────────────────────────────────────
    story.append(Paragraph("Findings", _S_H2))

    col_w = [42*mm, 22*mm, 18*mm, 38*mm, 18*mm, 14*mm, 13*mm]
    find_hdr = [
        Paragraph("Package",      _S_CELL_B),
        Paragraph("CVE ID",       _S_CELL_B),
        Paragraph("Severity",     _S_CELL_B),
        Paragraph("Reachability", _S_CELL_B),
        Paragraph("Verdict",      _S_CELL_B),
        Paragraph("Priority",     _S_CELL_B),
        Paragraph("Risk",         _S_CELL_B),
    ]
    find_rows = [find_hdr]
    sev_row_styles = []
    reach_row_styles = []

    pkg_findings = [e for e in enriched if e.get("finding_type") != "dast"]
    # Sort: DYNAMICALLY_REACHABLE first, then by severity
    _tier = {"DYNAMICALLY_REACHABLE": 4, "STATICALLY_REACHABLE": 3, "UNCERTAIN": 2, "NOT_REACHABLE": 1}
    _srank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
    pkg_findings.sort(key=lambda e: (
        -_tier.get(e.get("reachability_class", ""), 0),
        -_srank.get(e.get("severity", ""), 0),
    ))

    for i, e in enumerate(pkg_findings, start=1):
        sev = e.get("severity", "—")
        rc  = e.get("reachability_class", "—")
        risk = e.get("risk_score")
        find_rows.append([
            Paragraph(_esc(e.get("package") or "—"), _S_CELL),
            Paragraph(_esc(e.get("cve_id")   or "—"), _S_MONO),
            Paragraph(sev,  _S_CELL_B),
            Paragraph(_fmt_reach(rc), _S_CELL),
            Paragraph(_esc(e.get("verdict") or "—"), _S_CELL),
            Paragraph(_esc(e.get("priority") or "—"), _S_CELL),
            Paragraph(f"{risk:.1f}" if isinstance(risk, float) else "—", _S_CELL),
        ])
        row_idx = i  # header is row 0
        if sev in _SEV_COLOR:
            sev_row_styles.append(("BACKGROUND", (2, row_idx), (2, row_idx), _SEV_COLOR[sev]))
        if rc in _REACH_COLOR:
            reach_row_styles.append(("BACKGROUND", (3, row_idx), (3, row_idx), _REACH_COLOR[rc]))

    find_table = Table(find_rows, colWidths=col_w, repeatRows=1)
    find_table.setStyle(_base_table_style() + [
        ("BACKGROUND", (0, 0), (-1, 0), _C_SURFACE),
        ("TEXTCOLOR",  (0, 0), (-1, 0), _C_GREEN),
    ] + sev_row_styles + reach_row_styles)
    story.append(find_table)
    story.append(Spacer(1, 5 * mm))

    # ── 4. Evidence Details ───────────────────────────────────────────────────
    actionable = [
        e for e in enriched
        if e.get("reachability_class") in ("DYNAMICALLY_REACHABLE", "STATICALLY_REACHABLE")
        and e.get("finding_type") != "dast"
    ]
    if actionable:
        story.append(Paragraph("Evidence Details", _S_H2))
        story.append(Paragraph(
            "Confirmed and statically-reachable findings with file/function evidence.",
            _S_MUTE,
        ))
        story.append(Spacer(1, 2 * mm))

        for e in actionable:
            pkg  = e.get("package") or "—"
            cve  = e.get("cve_id")  or "—"
            rc   = e.get("reachability_class", "")
            sev  = e.get("severity", "—")
            fix  = e.get("fix_version") or "no fix available"
            files = e.get("files") or []
            fn    = e.get("function") or ""

            rc_color = _REACH_COLOR.get(rc, _C_MUTE)
            ev = e.get("evidence") or {}

            detail_data = [
                [
                    Paragraph(f"{pkg}  <font color='#{_hex(rc_color)}'>{_fmt_reach(rc)}</font>", _S_CELL_B),
                    Paragraph(f"CVE: {cve}  ·  {sev}  ·  Fix: {fix}", _S_MUTE),
                ],
            ]
            if fn:
                detail_data.append([
                    Paragraph("Function", _S_SECTION),
                    Paragraph(_esc(fn), _S_MONO),
                ])
            if files:
                detail_data.append([
                    Paragraph("Files", _S_SECTION),
                    Paragraph("<br/>".join(_esc(f) for f in files[:6]), _S_MONO),
                ])
            # Evidence chain flags
            flags = []
            if ev.get("import_detected"):
                flags.append("import ✓")
            if ev.get("call_chain_exists"):
                flags.append("call-chain ✓")
            if ev.get("sink_reachable"):
                flags.append("sink ✓")
            if ev.get("has_coverage_hit"):
                flags.append("coverage ✓")
            if flags:
                detail_data.append([
                    Paragraph("Evidence", _S_SECTION),
                    Paragraph("  ·  ".join(flags), _S_CELL),
                ])

            d_table = Table(detail_data, colWidths=[32 * mm, None])
            d_table.setStyle(TableStyle([
                ("BACKGROUND",   (0, 0), (-1, -1), _C_LIGHT_ROW),
                ("BOX",          (0, 0), (-1, -1), 0.5, _C_BORDER),
                ("VALIGN",       (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING",  (0, 0), (-1, -1), 6),
                ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                ("TOPPADDING",   (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING",(0, 0), (-1, -1), 4),
                ("LINEABOVE",    (0, 0), (-1, 0), 1.5, rc_color),
            ]))
            story.append(d_table)
            story.append(Spacer(1, 2 * mm))

    # ── Footer ────────────────────────────────────────────────────────────────
    story.append(Spacer(1, 4 * mm))
    story.append(HRFlowable(width="100%", thickness=0.5, color=_C_BORDER))
    story.append(Spacer(1, 2 * mm))
    story.append(Paragraph(
        f"Generated by VulnReach v2 · {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
        _S_MUTE,
    ))

    doc.build(story)
    buf.seek(0)
    return buf


# ── Helpers ───────────────────────────────────────────────────────────────────

def _base_table_style() -> list:
    return [
        ("FONTSIZE",     (0, 0), (-1, -1), 7.5),
        ("ROWBACKGROUNDS",(0, 1), (-1, -1), [_C_BG, _C_LIGHT_ROW]),
        ("GRID",         (0, 0), (-1, -1), 0.25, _C_BORDER),
        ("VALIGN",       (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING",  (0, 0), (-1, -1), 5),
        ("RIGHTPADDING", (0, 0), (-1, -1), 5),
        ("TOPPADDING",   (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING",(0, 0), (-1, -1), 4),
    ]


def _color_cell(color: colors.Color, value: int) -> colors.Color:
    """Return the color only if the value is non-zero, else surface."""
    return color if value > 0 else _C_SURFACE


def _fmt_reach(rc: str) -> str:
    labels = {
        "DYNAMICALLY_REACHABLE": "Dynamic",
        "STATICALLY_REACHABLE":  "Static",
        "UNCERTAIN":             "Uncertain",
        "NOT_REACHABLE":         "Not Reachable",
    }
    return labels.get(rc, rc)


def _esc(text: str) -> str:
    """Escape special XML/reportlab characters."""
    return (
        str(text)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )


def _hex(color: colors.Color) -> str:
    """Convert a reportlab color to a 6-digit hex string (no #)."""
    r, g, b = int(color.red * 255), int(color.green * 255), int(color.blue * 255)
    return f"{r:02x}{g:02x}{b:02x}"
