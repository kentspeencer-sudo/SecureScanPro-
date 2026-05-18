"""Server-side PDF Report Generator with Whitelabel Support."""

from __future__ import annotations

import io
import math
from datetime import datetime, timezone
from typing import Any

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch, mm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    PageBreak, HRFlowable, Image,
)
from reportlab.graphics.shapes import Drawing, Rect, String, Circle, Wedge
from reportlab.graphics.charts.barcharts import VerticalBarChart
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT


BRAND_PRIMARY = colors.HexColor("#3b82f6")
BRAND_SECONDARY = colors.HexColor("#6366f1")
BRAND_DARK = colors.HexColor("#0f172a")
BRAND_LIGHT = colors.HexColor("#f8fafc")
SEVERITY_COLORS = {
    "critical": colors.HexColor("#dc2626"),
    "high": colors.HexColor("#ef4444"),
    "medium": colors.HexColor("#f59e0b"),
    "low": colors.HexColor("#6366f1"),
    "info": colors.HexColor("#64748b"),
}


def _severity_order(s: str) -> int:
    return {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(s, 5)


def _get_grade_color(grade: str) -> colors.Color:
    return {
        "A+": colors.HexColor("#10b981"), "A": colors.HexColor("#10b981"),
        "B": colors.HexColor("#3b82f6"), "C": colors.HexColor("#f59e0b"),
        "D": colors.HexColor("#ef4444"), "F": colors.HexColor("#dc2626"),
    }.get(grade, colors.HexColor("#64748b"))


def _build_styles(brand_color: colors.Color | None = None):
    ss = getSampleStyleSheet()
    primary = brand_color or BRAND_PRIMARY

    styles = {
        "title": ParagraphStyle("RPTitle", parent=ss["Title"], fontSize=28, textColor=primary, spaceAfter=6, fontName="Helvetica-Bold"),
        "subtitle": ParagraphStyle("RPSubtitle", parent=ss["Normal"], fontSize=12, textColor=colors.HexColor("#64748b"), spaceAfter=20),
        "h1": ParagraphStyle("RPH1", parent=ss["Heading1"], fontSize=20, textColor=BRAND_DARK, spaceAfter=10, spaceBefore=20, fontName="Helvetica-Bold"),
        "h2": ParagraphStyle("RPH2", parent=ss["Heading2"], fontSize=16, textColor=BRAND_DARK, spaceAfter=8, spaceBefore=14, fontName="Helvetica-Bold"),
        "h3": ParagraphStyle("RPH3", parent=ss["Heading3"], fontSize=13, textColor=BRAND_DARK, spaceAfter=6, spaceBefore=10, fontName="Helvetica-Bold"),
        "body": ParagraphStyle("RPBody", parent=ss["Normal"], fontSize=10, textColor=colors.HexColor("#334155"), leading=14),
        "body_small": ParagraphStyle("RPBodySm", parent=ss["Normal"], fontSize=9, textColor=colors.HexColor("#64748b"), leading=12),
        "center": ParagraphStyle("RPCenter", parent=ss["Normal"], fontSize=10, alignment=TA_CENTER, textColor=colors.HexColor("#334155")),
        "severity_critical": ParagraphStyle("SevCrit", parent=ss["Normal"], fontSize=9, textColor=SEVERITY_COLORS["critical"], fontName="Helvetica-Bold"),
        "severity_high": ParagraphStyle("SevHigh", parent=ss["Normal"], fontSize=9, textColor=SEVERITY_COLORS["high"], fontName="Helvetica-Bold"),
        "severity_medium": ParagraphStyle("SevMed", parent=ss["Normal"], fontSize=9, textColor=SEVERITY_COLORS["medium"], fontName="Helvetica-Bold"),
        "severity_low": ParagraphStyle("SevLow", parent=ss["Normal"], fontSize=9, textColor=SEVERITY_COLORS["low"], fontName="Helvetica-Bold"),
        "severity_info": ParagraphStyle("SevInfo", parent=ss["Normal"], fontSize=9, textColor=SEVERITY_COLORS["info"], fontName="Helvetica-Bold"),
    }
    return styles


def _draw_risk_matrix(issues: list[dict]) -> Drawing:
    d = Drawing(400, 200)
    d.add(Rect(0, 0, 400, 200, fillColor=colors.HexColor("#f8fafc"), strokeColor=colors.HexColor("#e2e8f0"), strokeWidth=1))
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for i in issues:
        sev = (i.get("severity") or "info").lower()
        counts[sev] = counts.get(sev, 0) + 1

    labels = ["Critical", "High", "Medium", "Low", "Info"]
    keys = ["critical", "high", "medium", "low", "info"]
    bar_colors = [SEVERITY_COLORS[k] for k in keys]
    max_val = max(counts.values(), default=1) or 1
    bar_width = 50
    gap = 22
    start_x = 40

    for idx, key in enumerate(keys):
        x = start_x + idx * (bar_width + gap)
        val = counts[key]
        bar_h = max(5, (val / max_val) * 140)
        d.add(Rect(x, 30, bar_width, bar_h, fillColor=bar_colors[idx], strokeColor=None, rx=4))
        d.add(String(x + bar_width / 2, 30 + bar_h + 5, str(val), fontSize=11, fontName="Helvetica-Bold", fillColor=BRAND_DARK, textAnchor="middle"))
        d.add(String(x + bar_width / 2, 12, labels[idx], fontSize=8, fontName="Helvetica", fillColor=colors.HexColor("#64748b"), textAnchor="middle"))

    return d


def _draw_compliance_gauge(label: str, pct: float, x_off: int = 0) -> Drawing:
    d = Drawing(120, 100)
    cx, cy, r = 60, 55, 40
    color = colors.HexColor("#10b981") if pct >= 70 else colors.HexColor("#f59e0b") if pct >= 40 else colors.HexColor("#ef4444")
    d.add(Circle(cx, cy, r, fillColor=colors.HexColor("#f1f5f9"), strokeColor=colors.HexColor("#e2e8f0"), strokeWidth=2))
    if pct > 0:
        d.add(Wedge(cx, cy, r, 90, 90 - pct * 3.6, fillColor=color, strokeColor=None))
    d.add(Circle(cx, cy, r - 12, fillColor=colors.white, strokeColor=None))
    d.add(String(cx, cy - 5, f"{int(pct)}%", fontSize=14, fontName="Helvetica-Bold", fillColor=BRAND_DARK, textAnchor="middle"))
    d.add(String(cx, 5, label, fontSize=8, fontName="Helvetica", fillColor=colors.HexColor("#64748b"), textAnchor="middle"))
    return d


def generate_pdf_report(
    scan_data: dict[str, Any],
    whitelabel: dict[str, Any] | None = None,
    include_executive_summary: bool = True,
    language: str = "en",
) -> bytes:
    """Generate a professional PDF report.

    Args:
        scan_data: Full scan results dict (url, grade, issues, modules, etc.)
        whitelabel: Optional branding dict with keys:
            - company_name: str
            - logo_path: str (path to logo image file)
            - primary_color: str (hex color like "#ff0000")
            - tagline: str
            - contact_email: str
            - website: str
        include_executive_summary: Whether to include exec summary page
        language: Language code (en, ur, ar, es)
    """
    buf = io.BytesIO()
    brand_color = None
    company = "SecureScan Pro"
    tagline = "Enterprise Security Platform"
    contact_email = "support@securescanpro.com"

    if whitelabel:
        company = whitelabel.get("company_name", company)
        tagline = whitelabel.get("tagline", tagline)
        contact_email = whitelabel.get("contact_email", contact_email)
        if whitelabel.get("primary_color"):
            try:
                brand_color = colors.HexColor(whitelabel["primary_color"])
            except Exception:
                pass

    styles = _build_styles(brand_color)
    primary = brand_color or BRAND_PRIMARY

    doc = SimpleDocTemplate(
        buf, pagesize=A4,
        rightMargin=50, leftMargin=50,
        topMargin=60, bottomMargin=50,
        title=f"Security Report - {scan_data.get('url', 'Unknown')}",
        author=company,
    )

    story: list[Any] = []
    url = scan_data.get("url", "Unknown")
    grade = scan_data.get("grade", "?")
    issues = scan_data.get("issues", [])
    issues_sorted = sorted(issues, key=lambda i: _severity_order(i.get("severity", "info")))
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    # --- Cover Page ---
    story.append(Spacer(1, 80))
    story.append(Paragraph(company, styles["title"]))
    story.append(Paragraph(tagline, styles["subtitle"]))
    story.append(HRFlowable(width="100%", thickness=2, color=primary, spaceAfter=20))
    story.append(Spacer(1, 30))
    story.append(Paragraph("Web Security Assessment Report", ParagraphStyle("Cover", fontSize=22, textColor=BRAND_DARK, fontName="Helvetica-Bold", alignment=TA_CENTER)))
    story.append(Spacer(1, 20))

    cover_data = [
        ["Target URL:", url],
        ["Security Grade:", grade],
        ["Total Issues:", str(len(issues))],
        ["Report Date:", now],
        ["Generated By:", company],
    ]
    cover_table = Table(cover_data, colWidths=[120, 350])
    cover_table.setStyle(TableStyle([
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 11),
        ("TEXTCOLOR", (0, 0), (0, -1), colors.HexColor("#64748b")),
        ("TEXTCOLOR", (1, 0), (1, -1), BRAND_DARK),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
        ("TOPPADDING", (0, 0), (-1, -1), 8),
    ]))
    story.append(cover_table)
    story.append(Spacer(1, 40))

    sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for i in issues:
        s = (i.get("severity") or "info").lower()
        sev_counts[s] = sev_counts.get(s, 0) + 1

    sev_summary = Table(
        [["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
         [str(sev_counts["critical"]), str(sev_counts["high"]), str(sev_counts["medium"]), str(sev_counts["low"]), str(sev_counts["info"])]],
        colWidths=[90] * 5,
    )
    sev_summary.setStyle(TableStyle([
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, 0), 9),
        ("FONTSIZE", (0, 1), (-1, 1), 18),
        ("FONTNAME", (0, 1), (-1, 1), "Helvetica-Bold"),
        ("TEXTCOLOR", (0, 0), (0, -1), SEVERITY_COLORS["critical"]),
        ("TEXTCOLOR", (1, 0), (1, -1), SEVERITY_COLORS["high"]),
        ("TEXTCOLOR", (2, 0), (2, -1), SEVERITY_COLORS["medium"]),
        ("TEXTCOLOR", (3, 0), (3, -1), SEVERITY_COLORS["low"]),
        ("TEXTCOLOR", (4, 0), (4, -1), SEVERITY_COLORS["info"]),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
    ]))
    story.append(sev_summary)

    if not (whitelabel and whitelabel.get("company_name")):
        story.append(Spacer(1, 30))
        story.append(Paragraph(
            '<font color="#94a3b8" size="9">Generated by SecureScan Pro — Free Plan</font>',
            ParagraphStyle("Watermark", alignment=TA_CENTER, fontSize=9)
        ))

    story.append(PageBreak())

    # --- Executive Summary ---
    if include_executive_summary:
        story.append(Paragraph("Executive Summary", styles["h1"]))
        story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#e2e8f0"), spaceAfter=12))

        grade_color = _get_grade_color(grade)
        risk_level = "Critical" if grade in ("D", "F") else "High" if grade == "C" else "Moderate" if grade == "B" else "Low"

        exec_text = (
            f"A comprehensive security assessment was performed on <b>{url}</b> on {now}. "
            f"The target received an overall security grade of <b><font color='{grade_color.hexval()}'>{grade}</font></b>, "
            f"indicating a <b>{risk_level}</b> risk level. "
            f"A total of <b>{len(issues)}</b> security findings were identified across multiple scanning modules."
        )
        story.append(Paragraph(exec_text, styles["body"]))
        story.append(Spacer(1, 12))

        if sev_counts["critical"] > 0:
            story.append(Paragraph(
                f'<font color="{SEVERITY_COLORS["critical"].hexval()}"><b>IMMEDIATE ACTION REQUIRED:</b></font> '
                f'{sev_counts["critical"]} critical vulnerabilit{"y" if sev_counts["critical"] == 1 else "ies"} detected that require urgent remediation.',
                styles["body"]
            ))
            story.append(Spacer(1, 8))

        story.append(Paragraph("Key Findings:", styles["h3"]))
        for i in issues_sorted[:5]:
            sev = (i.get("severity") or "info").upper()
            sev_style = styles.get(f"severity_{sev.lower()}", styles["body_small"])
            story.append(Paragraph(f'<b>[{sev}]</b> {i.get("title", "Unknown")}', sev_style))

        if len(issues) > 5:
            story.append(Paragraph(f'...and {len(issues) - 5} more findings (see Detailed Findings section)', styles["body_small"]))

        story.append(Spacer(1, 16))

        # Risk Matrix
        story.append(Paragraph("Risk Distribution", styles["h2"]))
        story.append(_draw_risk_matrix(issues))
        story.append(Spacer(1, 12))

        # Compliance gauges
        compliance = scan_data.get("compliance", {})
        owasp_pct = compliance.get("owasp_coverage", 0)
        pci_pct = compliance.get("pci_coverage", 0)
        if owasp_pct or pci_pct:
            story.append(Paragraph("Compliance Status", styles["h2"]))
            gauge_data = []
            if owasp_pct:
                gauge_data.append(_draw_compliance_gauge("OWASP Top 10", owasp_pct))
            if pci_pct:
                gauge_data.append(_draw_compliance_gauge("PCI DSS", pci_pct))
            if gauge_data:
                gt = Table([gauge_data], colWidths=[140] * len(gauge_data))
                gt.setStyle(TableStyle([("ALIGN", (0, 0), (-1, -1), "CENTER")]))
                story.append(gt)

        story.append(PageBreak())

    # --- Remediation Priority List ---
    story.append(Paragraph("Remediation Priority List", styles["h1"]))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#e2e8f0"), spaceAfter=12))
    story.append(Paragraph("Issues sorted by severity (CVSS score where available). Address critical and high severity items first.", styles["body_small"]))
    story.append(Spacer(1, 10))

    if issues_sorted:
        rem_header = ["#", "Severity", "Finding", "CVSS", "Recommendation"]
        rem_data = [rem_header]
        for idx, issue in enumerate(issues_sorted[:30], 1):
            sev = (issue.get("severity") or "info").upper()
            cvss = issue.get("cvss_score", "-")
            if isinstance(cvss, (int, float)):
                cvss = f"{cvss:.1f}"
            title = issue.get("title", "Unknown")
            if len(title) > 50:
                title = title[:47] + "..."
            rec = issue.get("recommendation", "-")
            if len(rec) > 60:
                rec = rec[:57] + "..."
            rem_data.append([str(idx), sev, title, str(cvss), rec])

        rem_table = Table(rem_data, colWidths=[25, 55, 160, 40, 200])
        style_cmds = [
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, 0), 8),
            ("FONTSIZE", (0, 1), (-1, -1), 8),
            ("BACKGROUND", (0, 0), (-1, 0), BRAND_DARK),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("WORDWRAP", (2, 1), (2, -1), True),
            ("WORDWRAP", (4, 1), (4, -1), True),
        ]
        for row_idx, issue in enumerate(issues_sorted[:30], 1):
            sev = (issue.get("severity") or "info").lower()
            sev_color = SEVERITY_COLORS.get(sev, SEVERITY_COLORS["info"])
            style_cmds.append(("TEXTCOLOR", (1, row_idx), (1, row_idx), sev_color))
            style_cmds.append(("FONTNAME", (1, row_idx), (1, row_idx), "Helvetica-Bold"))
            if row_idx % 2 == 0:
                style_cmds.append(("BACKGROUND", (0, row_idx), (-1, row_idx), colors.HexColor("#f8fafc")))

        rem_table.setStyle(TableStyle(style_cmds))
        story.append(rem_table)
    else:
        story.append(Paragraph("No issues found. The target appears to be well-configured.", styles["body"]))

    story.append(PageBreak())

    # --- Detailed Findings ---
    story.append(Paragraph("Detailed Findings", styles["h1"]))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#e2e8f0"), spaceAfter=12))

    for idx, issue in enumerate(issues_sorted, 1):
        sev = (issue.get("severity") or "info").upper()
        sev_color = SEVERITY_COLORS.get(sev.lower(), SEVERITY_COLORS["info"])

        story.append(Paragraph(f'{idx}. [{sev}] {issue.get("title", "Unknown")}', styles["h3"]))
        if issue.get("description"):
            story.append(Paragraph(f'<b>Description:</b> {issue["description"]}', styles["body"]))
        if issue.get("category"):
            story.append(Paragraph(f'<b>Category:</b> {issue["category"]}', styles["body_small"]))
        cvss = issue.get("cvss_score")
        if cvss and cvss != "-":
            story.append(Paragraph(f'<b>CVSS Score:</b> <font color="{sev_color.hexval()}">{cvss}</font>', styles["body"]))
        if issue.get("recommendation"):
            story.append(Paragraph(f'<b>Remediation:</b> {issue["recommendation"]}', styles["body"]))
        if issue.get("fix_code"):
            story.append(Spacer(1, 4))
            code_style = ParagraphStyle("Code", fontSize=8, fontName="Courier", textColor=colors.HexColor("#334155"),
                                        backColor=colors.HexColor("#f1f5f9"), borderPadding=6, leading=11)
            code = issue["fix_code"].replace("<", "&lt;").replace(">", "&gt;")
            story.append(Paragraph(code, code_style))
        story.append(Spacer(1, 8))

    # --- Footer info ---
    story.append(Spacer(1, 20))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#e2e8f0"), spaceAfter=12))
    story.append(Paragraph(f"Report generated by {company} | {contact_email}", styles["body_small"]))
    story.append(Paragraph(f"This report is confidential. Distribution without authorization is prohibited.", styles["body_small"]))

    doc.build(story)
    return buf.getvalue()


# i18n labels
TRANSLATIONS = {
    "en": {
        "title": "Web Security Assessment Report",
        "exec_summary": "Executive Summary",
        "risk_dist": "Risk Distribution",
        "compliance": "Compliance Status",
        "remediation": "Remediation Priority List",
        "detailed": "Detailed Findings",
        "generated_by": "Generated by",
        "confidential": "This report is confidential.",
        "grade": "Security Grade",
        "issues": "Total Issues",
        "date": "Report Date",
        "target": "Target URL",
        "critical": "CRITICAL",
        "high": "HIGH",
        "medium": "MEDIUM",
        "low": "LOW",
        "info": "INFO",
    },
    "ur": {
        "title": "ویب سیکیورٹی تشخیصی رپورٹ",
        "exec_summary": "ایگزیکٹو سمری",
        "risk_dist": "خطرے کی تقسیم",
        "compliance": "تعمیل کی حیثیت",
        "remediation": "اصلاحی ترجیحی فہرست",
        "detailed": "تفصیلی نتائج",
        "generated_by": "تیار کردہ",
        "confidential": "یہ رپورٹ خفیہ ہے۔",
        "grade": "سیکیورٹی درجہ",
        "issues": "کل مسائل",
        "date": "رپورٹ کی تاریخ",
        "target": "ہدف URL",
        "critical": "سنگین",
        "high": "بلند",
        "medium": "درمیانی",
        "low": "کم",
        "info": "معلومات",
    },
    "ar": {
        "title": "تقرير تقييم أمان الويب",
        "exec_summary": "الملخص التنفيذي",
        "risk_dist": "توزيع المخاطر",
        "compliance": "حالة الامتثال",
        "remediation": "قائمة أولويات المعالجة",
        "detailed": "النتائج التفصيلية",
        "generated_by": "تم الإنشاء بواسطة",
        "confidential": "هذا التقرير سري.",
        "grade": "درجة الأمان",
        "issues": "إجمالي المشاكل",
        "date": "تاريخ التقرير",
        "target": "عنوان URL الهدف",
        "critical": "حرج",
        "high": "عالي",
        "medium": "متوسط",
        "low": "منخفض",
        "info": "معلومات",
    },
    "es": {
        "title": "Informe de Evaluación de Seguridad Web",
        "exec_summary": "Resumen Ejecutivo",
        "risk_dist": "Distribución de Riesgos",
        "compliance": "Estado de Cumplimiento",
        "remediation": "Lista de Prioridad de Remediación",
        "detailed": "Hallazgos Detallados",
        "generated_by": "Generado por",
        "confidential": "Este informe es confidencial.",
        "grade": "Calificación de Seguridad",
        "issues": "Problemas Totales",
        "date": "Fecha del Informe",
        "target": "URL Objetivo",
        "critical": "CRÍTICO",
        "high": "ALTO",
        "medium": "MEDIO",
        "low": "BAJO",
        "info": "INFO",
    },
}
