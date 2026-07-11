"""
aml_pdf.py — SLA Report PDF Export
Renders the same data aml_reports.build_sla_report() produces as a
formatted PDF, for the "Export PDF" button on /reports. Deliberately
takes the report dict as input rather than a db connection — this module
has no SQL of its own and stays a pure rendering layer, consistent with
aml_service.py owning all DB access and aml_reports.py owning all
aggregate queries. If build_sla_report()'s shape ever changes, only this
file's render_sla_report_pdf() needs to follow.
"""
import io
from datetime import datetime, timezone

from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.units import inch
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable,
)


def _fmt_days(value):
    """None-safe day formatter — avg_time_to_* / rate fields are None
    when there's no closed-alert data yet (see aml_reports.py docstrings),
    and that should render as an explicit em dash, not '0.00' (which
    would misleadingly imply zero elapsed time rather than no data)."""
    return f"{value:.2f} days" if value is not None else "—"


def _fmt_pct(value):
    return f"{value:.1f}%" if value is not None else "—"


def render_sla_report_pdf(report: dict) -> bytes:
    """Builds the SLA Report PDF in-memory and returns the raw bytes —
    the Flask route wraps this directly in a Response rather than this
    module touching the filesystem, since it has no reason to know about
    /mnt/user-data or any particular output path; that's a Flask-layer
    concern, not a rendering concern."""
    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=letter,
        topMargin=0.6 * inch, bottomMargin=0.6 * inch,
        leftMargin=0.6 * inch, rightMargin=0.6 * inch,
    )
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        "ReportTitle", parent=styles["Title"], fontSize=18, spaceAfter=2,
    )
    subtitle_style = ParagraphStyle(
        "ReportSubtitle", parent=styles["Normal"], fontSize=9,
        textColor=colors.HexColor("#555555"), spaceAfter=18,
    )
    section_style = ParagraphStyle(
        "Section", parent=styles["Heading2"], fontSize=13,
        spaceBefore=16, spaceAfter=8, textColor=colors.HexColor("#1a1a1a"),
    )
    note_style = ParagraphStyle(
        "Note", parent=styles["Normal"], fontSize=8,
        textColor=colors.HexColor("#666666"), spaceBefore=6,
    )

    story = []

    # Header
    story.append(Paragraph("AML Monitoring — SLA &amp; Compliance Report", title_style))
    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    story.append(Paragraph(
        f"Generated {generated_at}",
        subtitle_style,
    ))
    story.append(HRFlowable(width="100%", thickness=0.75, color=colors.HexColor("#cccccc")))

    # Alert volume summary
    summary = report.get("summary") or {}
    story.append(Paragraph("Alert Volume Summary", section_style))
    summary_rows = [
        ["Status", "Count"],
        ["Open", str(summary.get("open_count") or 0)],
        ["Under Review", str(summary.get("under_review_count") or 0)],
        ["Escalated", str(summary.get("escalated_count") or 0)],
        ["Closed — SAR Filed", str(summary.get("closed_sar_count") or 0)],
        ["Closed — No Action", str(summary.get("closed_no_action_count") or 0)],
        ["Total", str(summary.get("total") or 0)],
    ]
    summary_table = Table(summary_rows, colWidths=[3.2 * inch, 1.5 * inch])
    summary_table.setStyle(_table_style(header_rows=1, bold_last_row=True))
    story.append(summary_table)

    # SLA timing metrics
    story.append(Paragraph("SLA Timing", section_style))
    timing_rows = [
        ["Metric", "Value"],
        ["Avg. time to first review (created \u2192 reviewed)", _fmt_days(report.get("avg_time_to_review_days"))],
        ["Avg. time to closure (created \u2192 closed)", _fmt_days(report.get("avg_time_to_close_days"))],
    ]
    timing_table = Table(timing_rows, colWidths=[3.8 * inch, 1.7 * inch])
    timing_table.setStyle(_table_style(header_rows=1))
    story.append(timing_table)
    story.append(Paragraph(
        "Time-to-review and time-to-close are calculated from the latest "
        "decision record per alert (created_at \u2192 reviewed_at / closed_at "
        "in str_decisions). \u2014 indicates no qualifying alerts yet.",
        note_style,
    ))

    # Disposition rates
    story.append(Paragraph("Disposition Rates (of closed alerts)", section_style))
    rate_rows = [
        ["Metric", "Value"],
        ["False positive rate", _fmt_pct(report.get("false_positive_rate_pct"))],
        ["SAR filing rate", _fmt_pct(report.get("sar_rate_pct"))],
    ]
    rate_table = Table(rate_rows, colWidths=[3.8 * inch, 1.7 * inch])
    rate_table.setStyle(_table_style(header_rows=1))
    story.append(rate_table)

    # Alerts by scenario
    story.append(Paragraph("Alerts by Scenario", section_style))
    by_scenario = report.get("alerts_by_scenario") or []
    if by_scenario:
        scenario_rows = [["Scenario", "Total", "Open*", "Closed"]]
        for row in by_scenario:
            scenario_rows.append([
                Paragraph(
                    f"<b>{row.get('scenario_code', '')}</b><br/>"
                    f"<font size=8 color='#666666'>{row.get('scenario_description', '')}</font>",
                    styles["Normal"],
                ),
                str(row.get("total_alerts") or 0),
                str(row.get("open_count") or 0),
                str(row.get("closed_count") or 0),
            ])
        scenario_table = Table(
            scenario_rows,
            colWidths=[3.4 * inch, 0.7 * inch, 0.7 * inch, 0.7 * inch],
            repeatRows=1,
        )
        scenario_table.setStyle(_table_style(header_rows=1))
        story.append(scenario_table)
        story.append(Paragraph(
            "*Open includes OPEN, UNDER_REVIEW, and ESCALATED (any non-terminal status).",
            note_style,
        ))
    else:
        story.append(Paragraph("No alerts have been raised yet.", styles["Normal"]))

    # Oldest open alert
    story.append(Paragraph("Oldest Still-Open Alert", section_style))
    oldest = report.get("oldest_open_alert")
    if oldest:
        oldest_rows = [
            ["Alert ID", oldest.get("alert_id", "")],
            ["Scenario", oldest.get("scenario_code", "")],
            ["Severity", oldest.get("severity", "")],
            ["Account", oldest.get("account_id", "")],
            ["Status", oldest.get("status", "")],
            ["Created", (oldest.get("created_at") or "")[:19].replace("T", " ")],
            ["Case Reference", (oldest.get("case_id") or "—")],
        ]
        oldest_table = Table(oldest_rows, colWidths=[1.3 * inch, 4.2 * inch])
        oldest_table.setStyle(_table_style(header_rows=0, label_col=True))
        story.append(oldest_table)
    else:
        story.append(Paragraph("Nothing waiting — every alert is closed.", styles["Normal"]))

    doc.build(story)
    return buf.getvalue()


def _table_style(header_rows: int = 1, bold_last_row: bool = False, label_col: bool = False) -> TableStyle:
    """Shared table styling so every section looks consistent without
    repeating the same style block six times."""
    cmds = [
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#dddddd")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ]
    if header_rows:
        cmds += [
            ("BACKGROUND", (0, 0), (-1, header_rows - 1), colors.HexColor("#24292e")),
            ("TEXTCOLOR", (0, 0), (-1, header_rows - 1), colors.white),
            ("FONTNAME", (0, 0), (-1, header_rows - 1), "Helvetica-Bold"),
        ]
    if bold_last_row:
        cmds += [
            ("FONTNAME", (0, -1), (-1, -1), "Helvetica-Bold"),
            ("BACKGROUND", (0, -1), (-1, -1), colors.HexColor("#f0f0f0")),
        ]
    if label_col:
        cmds += [("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold")]
    return TableStyle(cmds)