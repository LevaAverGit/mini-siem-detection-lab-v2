from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:  # keep openpyxl out of the import path for the md/json callers
    from openpyxl.workbook.workbook import Workbook


def generate_markdown_report(
    incident: dict, alerts: list[dict]
) -> str:
    inc_id = incident.get("incident_id", "UNKNOWN")
    title = incident.get("title", "Untitled")
    severity = incident.get("severity", "unknown").upper()
    score = incident.get("score", 0)
    summary = incident.get("summary", "")
    status = incident.get("status", "open")
    created = incident.get("created_at", "")
    entities = incident.get("involved_entities", {})
    ips = entities.get("source_ips", [])
    users = entities.get("usernames", [])
    hosts = entities.get("hosts", [])
    timeline = incident.get("timeline", [])
    actions = incident.get("recommended_actions", [])
    analyst_notes = incident.get("analyst_notes") or ""

    lines = [
        f"# Incident Report: {inc_id}",
        "",
        f"**Title:** {title}",
        f"**Status:** {status}",
        f"**Created:** {created}",
        "",
        "---",
        "",
        "## Executive Summary",
        "",
        summary,
        "",
        "---",
        "",
        "## Severity and Score",
        "",
        "| Severity | Score |",
        "|---|---|",
        f"| {severity} | {score}/100 |",
        "",
        "---",
        "",
        "## Involved Entities",
        "",
        f"**Source IPs:** {', '.join(ips) if ips else 'none'}",
        f"**Usernames:** {', '.join(users) if users else 'none'}",
        f"**Hosts:** {', '.join(hosts) if hosts else 'none'}",
        "",
        "---",
        "",
        "## Timeline",
        "",
    ]

    if timeline:
        lines.append("| Timestamp | Description |")
        lines.append("|---|---|")
        for entry in timeline[:20]:
            ts = entry.get("timestamp", "")[:19] if entry.get("timestamp") else ""
            desc = entry.get("description", "")[:100]
            lines.append(f"| {ts} | {desc} |")
    else:
        lines.append("No timeline events recorded.")
    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("## Alerts")
    lines.append("")

    for alert in alerts:
        lines.append(f"### {alert.get('title', 'Alert')}")
        lines.append(f"- **Rule:** `{alert.get('rule_id', '')}` — {alert.get('rule_name', '')}")
        lines.append(f"- **Severity:** {alert.get('severity', '').upper()}")
        lines.append(f"- **Score:** {alert.get('score', 0)}")
        lines.append(f"- **Status:** {alert.get('status', 'new')}")
        lines.append(f"- **Description:** {alert.get('description', '')}")
        tactic = alert.get("mitre_tactic")
        technique_id = alert.get("mitre_technique_id")
        technique_name = alert.get("mitre_technique_name")
        confidence = alert.get("mitre_mapping_confidence")
        if tactic and technique_id:
            lines.append("- **MITRE ATT&CK:**")
            lines.append(f"  - Tactic: {tactic}")
            lines.append(f"  - Technique: {technique_id} — {technique_name}")
            lines.append(f"  - Mapping confidence: {confidence}")
        else:
            lines.append("- **MITRE ATT&CK:** not mapped")
        lines.append("")

    lines.append("---")
    lines.append("")
    lines.append("## Evidence")
    lines.append("")
    for alert in alerts:
        evidence = alert.get("evidence", [])
        if evidence:
            lines.append(f"**{alert.get('rule_id', 'RULE')}:**")
            for item in evidence:
                lines.append(f"- {item}")
            lines.append("")

    lines.append("---")
    lines.append("")
    lines.append("## Recommended Analyst Actions")
    lines.append("")
    if actions:
        for action in actions:
            lines.append(f"- {action}")
    else:
        lines.append("No specific actions recorded.")
    lines.append("")

    lines.append("---")
    lines.append("")
    lines.append("## Analyst Notes")
    lines.append("")
    lines.append(analyst_notes if analyst_notes else "_No analyst notes yet._")
    lines.append("")

    lines.append("---")
    lines.append("")
    lines.append("## False Positive Considerations")
    lines.append("")
    lines.append("- SSH brute force: authorized vulnerability scanners, IT team pen tests")
    lines.append("- Web scanning: security scanners authorized by the organization")
    lines.append("- Sensitive path access: developer tools or monitoring agents")
    lines.append("- Cloud security group: short-lived rules for maintenance windows")
    lines.append("")

    lines.append("---")
    lines.append("")
    lines.append("## Limitations")
    lines.append("")
    lines.append("- This report is based on synthetic log data. No real systems are involved.")
    lines.append("- Detection rules use static thresholds without time-windowing.")
    lines.append("- Multi-source correlation is based on exact IP matching, not entity resolution.")
    lines.append("")

    lines.append(f"_Generated: {datetime.now(timezone.utc).isoformat()[:19]}Z_")

    return "\n".join(lines)


def generate_json_report(
    incident: dict, alerts: list[dict]
) -> dict[str, Any]:
    return {
        "schema_version": "1.0",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "incident": incident,
        "alerts": alerts,
    }


# Severity -> fill colour, so an analyst reading the Excel export sees critical
# rows as red the same way the Grafana board and the CLI colour them.
_SEVERITY_FILL = {
    "critical": "C0392B",
    "high": "E67E22",
    "medium": "F1C40F",
    "low": "27AE60",
}


def generate_xlsx_report(incident: dict, alerts: list[dict]) -> "Workbook":
    """Build an Excel workbook for one incident and its alerts.

    Three sheets: a summary of the incident, the alert table (one row per alert,
    coloured by severity), and the incident timeline. openpyxl is imported here,
    not at module top, so the markdown/JSON path carries no Excel dependency.

    Returns the ``Workbook``; the caller saves it (it is binary, unlike the text
    reports). Analysts export incidents to Excel constantly for handoff to teams
    that do not read Markdown, which is what this covers.
    """
    from openpyxl import Workbook
    from openpyxl.styles import Alignment, Font, PatternFill
    from openpyxl.utils import get_column_letter

    header_font = Font(bold=True, color="FFFFFF")
    header_fill = PatternFill("solid", fgColor="1F3864")
    wrap = Alignment(wrap_text=True, vertical="top")

    def _style_header(ws, ncols: int) -> None:
        for col in range(1, ncols + 1):
            cell = ws.cell(row=1, column=col)
            cell.font = header_font
            cell.fill = header_fill
        ws.freeze_panes = "A2"

    wb = Workbook()

    # --- Sheet 1: Summary -------------------------------------------------- #
    ws = wb.active
    ws.title = "Summary"
    entities = incident.get("involved_entities", {}) or {}
    rows = [
        ("Incident ID", incident.get("incident_id", "UNKNOWN")),
        ("Title", incident.get("title", "")),
        ("Severity", str(incident.get("severity", "")).upper()),
        ("Score", f"{incident.get('score', 0)}/100"),
        ("Status", incident.get("status", "open")),
        ("Created", incident.get("created_at", "")),
        ("Alerts in incident", len(alerts)),
        ("Source IPs", ", ".join(entities.get("source_ips", []) or [])),
        ("Usernames", ", ".join(entities.get("usernames", []) or [])),
        ("Hosts", ", ".join(entities.get("hosts", []) or [])),
        ("Summary", incident.get("summary", "")),
    ]
    ws.append(["Field", "Value"])
    _style_header(ws, 2)
    for label, value in rows:
        ws.append([label, value])
        ws.cell(row=ws.max_row, column=1).font = Font(bold=True)
        ws.cell(row=ws.max_row, column=2).alignment = wrap
    ws.column_dimensions["A"].width = 22
    ws.column_dimensions["B"].width = 70

    # --- Sheet 2: Alerts --------------------------------------------------- #
    ws = wb.create_sheet("Alerts")
    headers = [
        "Rule ID", "Rule name", "Severity", "Score", "Status",
        "Source IP", "Username", "MITRE tactic", "Technique", "Confidence",
    ]
    ws.append(headers)
    _style_header(ws, len(headers))
    for a in alerts:
        technique = " ".join(
            x for x in (a.get("mitre_technique_id"), a.get("mitre_technique_name")) if x
        )
        ws.append([
            a.get("rule_id", ""),
            a.get("rule_name", ""),
            str(a.get("severity", "")).upper(),
            a.get("score", 0),
            a.get("status", "new"),
            a.get("source_ip", ""),
            a.get("username", ""),
            a.get("mitre_tactic", ""),
            technique,
            a.get("mitre_mapping_confidence", ""),
        ])
        fill = _SEVERITY_FILL.get(str(a.get("severity", "")).lower())
        if fill:
            ws.cell(row=ws.max_row, column=3).fill = PatternFill("solid", fgColor=fill)
            ws.cell(row=ws.max_row, column=3).font = Font(color="FFFFFF", bold=True)
    widths = [22, 34, 10, 7, 10, 16, 14, 18, 30, 12]
    for i, w in enumerate(widths, start=1):
        ws.column_dimensions[get_column_letter(i)].width = w

    # --- Sheet 3: Timeline ------------------------------------------------- #
    ws = wb.create_sheet("Timeline")
    ws.append(["Time (UTC)", "Event", "Event ID", "Alert ID"])
    _style_header(ws, 4)
    for entry in incident.get("timeline", []) or []:
        ws.append([
            entry.get("timestamp", ""),
            entry.get("description", ""),
            entry.get("event_id", ""),
            entry.get("alert_id", ""),
        ])
    ws.column_dimensions["A"].width = 26
    ws.column_dimensions["B"].width = 60
    ws.column_dimensions["C"].width = 16
    ws.column_dimensions["D"].width = 16

    return wb
