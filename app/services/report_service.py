from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any


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
        f"| Severity | Score |",
        f"|---|---|",
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
            lines.append(f"- **MITRE ATT&CK:**")
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
