from __future__ import annotations

import uuid
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any

import yaml

from app.models.schemas import Alert, AlertSeverity, Event, SourceType


def load_rules(path: str) -> dict[str, Any]:
    with open(path, encoding="utf-8") as f:
        config = yaml.safe_load(f)
    return {r["rule_id"]: r for r in config.get("rules", [])}


def _mitre_fields(rule: dict) -> dict:
    return {
        "mitre_tactic": rule.get("mitre_tactic"),
        "mitre_technique_id": rule.get("mitre_technique_id"),
        "mitre_technique_name": rule.get("mitre_technique_name"),
        "mitre_mapping_confidence": rule.get("mitre_mapping_confidence"),
    }


def _make_alert(
    rule: dict,
    severity: AlertSeverity,
    score: int,
    event_ids: list[str],
    source_ip: str | None,
    username: str | None,
    title: str,
    description: str,
    evidence: list[str],
) -> Alert:
    return Alert(
        alert_id=str(uuid.uuid4()),
        rule_id=rule["rule_id"],
        rule_name=rule["name"],
        severity=severity,
        score=score,
        event_ids=event_ids,
        source_ip=source_ip,
        username=username,
        title=title,
        description=description,
        evidence=evidence,
        recommendation=rule.get("recommendation", "").strip(),
        created_at=datetime.now(timezone.utc),
        **_mitre_fields(rule),
    )


def _detect_ssh_brute_force(
    events: list[Event], rule: dict
) -> list[Alert]:
    failed_by_ip: dict[str, list[Event]] = defaultdict(list)
    for ev in events:
        if ev.source_type == SourceType.linux_auth and ev.action in (
            "ssh_failed_password",
            "ssh_invalid_user",
        ):
            if ev.source_ip:
                failed_by_ip[ev.source_ip].append(ev)

    thresholds = rule["thresholds"]
    scores = rule["scores"]
    alerts = []
    for ip, evs in failed_by_ip.items():
        count = len(evs)
        if count >= thresholds["critical"]:
            sev, sc = AlertSeverity.critical, scores["critical"]
        elif count >= thresholds["high"]:
            sev, sc = AlertSeverity.high, scores["high"]
        elif count >= thresholds["medium"]:
            sev, sc = AlertSeverity.medium, scores["medium"]
        else:
            continue
        alerts.append(
            _make_alert(
                rule=rule,
                severity=sev,
                score=sc,
                event_ids=[e.event_id for e in evs],
                source_ip=ip,
                username=None,
                title=f"SSH Brute Force from {ip} ({count} attempts)",
                description=f"{count} failed SSH login attempts from {ip}",
                evidence=[
                    f"{count} failed SSH attempts from {ip}",
                    f"Severity threshold reached: {sev.value} (>= {thresholds[sev.value]})",
                ],
            )
        )
    return alerts


def _detect_ssh_brute_force_success(
    events: list[Event], rule: dict
) -> list[Alert]:
    failed_by_ip: dict[str, list[Event]] = defaultdict(list)
    success_by_ip: dict[str, list[Event]] = defaultdict(list)
    for ev in events:
        if ev.source_type != SourceType.linux_auth:
            continue
        if ev.action in ("ssh_failed_password", "ssh_invalid_user") and ev.source_ip:
            failed_by_ip[ev.source_ip].append(ev)
        elif ev.action == "ssh_accepted_password" and ev.source_ip:
            success_by_ip[ev.source_ip].append(ev)

    min_failures = rule.get("min_failures", 5)
    alerts = []
    for ip, success_evs in success_by_ip.items():
        failures = failed_by_ip.get(ip, [])
        if len(failures) >= min_failures:
            all_ids = [e.event_id for e in failures] + [e.event_id for e in success_evs]
            usernames = list({e.username for e in success_evs if e.username})
            alerts.append(
                _make_alert(
                    rule=rule,
                    severity=AlertSeverity.critical,
                    score=rule["score"],
                    event_ids=all_ids,
                    source_ip=ip,
                    username=usernames[0] if usernames else None,
                    title=f"Successful SSH Login After Brute Force from {ip}",
                    description=(
                        f"{len(failures)} failed SSH attempts from {ip} followed by successful login"
                    ),
                    evidence=[
                        f"{len(failures)} failed SSH attempts from {ip}",
                        f"Successful SSH login for: {', '.join(usernames) or 'unknown'}",
                    ],
                )
            )
    return alerts


def _detect_web_dir_scan(events: list[Event], rule: dict) -> list[Alert]:
    not_found_by_ip: dict[str, list[Event]] = defaultdict(list)
    for ev in events:
        if ev.source_type == SourceType.nginx_access and ev.status == "404" and ev.source_ip:
            not_found_by_ip[ev.source_ip].append(ev)

    thresholds = rule["thresholds"]
    scores = rule["scores"]
    alerts = []
    for ip, evs in not_found_by_ip.items():
        count = len(evs)
        if count >= thresholds["high"]:
            sev, sc = AlertSeverity.high, scores["high"]
        elif count >= thresholds["medium"]:
            sev, sc = AlertSeverity.medium, scores["medium"]
        else:
            continue
        alerts.append(
            _make_alert(
                rule=rule,
                severity=sev,
                score=sc,
                event_ids=[e.event_id for e in evs],
                source_ip=ip,
                username=None,
                title=f"Web Directory Scanning from {ip} ({count} x 404)",
                description=f"{count} HTTP 404 responses triggered by {ip}",
                evidence=[
                    f"{count} HTTP 404 responses from {ip}",
                    f"Sample paths: {', '.join(e.raw_event.get('path', '') for e in evs[:5])}",
                ],
            )
        )
    return alerts


def _detect_sensitive_path(events: list[Event], rule: dict) -> list[Alert]:
    sensitive_paths = rule["paths"]
    alerts = []
    for ev in events:
        if ev.source_type != SourceType.nginx_access:
            continue
        path = ev.raw_event.get("path", "")
        matched = next((p for p in sensitive_paths if path.startswith(p)), None)
        if not matched:
            continue
        if ev.status in ("200", "302"):
            sev = AlertSeverity.high
            sc = rule["scores"]["high"]
        else:
            sev = AlertSeverity.medium
            sc = rule["scores"]["medium"]
        alerts.append(
            _make_alert(
                rule=rule,
                severity=sev,
                score=sc,
                event_ids=[ev.event_id],
                source_ip=ev.source_ip,
                username=ev.username,
                title=f"Sensitive Path Access: {path} [{ev.status}]",
                description=f"Access to sensitive path {path} returned HTTP {ev.status}",
                evidence=[
                    f"Path: {path}",
                    f"HTTP status: {ev.status}",
                    f"Source IP: {ev.source_ip}",
                    f"Matched rule path: {matched}",
                ],
            )
        )
    return alerts


def _detect_suspicious_user_agent(events: list[Event], rule: dict) -> list[Alert]:
    scanner_agents = rule["user_agents"]
    sensitive_paths = [
        "/.env", "/.git", "/admin", "/phpmyadmin", "/backup", "/wp-admin", "/config"
    ]
    alerts = []
    for ev in events:
        if ev.source_type != SourceType.nginx_access:
            continue
        ua = ev.raw_event.get("user_agent", "").lower()
        matched_agent = next((a for a in scanner_agents if a in ua), None)
        if not matched_agent:
            continue
        path = ev.raw_event.get("path", "")
        is_sensitive = any(path.startswith(p) for p in sensitive_paths)
        if is_sensitive or ev.status in ("200", "302"):
            sev = AlertSeverity(rule["severity_sensitive_path"])
            sc = rule["scores"]["high"]
        else:
            sev = AlertSeverity(rule["severity_default"])
            sc = rule["scores"]["medium"]
        alerts.append(
            _make_alert(
                rule=rule,
                severity=sev,
                score=sc,
                event_ids=[ev.event_id],
                source_ip=ev.source_ip,
                username=ev.username,
                title=f"Scanner User Agent Detected: {matched_agent}",
                description=f"Request from known scanner tool '{matched_agent}' to {path}",
                evidence=[
                    f"User agent: {ua[:80]}",
                    f"Path: {path}",
                    f"HTTP status: {ev.status}",
                ],
            )
        )
    return alerts


def _detect_win_account_created(events: list[Event], rule: dict) -> list[Alert]:
    failures_by_host: dict[str, list[Event]] = defaultdict(list)
    creations_by_host: dict[str, list[Event]] = defaultdict(list)
    for ev in events:
        if ev.source_type != SourceType.windows_security:
            continue
        if ev.action == "logon_failure":
            failures_by_host[ev.source_host].append(ev)
        elif ev.action == "user_account_created":
            creations_by_host[ev.source_host].append(ev)

    min_failures = rule.get("min_failures", 3)
    alerts = []
    for host, creation_evs in creations_by_host.items():
        failures = failures_by_host.get(host, [])
        if len(failures) >= min_failures:
            all_ids = [e.event_id for e in failures] + [e.event_id for e in creation_evs]
            new_accounts = [e.raw_event.get("new_account", "unknown") for e in creation_evs]
            alerts.append(
                _make_alert(
                    rule=rule,
                    severity=AlertSeverity(rule["severity"]),
                    score=rule["score"],
                    event_ids=all_ids,
                    source_ip=failures[0].source_ip if failures else None,
                    username=creation_evs[0].username,
                    title=f"Account Created After Failures on {host}",
                    description=(
                        f"{len(failures)} failed logons on {host} followed by "
                        f"user account creation: {', '.join(new_accounts)}"
                    ),
                    evidence=[
                        f"{len(failures)} 4625 (logon failure) events on {host}",
                        f"4720 (account created): {', '.join(new_accounts)}",
                    ],
                )
            )
    return alerts


def _detect_cloud_sg_open(events: list[Event], rule: dict) -> list[Alert]:
    db_ports = set(rule.get("db_ports", []))
    dangerous_ports = set(rule.get("dangerous_ports", []))
    alerts = []
    for ev in events:
        if ev.source_type != SourceType.cloud_audit:
            continue
        if ev.action != "security_group_rule_added":
            continue
        cidr = ev.raw_event.get("cidr", "")
        port = ev.raw_event.get("port")
        if cidr != "0.0.0.0/0" or port not in dangerous_ports:
            continue
        if port in db_ports:
            sev = AlertSeverity(rule["severity_db_ports"])
            sc = rule["scores"]["critical"]
        else:
            sev = AlertSeverity(rule["severity_remote_ports"])
            sc = rule["scores"]["high"]
        alerts.append(
            _make_alert(
                rule=rule,
                severity=sev,
                score=sc,
                event_ids=[ev.event_id],
                source_ip=ev.source_ip,
                username=ev.username,
                title=f"Security Group Opened to 0.0.0.0/0 on Port {port}",
                description=f"Inbound rule added allowing {cidr} on port {port}/{ev.raw_event.get('protocol', 'tcp')}",
                evidence=[
                    f"Security group: {ev.raw_event.get('security_group_id', 'unknown')}",
                    f"CIDR: {cidr}",
                    f"Port: {port}",
                    f"Region: {ev.source_host}",
                    f"Modified by: {ev.username}",
                ],
            )
        )
    return alerts


def _detect_iam_change_after_failure(events: list[Event], rule: dict) -> list[Alert]:
    failures_by_user: dict[str, list[Event]] = defaultdict(list)
    failures_by_ip: dict[str, list[Event]] = defaultdict(list)
    iam_changes: list[Event] = []

    for ev in events:
        if ev.source_type != SourceType.cloud_audit:
            continue
        if ev.action == "console_login" and ev.status == "failure":
            if ev.username:
                failures_by_user[ev.username].append(ev)
            if ev.source_ip:
                failures_by_ip[ev.source_ip].append(ev)
        elif ev.action == "iam_policy_changed":
            iam_changes.append(ev)

    alerts = []
    for change_ev in iam_changes:
        triggered_by_user = change_ev.username and change_ev.username in failures_by_user
        triggered_by_ip = change_ev.source_ip and change_ev.source_ip in failures_by_ip
        if triggered_by_user or triggered_by_ip:
            related_failures = (
                failures_by_user.get(change_ev.username, [])
                + failures_by_ip.get(change_ev.source_ip or "", [])
            )
            unique_ids = list({e.event_id for e in related_failures})
            alerts.append(
                _make_alert(
                    rule=rule,
                    severity=AlertSeverity(rule["severity"]),
                    score=rule["score"],
                    event_ids=unique_ids + [change_ev.event_id],
                    source_ip=change_ev.source_ip,
                    username=change_ev.username,
                    title=f"IAM Policy Changed After Login Failures by {change_ev.username}",
                    description=(
                        f"IAM policy '{change_ev.raw_event.get('policy_name', 'unknown')}' was modified "
                        f"by {change_ev.username} who had recent console login failures"
                    ),
                    evidence=[
                        f"{len(related_failures)} console login failures by {change_ev.username} / {change_ev.source_ip}",
                        f"IAM change: {change_ev.raw_event.get('change_type', 'unknown')} on {change_ev.raw_event.get('policy_name', 'unknown')}",
                        f"Target: {change_ev.raw_event.get('target_user', 'unknown')}",
                    ],
                )
            )
    return alerts


def _detect_multi_source_ip(
    events: list[Event], alerts_so_far: list[Alert], rule: dict
) -> list[Alert]:
    """IPs that appear in alerts from 2+ different source types."""
    alert_sources_by_ip: dict[str, set[str]] = defaultdict(set)
    alert_ids_by_ip: dict[str, list[str]] = defaultdict(list)

    for alert in alerts_so_far:
        if not alert.source_ip:
            continue
        for eid in alert.event_ids:
            ev = next((e for e in events if e.event_id == eid), None)
            if ev:
                alert_sources_by_ip[alert.source_ip].add(ev.source_type.value)
        alert_ids_by_ip[alert.source_ip].append(alert.alert_id)

    min_sources = rule.get("min_sources", 2)
    new_alerts = []
    for ip, source_types in alert_sources_by_ip.items():
        if len(source_types) >= min_sources:
            related_event_ids = [
                e.event_id for e in events if e.source_ip == ip
            ]
            new_alerts.append(
                _make_alert(
                    rule=rule,
                    severity=AlertSeverity.critical,
                    score=rule["score"],
                    event_ids=related_event_ids,
                    source_ip=ip,
                    username=None,
                    title=f"Multi-Source Suspicious Activity from {ip}",
                    description=(
                        f"IP {ip} appears in suspicious events across {len(source_types)} "
                        f"source types: {', '.join(sorted(source_types))}"
                    ),
                    evidence=[
                        f"Involved source types: {', '.join(sorted(source_types))}",
                        f"Related alert IDs: {', '.join(alert_ids_by_ip[ip][:5])}",
                    ],
                )
            )
    return new_alerts


def run_detections(events: list[Event], rules: dict[str, Any]) -> list[Alert]:
    alerts: list[Alert] = []

    if "SSH_BRUTE_FORCE" in rules:
        alerts.extend(_detect_ssh_brute_force(events, rules["SSH_BRUTE_FORCE"]))
    if "SSH_BRUTE_FORCE_SUCCESS" in rules:
        alerts.extend(_detect_ssh_brute_force_success(events, rules["SSH_BRUTE_FORCE_SUCCESS"]))
    if "WEB_DIR_SCAN" in rules:
        alerts.extend(_detect_web_dir_scan(events, rules["WEB_DIR_SCAN"]))
    if "SENSITIVE_PATH_ACCESS" in rules:
        alerts.extend(_detect_sensitive_path(events, rules["SENSITIVE_PATH_ACCESS"]))
    if "SUSPICIOUS_USER_AGENT" in rules:
        alerts.extend(_detect_suspicious_user_agent(events, rules["SUSPICIOUS_USER_AGENT"]))
    if "WIN_ACCOUNT_CREATED_AFTER_FAILURES" in rules:
        alerts.extend(_detect_win_account_created(events, rules["WIN_ACCOUNT_CREATED_AFTER_FAILURES"]))
    if "CLOUD_SG_OPEN" in rules:
        alerts.extend(_detect_cloud_sg_open(events, rules["CLOUD_SG_OPEN"]))
    if "CLOUD_IAM_CHANGE_AFTER_FAILURE" in rules:
        alerts.extend(_detect_iam_change_after_failure(events, rules["CLOUD_IAM_CHANGE_AFTER_FAILURE"]))
    if "MULTI_SOURCE_SUSPICIOUS_IP" in rules:
        alerts.extend(_detect_multi_source_ip(events, alerts, rules["MULTI_SOURCE_SUSPICIOUS_IP"]))

    return alerts
