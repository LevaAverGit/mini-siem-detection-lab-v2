from __future__ import annotations

import uuid
from collections import defaultdict
from datetime import datetime, timezone

from app.models.schemas import Alert, AlertSeverity, Event, Incident, InvolvedEntities, TimelineEntry

_SEVERITY_ORDER = {
    AlertSeverity.low: 0,
    AlertSeverity.medium: 1,
    AlertSeverity.high: 2,
    AlertSeverity.critical: 3,
}


def _max_severity(alerts: list[Alert]) -> AlertSeverity:
    return max(alerts, key=lambda a: _SEVERITY_ORDER[a.severity]).severity


def _build_timeline(alerts: list[Alert], events: list[Event]) -> list[TimelineEntry]:
    entries: list[TimelineEntry] = []
    event_index = {e.event_id: e for e in events}

    for alert in sorted(alerts, key=lambda a: a.created_at):
        for eid in alert.event_ids:
            ev = event_index.get(eid)
            if ev:
                entries.append(
                    TimelineEntry(
                        timestamp=ev.timestamp,
                        description=ev.normalized_message,
                        event_id=eid,
                        alert_id=alert.alert_id,
                    )
                )
    entries.sort(key=lambda e: e.timestamp)
    seen: set[str] = set()
    unique: list[TimelineEntry] = []
    for e in entries:
        key = f"{e.timestamp.isoformat()[:16]}:{e.description[:40]}"
        if key not in seen:
            seen.add(key)
            unique.append(e)
    return unique[:50]


def _collect_entities(alerts: list[Alert], events: list[Event]) -> InvolvedEntities:
    event_index = {e.event_id: e for e in events}
    ips: set[str] = set()
    users: set[str] = set()
    hosts: set[str] = set()

    for alert in alerts:
        if alert.source_ip:
            ips.add(alert.source_ip)
        if alert.username:
            users.add(alert.username)
        for eid in alert.event_ids:
            ev = event_index.get(eid)
            if ev:
                if ev.source_ip:
                    ips.add(ev.source_ip)
                if ev.username:
                    users.add(ev.username)
                if ev.source_host and ev.source_host != "unknown":
                    hosts.add(ev.source_host)

    return InvolvedEntities(
        source_ips=sorted(ips),
        usernames=sorted(users),
        hosts=sorted(hosts),
    )


def _summarize(alerts: list[Alert], entities: InvolvedEntities) -> str:
    severity = _max_severity(alerts).value
    ips = ", ".join(entities.source_ips[:3]) or "unknown"
    rules = ", ".join(sorted({a.rule_id for a in alerts}))
    return (
        f"{severity.capitalize()} severity incident involving {len(alerts)} alert(s) "
        f"from IP(s): {ips}. "
        f"Rules triggered: {rules}."
    )


def _recommended_actions(alerts: list[Alert]) -> list[str]:
    seen: set[str] = set()
    actions: list[str] = []
    for alert in alerts:
        rec = alert.recommendation.strip()
        if rec and rec not in seen:
            seen.add(rec)
            actions.append(f"[{alert.rule_id}] {rec}")
    return actions


_incident_counter = 0


def _next_incident_id() -> str:
    global _incident_counter
    _incident_counter += 1
    return f"INC-{_incident_counter:04d}"


def reset_incident_counter() -> None:
    global _incident_counter
    _incident_counter = 0


def group_alerts(alerts: list[Alert], events: list[Event]) -> list[Incident]:
    """Group alerts into incidents by shared source_ip, falling back to rule_id grouping."""
    if not alerts:
        return []

    by_ip: dict[str, list[Alert]] = defaultdict(list)
    no_ip: list[Alert] = []
    for alert in alerts:
        if alert.source_ip:
            by_ip[alert.source_ip].append(alert)
        else:
            no_ip.append(alert)

    by_rule: dict[str, list[Alert]] = defaultdict(list)
    for alert in no_ip:
        by_rule[alert.rule_id].append(alert)

    groups: list[list[Alert]] = list(by_ip.values()) + list(by_rule.values())

    incidents: list[Incident] = []
    for group in groups:
        if not group:
            continue
        sev = _max_severity(group)
        total_score = min(sum(a.score for a in group), 100)
        entities = _collect_entities(group, events)
        timeline = _build_timeline(group, events)
        summary = _summarize(group, entities)
        actions = _recommended_actions(group)

        incidents.append(
            Incident(
                incident_id=_next_incident_id(),
                title=f"{sev.value.capitalize()} Incident — {entities.source_ips[0] if entities.source_ips else group[0].rule_id}",
                severity=sev,
                score=total_score,
                alert_ids=[a.alert_id for a in group],
                involved_entities=entities,
                timeline=timeline,
                summary=summary,
                recommended_actions=actions,
                created_at=datetime.now(timezone.utc),
            )
        )

    incidents.sort(key=lambda i: _SEVERITY_ORDER[i.severity], reverse=True)
    return incidents
