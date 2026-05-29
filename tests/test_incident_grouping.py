import pytest
from datetime import datetime, timezone

from app.models.schemas import Alert, AlertSeverity, AlertStatus, Event, SourceType
from app.services.incident_grouping_service import group_alerts, reset_incident_counter


def _alert(rule_id: str, severity: AlertSeverity, score: int, source_ip: str | None, event_ids: list[str]) -> Alert:
    return Alert(
        alert_id=f"alert-{rule_id}-{source_ip or 'no-ip'}",
        rule_id=rule_id,
        rule_name=rule_id,
        severity=severity,
        score=score,
        event_ids=event_ids,
        source_ip=source_ip,
        title=f"Test alert {rule_id}",
        description="test",
        evidence=[],
        recommendation="test recommendation",
        created_at=datetime.now(timezone.utc),
        status=AlertStatus.new,
    )


def _event(eid: str, source_ip: str | None, source_type: SourceType) -> Event:
    return Event(
        event_id=eid,
        timestamp=datetime.now(timezone.utc),
        source_type=source_type,
        source_host="host-01",
        source_ip=source_ip,
        action="test",
        status="test",
        raw_event={},
        normalized_message="test event",
    )


@pytest.fixture(autouse=True)
def reset_counter():
    reset_incident_counter()
    yield
    reset_incident_counter()


class TestGroupAlerts:
    def test_empty_alerts_returns_empty(self):
        result = group_alerts([], [])
        assert result == []

    def test_single_alert_creates_one_incident(self):
        ev = _event("ev1", "192.0.2.10", SourceType.linux_auth)
        alert = _alert("SSH_BRUTE_FORCE", AlertSeverity.high, 70, "192.0.2.10", ["ev1"])
        incidents = group_alerts([alert], [ev])
        assert len(incidents) == 1
        assert incidents[0].severity == AlertSeverity.high

    def test_same_ip_groups_together(self):
        ev1 = _event("ev1", "192.0.2.10", SourceType.linux_auth)
        ev2 = _event("ev2", "192.0.2.10", SourceType.nginx_access)
        alerts = [
            _alert("SSH_BRUTE_FORCE", AlertSeverity.medium, 40, "192.0.2.10", ["ev1"]),
            _alert("WEB_DIR_SCAN", AlertSeverity.high, 70, "192.0.2.10", ["ev2"]),
        ]
        incidents = group_alerts(alerts, [ev1, ev2])
        assert len(incidents) == 1
        assert incidents[0].severity == AlertSeverity.high

    def test_different_ips_separate_incidents(self):
        ev1 = _event("ev1", "192.0.2.10", SourceType.linux_auth)
        ev2 = _event("ev2", "192.0.2.20", SourceType.nginx_access)
        alerts = [
            _alert("SSH_BRUTE_FORCE", AlertSeverity.medium, 40, "192.0.2.10", ["ev1"]),
            _alert("WEB_DIR_SCAN", AlertSeverity.medium, 40, "192.0.2.20", ["ev2"]),
        ]
        incidents = group_alerts(alerts, [ev1, ev2])
        assert len(incidents) == 2

    def test_severity_escalation_to_max(self):
        ev = _event("ev1", "192.0.2.30", SourceType.linux_auth)
        alerts = [
            _alert("RULE_A", AlertSeverity.low, 10, "192.0.2.30", ["ev1"]),
            _alert("RULE_B", AlertSeverity.critical, 100, "192.0.2.30", ["ev1"]),
        ]
        incidents = group_alerts(alerts, [ev])
        assert incidents[0].severity == AlertSeverity.critical

    def test_incident_id_format(self):
        ev = _event("ev1", "192.0.2.40", SourceType.linux_auth)
        alert = _alert("TEST", AlertSeverity.medium, 40, "192.0.2.40", ["ev1"])
        incidents = group_alerts([alert], [ev])
        assert incidents[0].incident_id.startswith("INC-")

    def test_timeline_built_from_events(self):
        ev = _event("ev1", "192.0.2.50", SourceType.linux_auth)
        alert = _alert("SSH_BRUTE_FORCE", AlertSeverity.high, 70, "192.0.2.50", ["ev1"])
        incidents = group_alerts([alert], [ev])
        assert len(incidents[0].timeline) >= 1

    def test_involved_entities_populated(self):
        ev = _event("ev1", "192.0.2.60", SourceType.linux_auth)
        alert = _alert("TEST", AlertSeverity.medium, 40, "192.0.2.60", ["ev1"])
        incidents = group_alerts([alert], [ev])
        assert "192.0.2.60" in incidents[0].involved_entities.source_ips

    def test_score_capped_at_100(self):
        ev = _event("ev1", "192.0.2.70", SourceType.linux_auth)
        alerts = [
            _alert(f"RULE_{i}", AlertSeverity.critical, 100, "192.0.2.70", ["ev1"])
            for i in range(5)
        ]
        incidents = group_alerts(alerts, [ev])
        assert incidents[0].score <= 100
