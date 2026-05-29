import pytest
from datetime import datetime, timezone
from pathlib import Path

from app.db.database import init_db
from app.models.schemas import Alert, AlertSeverity, AlertStatus, Event, Incident, IncidentStatus, InvolvedEntities, SourceType
from app.services.storage_service import StorageService


def _make_event(eid: str, source_ip: str = "192.0.2.1") -> Event:
    return Event(
        event_id=eid,
        timestamp=datetime.now(timezone.utc),
        source_type=SourceType.linux_auth,
        source_host="web-01",
        source_ip=source_ip,
        username="root",
        action="ssh_failed_password",
        status="failure",
        raw_event={"line": "test"},
        normalized_message="test event",
    )


def _make_alert(aid: str, severity: AlertSeverity = AlertSeverity.medium) -> Alert:
    return Alert(
        alert_id=aid,
        rule_id="TEST_RULE",
        rule_name="Test Rule",
        severity=severity,
        score=50,
        event_ids=["ev1"],
        source_ip="192.0.2.1",
        title="Test Alert",
        description="test",
        evidence=["evidence item"],
        recommendation="test recommendation",
        created_at=datetime.now(timezone.utc),
    )


def _make_alert_with_mitre(aid: str) -> Alert:
    return Alert(
        alert_id=aid,
        rule_id="SSH_BRUTE_FORCE",
        rule_name="SSH Brute Force",
        severity=AlertSeverity.critical,
        score=100,
        event_ids=["ev1"],
        source_ip="192.0.2.1",
        title="Test Alert with MITRE",
        description="test",
        evidence=["evidence item"],
        recommendation="block ip",
        created_at=datetime.now(timezone.utc),
        mitre_tactic="Credential Access",
        mitre_technique_id="T1110.001",
        mitre_technique_name="Brute Force: Password Guessing",
        mitre_mapping_confidence="direct",
    )


def _make_incident(iid: str, alert_ids: list[str]) -> Incident:
    return Incident(
        incident_id=iid,
        title=f"Test Incident {iid}",
        severity=AlertSeverity.high,
        score=75,
        alert_ids=alert_ids,
        involved_entities=InvolvedEntities(source_ips=["192.0.2.1"]),
        summary="test summary",
        created_at=datetime.now(timezone.utc),
    )


class TestStorageService:
    def test_insert_and_list_events(self, db_path: str):
        storage = StorageService(db_path)
        events = [_make_event(f"ev-{i}") for i in range(5)]
        storage.insert_events(events)
        result = storage.list_events()
        assert len(result) == 5

    def test_list_events_by_source_type(self, db_path: str):
        storage = StorageService(db_path)
        storage.insert_events([_make_event("ev-linux")])
        result = storage.list_events(source_type="linux_auth")
        assert len(result) == 1
        result_nginx = storage.list_events(source_type="nginx_access")
        assert len(result_nginx) == 0

    def test_insert_duplicate_event_ignored(self, db_path: str):
        storage = StorageService(db_path)
        ev = _make_event("ev-dup")
        storage.insert_events([ev, ev])
        result = storage.list_events()
        assert len(result) == 1

    def test_insert_and_list_alerts(self, db_path: str):
        storage = StorageService(db_path)
        alerts = [_make_alert(f"alert-{i}") for i in range(3)]
        storage.insert_alerts(alerts)
        result = storage.list_alerts()
        assert len(result) == 3

    def test_list_alerts_filter_by_status(self, db_path: str):
        storage = StorageService(db_path)
        storage.insert_alerts([_make_alert("alert-new")])
        result = storage.list_alerts(status="new")
        assert len(result) == 1
        result_triaged = storage.list_alerts(status="triaged")
        assert len(result_triaged) == 0

    def test_list_alerts_filter_by_severity(self, db_path: str):
        storage = StorageService(db_path)
        storage.insert_alerts([
            _make_alert("alert-medium", AlertSeverity.medium),
            _make_alert("alert-high", AlertSeverity.high),
        ])
        result = storage.list_alerts(severity="high")
        assert len(result) == 1
        assert result[0]["alert_id"] == "alert-high"

    def test_update_alert_status(self, db_path: str):
        storage = StorageService(db_path)
        storage.insert_alerts([_make_alert("alert-update")])
        updated = storage.update_alert_status("alert-update", AlertStatus.triaged)
        assert updated is True
        result = storage.list_alerts(status="triaged")
        assert len(result) == 1

    def test_update_nonexistent_alert_returns_false(self, db_path: str):
        storage = StorageService(db_path)
        result = storage.update_alert_status("nonexistent", AlertStatus.triaged)
        assert result is False

    def test_insert_and_list_incidents(self, db_path: str):
        storage = StorageService(db_path)
        storage.insert_incidents([_make_incident("INC-0001", ["alert-1"])])
        result = storage.list_incidents()
        assert len(result) == 1

    def test_get_incident(self, db_path: str):
        storage = StorageService(db_path)
        storage.insert_incidents([_make_incident("INC-0002", ["alert-2"])])
        incident = storage.get_incident("INC-0002")
        assert incident is not None
        assert incident["incident_id"] == "INC-0002"

    def test_get_nonexistent_incident_returns_none(self, db_path: str):
        storage = StorageService(db_path)
        assert storage.get_incident("INC-MISSING") is None

    def test_evidence_serialized_as_list(self, db_path: str):
        storage = StorageService(db_path)
        storage.insert_alerts([_make_alert("alert-evidence")])
        alerts = storage.list_alerts()
        assert isinstance(alerts[0]["evidence"], list)

    def test_db_isolation_via_tmp_path(self, tmp_path: Path):
        path_a = str(tmp_path / "a.db")
        path_b = str(tmp_path / "b.db")
        init_db(path_a)
        init_db(path_b)
        StorageService(path_a).insert_events([_make_event("ev-a")])
        assert len(StorageService(path_a).list_events()) == 1
        assert len(StorageService(path_b).list_events()) == 0

    def test_alert_mitre_fields_roundtrip(self, db_path: str):
        storage = StorageService(db_path)
        alert = _make_alert_with_mitre("alert-mitre-1")
        storage.insert_alerts([alert])
        results = storage.list_alerts()
        assert len(results) == 1
        row = results[0]
        assert row["mitre_tactic"] == "Credential Access"
        assert row["mitre_technique_id"] == "T1110.001"
        assert row["mitre_technique_name"] == "Brute Force: Password Guessing"
        assert row["mitre_mapping_confidence"] == "direct"

    def test_alert_without_mitre_fields_stored_as_null(self, db_path: str):
        storage = StorageService(db_path)
        alert = _make_alert("alert-no-mitre")
        storage.insert_alerts([alert])
        results = storage.list_alerts()
        assert len(results) == 1
        row = results[0]
        assert row["mitre_tactic"] is None
        assert row["mitre_technique_id"] is None
