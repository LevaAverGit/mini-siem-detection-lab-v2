from __future__ import annotations

import json
from datetime import datetime

from app.db.database import get_connection
from app.models.schemas import Alert, AlertStatus, Event, Incident


class StorageService:
    def __init__(self, db_path: str):
        self.db_path = db_path

    def insert_events(self, events: list[Event]) -> None:
        if not events:
            return
        rows = [
            (
                e.event_id,
                e.timestamp.isoformat(),
                e.source_type.value,
                e.source_host,
                e.source_ip,
                e.username,
                e.action,
                e.status,
                json.dumps(e.raw_event),
                e.normalized_message,
                e.severity_hint,
            )
            for e in events
        ]
        with get_connection(self.db_path) as conn:
            conn.executemany(
                """INSERT OR IGNORE INTO events
                   (event_id, timestamp, source_type, source_host, source_ip, username,
                    action, status, raw_event, normalized_message, severity_hint)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                rows,
            )

    def list_events(
        self, limit: int = 100, source_type: str | None = None
    ) -> list[dict]:
        with get_connection(self.db_path) as conn:
            if source_type:
                rows = conn.execute(
                    "SELECT * FROM events WHERE source_type = ? ORDER BY timestamp DESC LIMIT ?",
                    (source_type, limit),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM events ORDER BY timestamp DESC LIMIT ?", (limit,)
                ).fetchall()
        return [dict(r) for r in rows]

    def insert_alerts(self, alerts: list[Alert]) -> None:
        if not alerts:
            return
        rows = [
            (
                a.alert_id,
                a.rule_id,
                a.rule_name,
                a.severity.value,
                a.score,
                json.dumps(a.event_ids),
                a.source_ip,
                a.username,
                a.title,
                a.description,
                json.dumps(a.evidence),
                a.recommendation,
                a.created_at.isoformat(),
                a.status.value,
                a.mitre_tactic,
                a.mitre_technique_id,
                a.mitre_technique_name,
                a.mitre_mapping_confidence,
            )
            for a in alerts
        ]
        with get_connection(self.db_path) as conn:
            conn.executemany(
                """INSERT OR IGNORE INTO alerts
                   (alert_id, rule_id, rule_name, severity, score, event_ids, source_ip,
                    username, title, description, evidence, recommendation, created_at, status,
                    mitre_tactic, mitre_technique_id, mitre_technique_name, mitre_mapping_confidence)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                rows,
            )

    def list_alerts(
        self, status: str | None = None, severity: str | None = None
    ) -> list[dict]:
        sql = "SELECT * FROM alerts WHERE 1=1"
        params: list = []
        if status:
            sql += " AND status = ?"
            params.append(status)
        if severity:
            sql += " AND severity = ?"
            params.append(severity)
        sql += " ORDER BY created_at DESC"
        with get_connection(self.db_path) as conn:
            rows = conn.execute(sql, params).fetchall()
        result = []
        for r in rows:
            row = dict(r)
            row["event_ids"] = json.loads(row["event_ids"])
            row["evidence"] = json.loads(row["evidence"])
            result.append(row)
        return result

    def update_alert_status(self, alert_id: str, status: AlertStatus) -> bool:
        with get_connection(self.db_path) as conn:
            cur = conn.execute(
                "UPDATE alerts SET status = ? WHERE alert_id = ?",
                (status.value, alert_id),
            )
        return cur.rowcount > 0

    def insert_incidents(self, incidents: list[Incident]) -> None:
        if not incidents:
            return
        rows = [
            (
                i.incident_id,
                i.title,
                i.severity.value,
                i.score,
                json.dumps(i.alert_ids),
                json.dumps(i.involved_entities.model_dump(mode="json")),
                json.dumps([t.model_dump(mode="json") for t in i.timeline]),
                i.summary,
                i.analyst_notes,
                json.dumps(i.recommended_actions),
                i.created_at.isoformat(),
                i.status.value,
            )
            for i in incidents
        ]
        with get_connection(self.db_path) as conn:
            conn.executemany(
                """INSERT OR IGNORE INTO incidents
                   (incident_id, title, severity, score, alert_ids, involved_entities,
                    timeline, summary, analyst_notes, recommended_actions, created_at, status)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
                rows,
            )

    def list_incidents(
        self, status: str | None = None, severity: str | None = None
    ) -> list[dict]:
        sql = "SELECT * FROM incidents WHERE 1=1"
        params: list = []
        if status:
            sql += " AND status = ?"
            params.append(status)
        if severity:
            sql += " AND severity = ?"
            params.append(severity)
        sql += " ORDER BY created_at DESC"
        with get_connection(self.db_path) as conn:
            rows = conn.execute(sql, params).fetchall()
        result = []
        for r in rows:
            row = dict(r)
            for field in ("alert_ids", "involved_entities", "timeline", "recommended_actions"):
                row[field] = json.loads(row[field])
            result.append(row)
        return result

    def get_incident(self, incident_id: str) -> dict | None:
        with get_connection(self.db_path) as conn:
            row = conn.execute(
                "SELECT * FROM incidents WHERE incident_id = ?", (incident_id,)
            ).fetchone()
        if not row:
            return None
        result = dict(row)
        for field in ("alert_ids", "involved_entities", "timeline", "recommended_actions"):
            result[field] = json.loads(result[field])
        return result

    def get_alerts_for_incident(self, alert_ids: list[str]) -> list[dict]:
        if not alert_ids:
            return []
        placeholders = ",".join("?" for _ in alert_ids)
        with get_connection(self.db_path) as conn:
            rows = conn.execute(
                f"SELECT * FROM alerts WHERE alert_id IN ({placeholders})", alert_ids
            ).fetchall()
        result = []
        for r in rows:
            row = dict(r)
            row["event_ids"] = json.loads(row["event_ids"])
            row["evidence"] = json.loads(row["evidence"])
            result.append(row)
        return result
