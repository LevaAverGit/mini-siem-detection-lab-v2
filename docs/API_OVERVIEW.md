# API Overview

Base URL: `http://127.0.0.1:8000` (local only, no auth required for lab)

Interactive docs: `http://127.0.0.1:8000/docs`

---

## GET /health

Returns liveness status.

```json
{"status": "ok"}
```

---

## POST /events/ingest

Ingest raw log content for a given source type.

**Request:**
```json
{
  "source_type": "linux_auth",
  "content": "Jan 10 09:10:15 web-01 sshd[1300]: Failed password for root from 192.0.2.100 port 43210 ssh2\n..."
}
```

`source_type` values: `linux_auth`, `nginx_access`, `windows_security`, `cloud_audit`

For `windows_security` and `cloud_audit`, content is JSONL (one JSON object per line).

**Response:**
```json
{
  "events_ingested": 15,
  "skipped": 1,
  "alerts_created": 2,
  "incidents_created": 1
}
```

---

## GET /events/

List normalized events.

**Query params:**
- `limit` (int, default 100)
- `source_type` (string, optional)

**Response:** Array of event objects with all normalized fields.

---

## GET /alerts/

List alerts.

**Query params:**
- `status` (string): `new`, `triaged`, `false_positive`, `escalated`, `closed`
- `severity` (string): `low`, `medium`, `high`, `critical`

**Response:**
```json
[
  {
    "alert_id": "uuid",
    "rule_id": "SSH_BRUTE_FORCE",
    "rule_name": "SSH Brute Force",
    "severity": "high",
    "score": 70,
    "event_ids": ["...", "..."],
    "source_ip": "192.0.2.100",
    "title": "SSH Brute Force from 192.0.2.100 (35 attempts)",
    "description": "35 failed SSH attempts from 192.0.2.100",
    "evidence": ["35 failed SSH attempts from 192.0.2.100", "..."],
    "recommendation": "Block source IP at firewall...",
    "created_at": "2026-01-10T09:15:00Z",
    "status": "new"
  }
]
```

---

## PATCH /alerts/{alert_id}/status

Update alert triage status.

**Request:**
```json
{"status": "triaged"}
```

Valid status values: `new`, `triaged`, `false_positive`, `escalated`, `closed`

**Response:**
```json
{"alert_id": "uuid", "status": "triaged"}
```

**Error:**
```json
{"detail": "Alert uuid not found"}
```

---

## GET /incidents/

List incidents.

**Query params:**
- `status`: `open`, `triaged`, `escalated`, `closed`
- `severity`: `low`, `medium`, `high`, `critical`

---

## GET /incidents/{incident_id}

Get incident details including timeline and involved entities.

**Error (404):**
```json
{"detail": "Incident INC-0001 not found"}
```

---

## GET /incidents/{incident_id}/report.md

Returns the incident report as Markdown text.

Includes: executive summary, severity, involved entities, timeline, alerts, evidence,
recommended actions, false positive considerations, limitations.

---

## GET /incidents/{incident_id}/report.json

Returns the incident report as JSON.

```json
{
  "schema_version": "1.0",
  "generated_at": "2026-01-10T09:20:00Z",
  "incident": { ... },
  "alerts": [ ... ]
}
```
