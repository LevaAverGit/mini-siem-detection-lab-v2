# Data Flow

## Ingest via API

```
POST /events/ingest
  body: { source_type: "linux_auth", content: "..." }
  ↓
  routes_events.ingest_events()
    ↓ split content into lines
    ↓ normalize each line → Event | None
    ↓ storage.insert_events(events)
    ↓ detection_engine.run_detections(events, rules)
    ↓ storage.insert_alerts(alerts)
    ↓ incident_grouping.group_alerts(alerts, events)
    ↓ storage.insert_incidents(incidents)
  ← IngestionResult { events_ingested, skipped, alerts_created, incidents_created }
```

## Normalization

```
Raw line or JSON object
  ↓
  normalize_linux_auth_line(line) → match regex patterns
  normalize_nginx_line(line) → match combined log regex
  normalize_windows_json(dict) → map event_code to action
  normalize_cloud_json(dict) → map action/status fields
  ↓
Event {
  event_id: uuid
  timestamp: datetime (UTC)
  source_type: SourceType
  source_host: str
  source_ip: str | None
  username: str | None
  action: str        (e.g. "ssh_failed_password", "http_get", "logon_failure")
  status: str        (e.g. "failure", "200", "success")
  raw_event: dict    (original fields preserved)
  normalized_message: str  (human-readable one-liner)
  severity_hint: str | None
}
```

## Detection

```
List[Event] + rules dict
  ↓
  _detect_ssh_brute_force()      → group by source_ip, count failures
  _detect_ssh_brute_force_success() → cross-join failures + successes by IP
  _detect_web_dir_scan()         → count 404s by IP
  _detect_sensitive_path()       → match path prefixes, check status
  _detect_suspicious_user_agent() → match UA substrings
  _detect_win_account_created()  → group 4625/4720 by host
  _detect_cloud_sg_open()        → match CIDR + port
  _detect_iam_change_after_failure() → join failures + IAM events
  _detect_multi_source_ip()      → check IPs in 2+ source types
  ↓
List[Alert] {
  alert_id, rule_id, rule_name, severity, score
  event_ids, source_ip, username
  title, description, evidence, recommendation
  created_at, status: "new"
}
```

## Incident Grouping

```
List[Alert] + List[Event]
  ↓
  group by source_ip → dict[ip → List[Alert]]
  fallback: group by rule_id (for alerts without IP)
  ↓
  for each group:
    max_severity = max(alert.severity)
    total_score = min(sum(scores), 100)
    entities = collect source_ips, usernames, hosts from events
    timeline = sorted unique (timestamp, description) pairs
    summary = human-readable string
    actions = deduplicated recommendations
  ↓
List[Incident] sorted by severity (critical first)
```

## Storage

All data is persisted to SQLite.

- `events` — one row per normalized event; `raw_event` as JSON TEXT
- `alerts` — one row per alert; `event_ids` and `evidence` as JSON TEXT
- `incidents` — one row per incident; `alert_ids`, `involved_entities`, `timeline`, `recommended_actions` as JSON TEXT

## Report Generation

```
GET /incidents/{id}/report.md
  ↓
  storage.get_incident(id)
  storage.get_alerts_for_incident(alert_ids)
  ↓
  report_service.generate_markdown_report(incident, alerts)
  ← Plain text Markdown response

GET /incidents/{id}/report.json
  ↓
  report_service.generate_json_report(incident, alerts)
  ← { schema_version, generated_at, incident, alerts }
```
