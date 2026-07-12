# Mini SIEM Detection Lab

[![CI](https://github.com/LevaAverGit/mini-siem-detection-lab-v2/actions/workflows/ci.yml/badge.svg)](https://github.com/LevaAverGit/mini-siem-detection-lab-v2/actions/workflows/ci.yml)

A lab-grade detection pipeline that simulates a SOC monitoring workflow:
event source → log ingestion → normalization → detection rules → alerts → incident grouping → report → analyst playbook.

Built to demonstrate Python backend, security engineering, and SOC workflow skills. Not a production SIEM.

---

## What This Project Demonstrates

- **Event pipeline design** — four log sources → unified normalized Event model → detection engine → alert/incident lifecycle
- **FastAPI backend** — ingest, list, triage, and report endpoints with Pydantic v2 models throughout
- **Detection rule engine** — 10 rules loaded from YAML, deterministic, no ML or external API
- **Incident grouping** — alerts correlated by shared source IP into incidents with timeline and entity tracking
- **SQLite persistence** — schema-first init, per-test isolation via `tmp_path`
- **CLI tool** — `ingest`, `demo`, `alerts list`, `incidents list`, `incidents report` commands
- **132 tests, 0 warnings** — unit tests for each service layer, API tests via `httpx.ASGITransport`
- **Structured reporting** — Markdown and JSON incident reports

---

## Architecture

```
Log Sources (4)                   Detection Engine
  linux_auth.log ─┐               ┌── SSH Brute Force (threshold-based)
  nginx_access.log┤               ├── Brute Force Success
  windows_sec.jsonl─► Normalize ──► ├── Web Dir Scanning
  cloud_audit.jsonl┘  (Event)    ├── Sensitive Path Access
                                  ├── Suspicious User Agent
                                  ├── Web Exploit Attempt (T1190)
POST /events/ingest               ├── Windows Account Created
  ↓                               ├── Cloud SG Opened to 0.0.0.0/0
Normalization Service             ├── IAM Change After Login Failure
  ↓                               └── Multi-Source Suspicious IP
Detection Engine (10 rules)
  ↓                              Storage
Alert List                          SQLite (events / alerts / incidents)
  ↓
Incident Grouping (by source_ip)
  ↓
Incident + Timeline
  ↓
Report (Markdown / JSON)
```

---

## Quickstart

```bash
# Install
python3.11 -m venv .venv && .venv/bin/pip install -r requirements-dev.txt

# Or with make
make install

# Run all tests
make test

# Run full demo (ingest all sample logs, show results)
make demo
```

---

## Demo

```
$ make demo

============================================================
Mini SIEM Detection Lab — Demo Run
============================================================
  Ingested  128 events from sample_logs/linux_auth.log
  Ingested  139 events from sample_logs/nginx_access.log
  Ingested   12 events from sample_logs/windows_security.jsonl
  Ingested    8 events from sample_logs/cloud_audit.jsonl

Total events ingested : 287
Total skipped         : 0
Alerts generated      : 121
Incidents created     : 9

Alert breakdown by severity:
  CRITICAL:  3
  HIGH    : 21
  MEDIUM  : 97

Incidents:
  [INC-0003] [CRITICAL] Critical Incident — 203.0.113.99
  [INC-0008] [CRITICAL] Critical Incident — 203.0.113.10
  [INC-0005] [HIGH]     High Incident — 198.51.100.77
  ...
```

---

## API Overview

| Endpoint | Method | Description |
|---|---|---|
| `/health` | GET | Liveness check |
| `/events/ingest` | POST | Ingest raw log content |
| `/events/` | GET | List events (filter: `source_type`, `limit`) |
| `/alerts/` | GET | List alerts (filter: `status`, `severity`) |
| `/alerts/{id}/status` | PATCH | Update alert triage status |
| `/incidents/` | GET | List incidents (filter: `status`, `severity`) |
| `/incidents/{id}` | GET | Get incident detail |
| `/incidents/{id}/report.md` | GET | Markdown report |
| `/incidents/{id}/report.json` | GET | JSON report |

See `docs/API_OVERVIEW.md` for request/response examples.

**Start the API:**
```bash
make run-api
# FastAPI available at http://127.0.0.1:8000
# Docs at http://127.0.0.1:8000/docs
```

---

## CLI Usage

```bash
# Ingest a log file
python -m cli.main ingest --source linux_auth --file sample_logs/linux_auth.log

# Run full demo
python -m cli.main demo

# List alerts
python -m cli.main alerts list

# List incidents
python -m cli.main incidents list

# Export incident report
python -m cli.main incidents report --id INC-0001 --format md --output reports/INC-0001.md
python -m cli.main incidents report --id INC-0001 --format json
```

---

## Detection Rules

| Rule ID | Source | Logic | Severity | MITRE Technique |
|---|---|---|---|---|
| `SSH_BRUTE_FORCE` | linux_auth | >= 10/30/100 failed SSH logins from same IP | medium/high/critical | T1110.001 |
| `SSH_BRUTE_FORCE_SUCCESS` | linux_auth | Same IP: >= 5 failures then accepted login | critical | T1078 |
| `WEB_DIR_SCAN` | nginx_access | >= 30/80 HTTP 404s from same IP | medium/high | T1595.002 |
| `SENSITIVE_PATH_ACCESS` | nginx_access | Access to /.env, /.git, /admin, /phpmyadmin | medium/high | T1083 |
| `SUSPICIOUS_USER_AGENT` | nginx_access | sqlmap, nikto, gobuster, masscan, dirbuster | medium/high | T1595 |
| `WEB_EXPLOIT_ATTEMPT` | nginx_access | SQLi / traversal / Log4Shell / cmd-injection / XSS signatures in decoded path or UA | high | T1190 |
| `WIN_ACCOUNT_CREATED_AFTER_FAILURES` | windows_security | 4720 follows multiple 4625 on same host | high | T1136.001 |
| `CLOUD_SG_OPEN` | cloud_audit | SG rule 0.0.0.0/0 on port 22/3389/5432/3306 | high/critical | T1562.007 |
| `CLOUD_IAM_CHANGE_AFTER_FAILURE` | cloud_audit | IAM policy change by user with recent login failures | high | T1098 |
| `MULTI_SOURCE_SUSPICIOUS_IP` | all | Same IP in suspicious events across 2+ source types | critical | Multiple |

All rules are configurable via `app/rules/default_rules.yml`. Each rule includes a MITRE ATT&CK tactic, technique, and mapping confidence (`direct` or `approximate`). See `docs/DETECTION_RULES.md` for per-rule mapping notes.

---

## Sigma-Style Rules

The `sigma_rules/` directory contains Sigma-format YAML examples that map the lab's detection logic to the [Sigma](https://sigmahq.io/) open standard:

| Sigma rule file | Lab rule mapped | MITRE technique |
|---|---|---|
| `sigma_rules/ssh_brute_force.yml` | SSH_BRUTE_FORCE | T1110.001 |
| `sigma_rules/web_path_traversal_scan.yml` | WEB_DIR_SCAN, SENSITIVE_PATH_ACCESS, SUSPICIOUS_USER_AGENT | T1595.002, T1083, T1595 |
| `sigma_rules/web_exploit_attempt.yml` | WEB_EXPLOIT_ATTEMPT | T1190 |
| `sigma_rules/windows_failed_logons_account_creation.yml` | WIN_ACCOUNT_CREATED_AFTER_FAILURES | T1136.001, T1078 |

> **Note:** These are Sigma-style examples for educational and portfolio purposes. They illustrate how custom detection rules can be expressed in an industry-standard format. The lab uses its own YAML rule loader (`app/rules/default_rules.yml`) rather than a full Sigma engine.

---

## Example Incident Report

`reports/example_incident_report.md` contains a synthetic SOC analyst incident report demonstrating the output format for an SSH brute-force-with-compromise scenario:

- Full timeline from first failed login to successful compromise
- MITRE ATT&CK tactic/technique chain (T1110.001 → T1078)
- Evidence from correlated rules
- Recommended response steps
- False positive assessment

---

## Sample Incident Workflow

```
1. Ingest logs
   python -m cli.main ingest --source linux_auth --file sample_logs/linux_auth.log

2. Run the rest
   python -m cli.main ingest --source nginx_access --file sample_logs/nginx_access.log
   python -m cli.main ingest --source windows_security --file sample_logs/windows_security.jsonl
   python -m cli.main ingest --source cloud_audit --file sample_logs/cloud_audit.jsonl

3. Review incidents
   python -m cli.main incidents list

4. Export report
   python -m cli.main incidents report --id INC-0001 --format md --output reports/report.md

5. Triage alert (via API)
   curl -X PATCH http://127.0.0.1:8000/alerts/{alert_id}/status \
     -H "Content-Type: application/json" \
     -d '{"status": "triaged"}'
```

---

## Tests

```bash
make test    # 124 tests
```

| Test module | Coverage |
|---|---|
| `test_normalization.py` | Linux auth, Nginx, Windows, Cloud parsers; malformed lines; file-level ingestion |
| `test_detection_engine.py` | All 10 rules; threshold boundaries; severity escalation; multi-source correlation |
| `test_incident_grouping.py` | IP grouping; severity escalation; timeline; entity collection; score cap |
| `test_storage_service.py` | Insert/list/update for events/alerts/incidents; DB isolation via `tmp_path` |
| `test_api_events.py` | Health, ingest, list endpoints; source_type filter |
| `test_api_alerts.py` | Alert list, status update, incidents list, report MD/JSON |
| `test_cli.py` | Demo, ingest, report export |
| `test_report_service.py` | Markdown sections, JSON structure, AI trace check |

---

## Project Structure

```
mini-siem-detection-lab/
├── app/
│   ├── main.py                    FastAPI app factory, lifespan
│   ├── api/
│   │   ├── routes_events.py       POST /events/ingest, GET /events/
│   │   ├── routes_alerts.py       GET/PATCH /alerts/
│   │   ├── routes_incidents.py    GET /incidents/, reports
│   │   └── routes_health.py       GET /health
│   ├── core/
│   │   ├── config.py              pydantic-settings (SIEM_ prefix)
│   │   └── logging.py             Structured JSON logging
│   ├── db/
│   │   ├── database.py            SQLite connection, init_db
│   │   └── schema.sql             CREATE TABLE statements
│   ├── models/
│   │   └── schemas.py             Event, Alert, Incident, Pydantic v2
│   ├── services/
│   │   ├── normalization_service.py   4 source parsers → unified Event
│   │   ├── detection_engine.py        10 detection rules → Alert list
│   │   ├── incident_grouping_service.py  Alert → Incident (by IP)
│   │   ├── storage_service.py         SQLite CRUD
│   │   ├── report_service.py          Markdown + JSON report generation
│   │   └── ingestion_service.py       File-level ingest orchestration
│   └── rules/
│       └── default_rules.yml      Detection rule thresholds and config
├── cli/
│   └── main.py                    CLI: ingest, demo, alerts, incidents
├── sample_logs/
│   ├── linux_auth.log             129 synthetic Linux auth events
│   ├── nginx_access.log           118 synthetic Nginx access events
│   ├── windows_security.jsonl     12 synthetic Windows Security events
│   └── cloud_audit.jsonl          8 synthetic cloud audit events
├── tests/                         124 tests
├── docs/                          11 documentation files
├── .github/workflows/ci.yml       GitHub Actions CI
├── Makefile
├── pyproject.toml
└── requirements.txt
```

---

## What This Is Not

- Not a production SIEM
- Not a replacement for Wazuh, MaxPatrol SIEM, KUMA, Splunk, or ELK
- Not a real-time distributed event processing system
- Not an ML/UEBA anomaly detection system
- Not an EDR, DLP, PAM, or NGFW
- Not agent-based log collection
- Not a legal compliance product

---

## Limitations

See `docs/LIMITATIONS.md` for a full list. Key points:

- All data is synthetic — no real systems are involved
- Detection rules use static thresholds without time-windowing
- Single-threaded processing — not designed for high-volume ingestion
- No authentication on API endpoints (local lab use only)
- No real-time streaming

---

## Skills Demonstrated

See `docs/BIGTECH_SKILLS_MAPPING.md` for a full competency mapping
and `docs/SOC_INTERVIEW_DEFENSE.md` for interview talking points and scope.

Demonstrates junior/junior+ readiness for security tooling, SOC automation, and Python backend tasks:

- Python 3.11, FastAPI, Pydantic v2, SQLite, pytest
- Event-driven pipeline thinking
- Detection rule engineering with rule-level MITRE ATT&CK mapping (direct/approximate confidence)
- SOC alert lifecycle (new → triaged → escalated → closed)
- Structured Markdown and JSON reporting
- CLI tool design
- Test isolation with `tmp_path` and `ASGITransport`

---

## License

MIT
