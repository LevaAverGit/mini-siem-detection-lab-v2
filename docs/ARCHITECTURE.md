# Architecture

## Overview

Mini SIEM Detection Lab is a single-process Python application. It has no background workers,
no message queue, and no real-time streaming — all of which are documented limitations.

The core pipeline is synchronous and stateless: given a batch of events, the detection engine
produces a deterministic set of alerts. This design makes the pipeline easy to test and reason about.

## Components

```
┌───────────────────────────────────────────────────────┐
│                     Log Sources (4)                   │
│  linux_auth.log | nginx_access.log | *.jsonl files    │
└───────────────────────────┬───────────────────────────┘
                            │ raw text / JSONL
                            ▼
┌───────────────────────────────────────────────────────┐
│              Normalization Service                    │
│  4 parsers: regex (Linux/Nginx) + JSON (Win/Cloud)    │
│  Output: List[Event] — unified model, all sources     │
└───────────────────────────┬───────────────────────────┘
                            │ List[Event]
                            ▼
┌───────────────────────────────────────────────────────┐
│              Detection Engine                         │
│  Loads rules from default_rules.yml                   │
│  9 rule functions → List[Alert]                       │
│  Each alert: rule_id, severity, score, evidence       │
└───────────────────────────┬───────────────────────────┘
                            │ List[Alert]
                            ▼
┌───────────────────────────────────────────────────────┐
│              Incident Grouping                        │
│  Group alerts by shared source_ip                     │
│  Build timeline, collect entities, escalate severity  │
│  Output: List[Incident]                               │
└───────────────────────────┬───────────────────────────┘
                            │ List[Incident]
                            ▼
┌───────────────────────────────────────────────────────┐
│              Storage Service (SQLite)                 │
│  3 tables: events, alerts, incidents                  │
│  JSON fields stored as TEXT, deserialized on read     │
└───────────────────────────┬───────────────────────────┘
                            │
             ┌──────────────┼──────────────┐
             ▼              ▼              ▼
         FastAPI          CLI          Report Service
         API (9 ep)    (5 commands)  (MD + JSON export)
```

## Design Decisions

### synchronous SQLite over aiosqlite

The project uses `sqlite3` (synchronous) rather than `aiosqlite`. The rationale:

- This is a single-user lab, not a multi-user service
- No concurrent writes require async I/O benefits
- Synchronous code is simpler to read and test
- FastAPI runs sync route handlers in a thread pool, so blocking is acceptable here

If the project scaled to concurrent multi-user API, the migration path would be `aiosqlite` + `asyncio.Lock`.

### Rule-based detection over ML

All detection uses static thresholds defined in YAML. No ML, no anomaly detection.

Reasons:
- Deterministic: tests produce the same result every run
- Auditable: each rule is readable and explainable
- Appropriate scope: lab-scale datasets do not justify ML overhead
- Hiring signal: rule engineering is a core SOC/detection skill

### Batch detection over streaming

Detection runs over all events in the current batch. No real-time sliding window.

Reasons:
- Simplifies state management
- Appropriate for log file ingestion (not Kafka streams)
- Documented honestly as a limitation

### IP-based incident grouping

Alerts are grouped into incidents primarily by `source_ip`. Alerts without an IP are grouped by `rule_id`.

This is a simple but useful heuristic for single-attacker scenarios. It does not handle:
- NAT or proxy scenarios where many users share an IP
- Multi-IP attackers using rotating proxies
These are documented as limitations.

### Flat service modules over class hierarchy

Each service is a module with functions, not a class hierarchy. Reasons:
- Easier to test individual functions in isolation
- No shared state between calls (rules loaded per call or passed as argument)
- Appropriate scale — no need for dependency injection or service locator patterns
