# Limitations

This is a lab and portfolio project. The following limitations are intentional or known.

## Data

- All log data is synthetic. No real systems, networks, or credentials are involved.
- Sample logs use documentation IP ranges (RFC 5737): 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24.
- Windows security events are simulated as JSONL, not collected from a real Windows system.
- Cloud audit events are synthetic and not connected to any cloud provider account.

## Detection Logic

- Detection rules use static thresholds over the full event set — there is no real-time sliding time window.
- Rules are purely heuristic and rule-based. No ML, anomaly detection, or UEBA.
- Correlation is based on exact source IP matching. No entity resolution or alias detection.
- Multi-source correlation only triggers when alerts exist from prior single-source rules.
- No threat intelligence enrichment (no IP reputation, no IOC feeds).

## Storage

- SQLite is used for simplicity. Not designed for concurrent multi-user access or high-volume ingestion.
- No data migration tooling beyond schema.sql init. Schema changes require `reset_db.py`.
- Raw event data and JSON fields are stored as TEXT columns.

## API

- No authentication or authorization. API is intended for local lab use only.
- No rate limiting or request queuing.
- All endpoints are synchronous (FastAPI sync routes wrapping synchronous SQLite).

## Deployment

- Not designed for production deployment.
- No HTTPS, no reverse proxy configuration, no multi-worker setup.
- No Docker Compose for the API (Docker is optional for future use).

## What This Is Not

- Not a SIEM replacement (Wazuh, MaxPatrol SIEM, KUMA, Splunk, ELK).
- Not a real-time streaming platform (Kafka, Flink, Logstash).
- Not an agent-based collector (Beats, Fluentd, Osquery).
- Not an EDR, DLP, PAM, NGFW, WAF, or KSC.
- Not a legal or compliance tool.
- Not a threat hunting platform.
