# PRD — Mini SIEM Detection Lab

## Problem

In SOC and SIEM teams, a junior analyst needs to understand not just individual log lines but the full event flow: from a log source, through normalization, detection rules, alert severity, grouping, triage, incident report, and follow-up recommendations. Most portfolio projects demonstrate parsing or scripting but skip the pipeline architecture and analyst lifecycle.

## Goal

Build a reproducible lab that demonstrates:
- Unified event ingestion pipeline (4 sources)
- Normalized event model
- Rule-based detection engine (10 rules, YAML-configurable)
- Alert generation with evidence and recommendations
- Incident grouping by shared entity (IP, host)
- FastAPI backend with SQLite persistence
- CLI tool for ingestion, triage, and export
- Synthetic log datasets covering Linux, Nginx, Windows, and Cloud
- Markdown and JSON incident reports
- pytest test suite (113 tests)
- GitHub Actions CI

## Non-Goals

- Not a production SIEM
- Not a replacement for Wazuh / MaxPatrol SIEM / KUMA / Splunk / ELK
- Not a real-time distributed streaming system
- Not a threat intelligence platform
- Not an ML or UEBA anomaly detection system
- Not agent-based log collection
- Not an EDR, DLP, PAM, NGFW, or WAF
- Not a legal or compliance product

## Target Hiring Signals

| Signal | Implementation |
|---|---|
| Python backend | FastAPI, services, Pydantic v2 |
| API design | 9 endpoints with typed request/response |
| Data modeling | Event / Alert / Incident with Pydantic v2 |
| Testing discipline | 113 tests, ASGITransport, tmp_path isolation |
| CI/CD | GitHub Actions CI |
| Observability | Structured JSON logging, normalized event messages |
| Security engineering | 10 detection rules, triage lifecycle |
| SOC workflow | Alert status transitions, incident grouping |
| Linux/logs | linux_auth and nginx_access parsers |
| Windows event awareness | Windows Security Event IDs (4624/4625/4672/4688/4720) |
| Cloud security awareness | Cloud audit events with IAM and SG rules |
| Documentation | PRD, architecture, QA, playbook, limitations |
| Maintainability | Makefile, pyproject.toml, CONTRIBUTING, developer guide |

## Primary Use Cases

1. User runs `make demo` to ingest all sample logs and see summary output.
2. User runs `python -m cli.main ingest` to ingest a specific source file.
3. Events are normalized to unified Event model.
4. Detection rules produce Alert objects with evidence and recommendations.
5. Alerts are grouped into Incidents with timeline and entity tracking.
6. Analyst lists alerts and incidents via CLI or FastAPI.
7. Analyst updates alert status via `PATCH /alerts/{id}/status`.
8. Analyst exports incident report as Markdown or JSON.
9. Documentation explains the analyst triage process.

## Success Criteria

- Project starts locally in under 5 minutes (`make install && make demo`)
- All 113 tests pass with `make test`
- CI passes on GitHub Actions
- README clearly explains the SOC workflow
- 10 detection rules implemented
- 4 log sources simulated
- Markdown and JSON reports supported
- No real external network required
- No private credentials anywhere in the repo
