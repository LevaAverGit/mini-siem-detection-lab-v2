# BigTech Skills Mapping

Demonstrates junior/junior+ readiness for security tooling, SOC automation, and Python backend tasks.

| Competency | Where demonstrated | Evidence |
|---|---|---|
| Python backend | FastAPI app, 6 service modules, Pydantic v2 | `app/main.py`, `app/services/` |
| API design | 9 typed endpoints, request/response validation, error handling | `app/api/`, `docs/API_OVERVIEW.md` |
| Data modeling | Event / Alert / Incident / InvolvedEntities / TimelineEntry | `app/models/schemas.py` |
| Testing discipline | 113 tests, ASGITransport, tmp_path DB isolation, 0 warnings | `tests/`, `docs/QUALITY_ASSURANCE.md` |
| CI/CD | GitHub Actions: checkout, Python 3.11 setup, pytest, ruff | `.github/workflows/ci.yml` |
| Observability thinking | Structured JSON logging, normalized event messages | `app/core/logging.py`, `normalized_message` field |
| Security engineering | 9 detection rules, severity scoring, evidence, recommendations | `app/services/detection_engine.py` |
| MITRE ATT&CK awareness | Rule-level MITRE tactic/technique mapping with direct/approximate confidence labels | `app/rules/default_rules.yml`, `docs/DETECTION_RULES.md` |
| SOC workflow | Alert status lifecycle (new → triaged → escalated → closed), incident grouping | `app/api/routes_alerts.py`, `incident_grouping_service.py` |
| Linux/logs | Linux auth log parser (regex), Nginx combined log parser | `normalization_service.py` |
| Windows event awareness | Windows Security Event IDs 4624/4625/4672/4688/4720 simulated | `sample_logs/windows_security.jsonl`, `normalize_windows_json()` |
| Cloud security awareness | Cloud IAM, security group rules, console login events | `sample_logs/cloud_audit.jsonl`, cloud detection rules |
| Configuration management | YAML-driven detection rules, env-based settings via pydantic-settings | `app/rules/default_rules.yml`, `app/core/config.py` |
| Documentation | PRD, architecture, data flow, detection rules, playbook, QA, limitations | `docs/` |
| Maintainability | Makefile, pyproject.toml, .editorconfig, ruff | root config files |
| CLI tooling | 5 CLI subcommands: ingest, demo, alerts list, incidents list, report | `cli/main.py` |
| Report generation | Markdown + JSON incident reports with timeline, evidence, recommendations | `app/services/report_service.py` |

## Notes

This project intentionally avoids overclaiming:

- No ML or AI-based detection — all rules are deterministic and auditable
- Stated as a lab project, not a production system
- Limitations are documented honestly in `docs/LIMITATIONS.md`
- All claims about detection accuracy are scoped to synthetic sample data

The skills above are demonstrated at junior/junior+ level: the architecture is intentional,
the code is testable and maintainable, and trade-offs are documented.
