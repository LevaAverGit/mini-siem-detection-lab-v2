# Developer Guide

## Setup

```bash
python3.11 -m venv .venv && .venv/bin/pip install -r requirements-dev.txt
# or
make install
```

## Common Commands

```bash
make test          # run 113 pytest tests
make demo          # ingest all sample logs, show summary
make run-api       # FastAPI on 127.0.0.1:8000
make lint          # ruff check (non-blocking)
make clean         # remove .venv, __pycache__, .db files
```

## Project Structure

```
app/
  main.py                    create_app() factory, lifespan, router mounts
  api/
    routes_events.py         POST /events/ingest, GET /events/
    routes_alerts.py         GET /alerts/, PATCH /alerts/{id}/status
    routes_incidents.py      GET /incidents/, /{id}, /{id}/report.md, /{id}/report.json
    routes_health.py         GET /health
  core/
    config.py                SIEM_ env var settings via pydantic-settings
    logging.py               Structured JSON logger
  db/
    database.py              get_connection(), init_db()
    schema.sql               CREATE TABLE events/alerts/incidents
  models/
    schemas.py               Event, Alert, Incident, Pydantic v2
  services/
    normalization_service.py 4 parsers → Event
    detection_engine.py      load_rules(), run_detections() → List[Alert]
    incident_grouping_service.py  group_alerts() → List[Incident]
    storage_service.py       StorageService: insert/list/update
    report_service.py        generate_markdown_report(), generate_json_report()
    ingestion_service.py     ingest_file() orchestration helper
  rules/
    default_rules.yml        10 detection rules with thresholds and metadata
cli/
  main.py                    argparse CLI: ingest/demo/alerts/incidents
tests/
  conftest.py                db_path, client, app fixtures
  test_normalization.py
  test_detection_engine.py
  test_incident_grouping.py
  test_storage_service.py
  test_api_events.py
  test_api_alerts.py
  test_cli.py
  test_report_service.py
```

## Adding a New Detection Rule

1. Add rule definition to `app/rules/default_rules.yml`
2. Add a detection function `_detect_<rule_name>(events, rule)` in `detection_engine.py`
3. Call it from `run_detections()` with the rule_id as key
4. Add tests in `tests/test_detection_engine.py`
5. Document the rule in `docs/DETECTION_RULES.md`
6. Add triage guidance to `docs/INCIDENT_TRIAGE_PLAYBOOK.md`
7. Run `make test`

## Adding a New Log Source

1. Add `source_type` value to `SourceType` enum in `app/models/schemas.py`
2. Add `normalize_<source>_line()` function in `normalization_service.py`
3. Wire it into `normalize_file()` and the API ingest handler
4. Add sample log file to `sample_logs/`
5. Add tests in `test_normalization.py`
6. Update `cli/main.py` demo with the new source

## Debugging

Run the demo with a custom DB to inspect results:

```bash
SIEM_DB_PATH=debug.db python -m cli.main demo
.venv/bin/python -c "
from app.services.storage_service import StorageService
s = StorageService('debug.db')
for inc in s.list_incidents():
    print(inc['incident_id'], inc['severity'], inc['title'])
"
```

Run a specific test:

```bash
.venv/bin/pytest tests/test_detection_engine.py::TestSSHBruteForce::test_critical_threshold -v
```

## Module Relationships

```
routes_events.py
  ↓ calls
  normalization_service.py    ← parse raw log to Event
  detection_engine.py         ← run rules, produce Alert list
  incident_grouping_service.py ← group Alerts into Incidents
  storage_service.py           ← persist to SQLite

routes_incidents.py
  ↓ calls
  storage_service.py
  report_service.py            ← generate MD/JSON from incident + alerts

models/schemas.py              ← shared Pydantic models
db/database.py                 ← connection and init, used by storage_service
core/config.py                 ← settings used by main.py and storage_service
```
