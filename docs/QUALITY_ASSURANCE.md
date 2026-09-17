# Quality Assurance

## Test Summary

| Category | Tests | Notes |
|---|---|---|
| Normalization | 34 | Linux auth, Nginx, Windows, Cloud, PostgreSQL parsers; malformed lines; file-level ingestion |
| Detection engine | 56 | All 14 rules; threshold boundaries; severity escalation; multi-source correlation |
| Incident grouping | 9 | IP grouping; severity escalation; timeline; entity collection; score cap |
| Storage service | 15 | Insert/list/update; DB isolation via tmp_path; incident-id numbering |
| API (events) | 8 | Health, ingest, list; filter by source_type |
| API (alerts + incidents) | 13 | Alert/incident list, status update, report MD/JSON |
| CLI | 6 | Demo, ingest, report export; sequential-ingest incident-id uniqueness |
| Report service | 16 | Markdown sections, JSON structure, no-AI-trace check |
| Sigma rules | 43 | Sigma files parse; required fields, UUID id, valid level, detection condition, ATT&CK tags |
| **Total** | **200** | |

## Test Patterns

### API tests — no real server required

All API tests use `httpx.ASGITransport` and `AsyncClient`. No actual HTTP server is started.

```python
@pytest.fixture()
async def client(app):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        yield c
```

### Database isolation per test

Each test that touches the database gets a fresh SQLite file via `tmp_path`:

```python
@pytest.fixture()
def db_path(tmp_path: Path) -> str:
    path = str(tmp_path / "test.db")
    init_db(path)
    return path
```

No committed `.db` files in the repository.

### Detection engine tests — deterministic synthetic data

Detection tests build events programmatically with known fields and exact counts, ensuring deterministic threshold testing:

```python
events = [Event(event_id=f"ev-{i}", source_ip="192.0.2.10", action="ssh_failed_password", ...) for i in range(10)]
alerts = run_detections(events, rules)
assert alerts[0].severity == AlertSeverity.medium
```

### Incident counter reset

`group_alerts` uses a global counter to produce deterministic INC-XXXX IDs. Tests that depend on incident IDs call `reset_incident_counter()` via an `autouse` fixture:

```python
@pytest.fixture(autouse=True)
def reset():
    reset_incident_counter()
    yield
    reset_incident_counter()
```

## What Is Not Tested

- Real-time time window detection (lab uses full-dataset window)
- Multi-user concurrent access (SQLite, single-threaded)
- Network failures or database corruption
- Very large log files (memory pressure, performance)
- Frontend (no frontend in this project)
- Real cloud/Windows systems

## Running Tests

```bash
make test
# or
.venv/bin/pytest tests/ -v
```

## CI

GitHub Actions runs the full test suite on every push and pull request to `main`.
See `.github/workflows/ci.yml`.
