from __future__ import annotations

from app.models.schemas import IngestionResult, ParseResult, SourceType
from app.services.detection_engine import load_rules, run_detections
from app.services.incident_grouping_service import group_alerts, set_incident_counter
from app.services.normalization_service import normalize_content, normalize_file
from app.services.storage_service import StorageService


def _run_pipeline(
    parse_result: ParseResult, db_path: str, rules_path: str
) -> IngestionResult:
    storage = StorageService(db_path)
    events = parse_result.events
    storage.insert_events(events)

    rules = load_rules(rules_path)
    alerts = run_detections(events, rules)
    storage.insert_alerts(alerts)

    # Continue incident numbering from what is already stored. Ingesting sources
    # in separate runs otherwise reuses INC-0001.. and INSERT OR IGNORE silently
    # drops the colliding incidents.
    set_incident_counter(storage.max_incident_number())
    incidents = group_alerts(alerts, events)
    storage.insert_incidents(incidents)

    return IngestionResult(
        events_ingested=len(events),
        skipped=parse_result.skipped_count,
        alerts_created=len(alerts),
        incidents_created=len(incidents),
    )


def ingest_file(
    path: str, source_type: SourceType, db_path: str, rules_path: str
) -> IngestionResult:
    return _run_pipeline(normalize_file(path, source_type), db_path, rules_path)


def ingest_text(
    content: str, source_type: SourceType, db_path: str, rules_path: str
) -> IngestionResult:
    return _run_pipeline(normalize_content(content, source_type), db_path, rules_path)
