from __future__ import annotations

from app.models.schemas import IngestionResult, SourceType
from app.services.detection_engine import load_rules, run_detections
from app.services.incident_grouping_service import group_alerts
from app.services.normalization_service import normalize_file
from app.services.storage_service import StorageService


def ingest_file(
    path: str,
    source_type: SourceType,
    db_path: str,
    rules_path: str,
) -> IngestionResult:
    storage = StorageService(db_path)

    parse_result = normalize_file(path, source_type)
    events = parse_result.events

    storage.insert_events(events)

    rules = load_rules(rules_path)
    alerts = run_detections(events, rules)
    storage.insert_alerts(alerts)

    incidents = group_alerts(alerts, events)
    storage.insert_incidents(incidents)

    return IngestionResult(
        events_ingested=len(events),
        skipped=parse_result.skipped_count,
        alerts_created=len(alerts),
        incidents_created=len(incidents),
    )


def ingest_text(
    content: str,
    source_type: SourceType,
    db_path: str,
    rules_path: str,
) -> IngestionResult:
    import json
    import tempfile
    import os

    suffix = ".jsonl" if source_type in (SourceType.windows_security, SourceType.cloud_audit) else ".log"
    with tempfile.NamedTemporaryFile(mode="w", suffix=suffix, delete=False, encoding="utf-8") as f:
        f.write(content)
        tmp_path = f.name

    try:
        return ingest_file(tmp_path, source_type, db_path, rules_path)
    finally:
        os.unlink(tmp_path)
