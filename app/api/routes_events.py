from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request

from app.models.schemas import IngestionResult, RawLogIngestion
from app.services.detection_engine import load_rules, run_detections
from app.services.incident_grouping_service import group_alerts
from app.services.normalization_service import normalize_linux_auth_line, normalize_nginx_line, normalize_windows_json, normalize_cloud_json
from app.services.storage_service import StorageService
from app.models.schemas import SourceType

import json

router = APIRouter(prefix="/events", tags=["events"])


def _get_storage(request: Request) -> StorageService:
    return StorageService(request.app.state.db_path)


def _get_rules(request: Request) -> dict:
    return load_rules(request.app.state.rules_path)


@router.post("/ingest", response_model=IngestionResult)
def ingest_events(body: RawLogIngestion, request: Request) -> IngestionResult:
    storage = _get_storage(request)
    rules = _get_rules(request)

    lines = body.content.splitlines()
    events = []
    skipped = 0

    for line in lines:
        line = line.strip()
        if not line:
            skipped += 1
            continue
        try:
            if body.source_type == SourceType.linux_auth:
                ev = normalize_linux_auth_line(line)
            elif body.source_type == SourceType.nginx_access:
                ev = normalize_nginx_line(line)
            elif body.source_type == SourceType.windows_security:
                ev = normalize_windows_json(json.loads(line))
            elif body.source_type == SourceType.cloud_audit:
                ev = normalize_cloud_json(json.loads(line))
            else:
                ev = None
            if ev:
                events.append(ev)
            else:
                skipped += 1
        except Exception:
            skipped += 1

    storage.insert_events(events)
    alerts = run_detections(events, rules)
    storage.insert_alerts(alerts)
    incidents = group_alerts(alerts, events)
    storage.insert_incidents(incidents)

    return IngestionResult(
        events_ingested=len(events),
        skipped=skipped,
        alerts_created=len(alerts),
        incidents_created=len(incidents),
    )


@router.get("/")
def list_events(request: Request, limit: int = 100, source_type: str | None = None) -> list[dict]:
    storage = _get_storage(request)
    return storage.list_events(limit=limit, source_type=source_type)
