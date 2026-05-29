from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import PlainTextResponse, JSONResponse

from app.services.report_service import generate_json_report, generate_markdown_report
from app.services.storage_service import StorageService

router = APIRouter(prefix="/incidents", tags=["incidents"])


def _get_storage(request: Request) -> StorageService:
    return StorageService(request.app.state.db_path)


@router.get("/")
def list_incidents(
    request: Request,
    status: str | None = None,
    severity: str | None = None,
) -> list[dict]:
    return _get_storage(request).list_incidents(status=status, severity=severity)


@router.get("/{incident_id}")
def get_incident(incident_id: str, request: Request) -> dict:
    incident = _get_storage(request).get_incident(incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail=f"Incident {incident_id} not found")
    return incident


@router.get("/{incident_id}/report.md", response_class=PlainTextResponse)
def get_incident_report_md(incident_id: str, request: Request) -> str:
    storage = _get_storage(request)
    incident = storage.get_incident(incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail=f"Incident {incident_id} not found")
    alert_ids = incident.get("alert_ids", [])
    alerts = storage.get_alerts_for_incident(alert_ids)
    return generate_markdown_report(incident, alerts)


@router.get("/{incident_id}/report.json")
def get_incident_report_json(incident_id: str, request: Request) -> dict:
    storage = _get_storage(request)
    incident = storage.get_incident(incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail=f"Incident {incident_id} not found")
    alert_ids = incident.get("alert_ids", [])
    alerts = storage.get_alerts_for_incident(alert_ids)
    return generate_json_report(incident, alerts)
