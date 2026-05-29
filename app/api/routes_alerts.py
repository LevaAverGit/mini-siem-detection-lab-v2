from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request

from app.models.schemas import AlertStatus, AlertStatusUpdate
from app.services.storage_service import StorageService

router = APIRouter(prefix="/alerts", tags=["alerts"])


def _get_storage(request: Request) -> StorageService:
    return StorageService(request.app.state.db_path)


@router.get("/")
def list_alerts(
    request: Request,
    status: str | None = None,
    severity: str | None = None,
) -> list[dict]:
    return _get_storage(request).list_alerts(status=status, severity=severity)


@router.patch("/{alert_id}/status")
def update_alert_status(
    alert_id: str, body: AlertStatusUpdate, request: Request
) -> dict:
    storage = _get_storage(request)
    updated = storage.update_alert_status(alert_id, body.status)
    if not updated:
        raise HTTPException(status_code=404, detail=f"Alert {alert_id} not found")
    return {"alert_id": alert_id, "status": body.status.value}
