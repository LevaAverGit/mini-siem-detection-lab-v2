from __future__ import annotations

from fastapi import APIRouter, Request

from app.models.schemas import IngestionResult, RawLogIngestion
from app.services.ingestion_service import ingest_text
from app.services.storage_service import StorageService

router = APIRouter(prefix="/events", tags=["events"])


def _get_storage(request: Request) -> StorageService:
    return StorageService(request.app.state.db_path)


@router.post("/ingest", response_model=IngestionResult)
def ingest_events(body: RawLogIngestion, request: Request) -> IngestionResult:
    return ingest_text(
        body.content,
        body.source_type,
        request.app.state.db_path,
        request.app.state.rules_path,
    )


@router.get("/")
def list_events(request: Request, limit: int = 100, source_type: str | None = None) -> list[dict]:
    return _get_storage(request).list_events(limit=limit, source_type=source_type)
