from contextlib import asynccontextmanager

from fastapi import FastAPI

from app.api import routes_alerts, routes_events, routes_health, routes_incidents
from app.core.config import settings
from app.core.logging import configure_logging
from app.db.database import init_db


@asynccontextmanager
async def lifespan(app: FastAPI):
    configure_logging()
    init_db(app.state.db_path)
    yield


def create_app(db_path: str | None = None, rules_path: str | None = None) -> FastAPI:
    app = FastAPI(
        title="Mini SIEM Detection Lab",
        description="Lab-grade SIEM-like detection pipeline: log ingestion, normalization, rules, alerts, incidents.",
        version="1.0.0",
        lifespan=lifespan,
    )
    app.state.db_path = db_path or settings.db_path
    app.state.rules_path = rules_path or settings.rules_path

    app.include_router(routes_health.router)
    app.include_router(routes_events.router)
    app.include_router(routes_alerts.router)
    app.include_router(routes_incidents.router)

    return app


app = create_app()
