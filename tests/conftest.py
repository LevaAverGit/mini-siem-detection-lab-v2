import pytest
from pathlib import Path
from httpx import ASGITransport, AsyncClient

from app.db.database import init_db
from app.main import create_app
from app.services.incident_grouping_service import reset_incident_counter


@pytest.fixture()
def db_path(tmp_path: Path) -> str:
    path = str(tmp_path / "test.db")
    init_db(path)
    return path


@pytest.fixture()
def rules_path() -> str:
    return "app/rules/default_rules.yml"


@pytest.fixture()
def app(db_path: str, rules_path: str):
    reset_incident_counter()
    return create_app(db_path=db_path, rules_path=rules_path)


@pytest.fixture()
async def client(app):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        yield c
