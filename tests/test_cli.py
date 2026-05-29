import os
import pytest
from pathlib import Path
from unittest.mock import patch

from app.db.database import init_db
from app.services.incident_grouping_service import reset_incident_counter


@pytest.fixture(autouse=True)
def reset():
    reset_incident_counter()
    yield
    reset_incident_counter()


class TestCLIDemo:
    def test_demo_runs_without_error(self, tmp_path: Path, capsys):
        db_path = str(tmp_path / "demo_test.db")
        init_db(db_path)
        reset_incident_counter()

        import argparse
        from cli.main import cmd_demo

        args = argparse.Namespace(db=db_path, rules="app/rules/default_rules.yml")
        cmd_demo(args)

        captured = capsys.readouterr()
        assert "Mini SIEM Detection Lab" in captured.out
        assert "Total events ingested" in captured.out

    def test_demo_creates_incidents(self, tmp_path: Path, capsys):
        db_path = str(tmp_path / "demo_inc.db")
        init_db(db_path)
        reset_incident_counter()

        import argparse
        from cli.main import cmd_demo

        args = argparse.Namespace(db=db_path, rules="app/rules/default_rules.yml")
        cmd_demo(args)

        from app.services.storage_service import StorageService
        storage = StorageService(db_path)
        incidents = storage.list_incidents()
        assert len(incidents) >= 1


class TestCLIIngest:
    def test_ingest_linux_auth(self, tmp_path: Path, capsys):
        db_path = str(tmp_path / "ingest_test.db")
        init_db(db_path)

        import argparse
        from cli.main import cmd_ingest
        from app.models.schemas import SourceType

        args = argparse.Namespace(
            db=db_path,
            rules="app/rules/default_rules.yml",
            source=SourceType.linux_auth,
            file="sample_logs/linux_auth.log",
        )
        cmd_ingest(args)
        captured = capsys.readouterr()
        assert "Events ingested" in captured.out

    def test_ingest_nginx(self, tmp_path: Path, capsys):
        db_path = str(tmp_path / "ingest_nginx.db")
        init_db(db_path)

        import argparse
        from cli.main import cmd_ingest
        from app.models.schemas import SourceType

        args = argparse.Namespace(
            db=db_path,
            rules="app/rules/default_rules.yml",
            source=SourceType.nginx_access,
            file="sample_logs/nginx_access.log",
        )
        cmd_ingest(args)
        captured = capsys.readouterr()
        assert "Events ingested" in captured.out


class TestCLIReport:
    def test_report_md_output(self, tmp_path: Path, capsys):
        db_path = str(tmp_path / "report_test.db")
        init_db(db_path)
        reset_incident_counter()

        import argparse
        from cli.main import cmd_demo, cmd_incidents_report

        demo_args = argparse.Namespace(db=db_path, rules="app/rules/default_rules.yml")
        cmd_demo(demo_args)

        from app.services.storage_service import StorageService
        incidents = StorageService(db_path).list_incidents()
        assert len(incidents) >= 1
        inc_id = incidents[0]["incident_id"]

        out_path = str(tmp_path / "report.md")
        report_args = argparse.Namespace(
            db=db_path,
            rules="app/rules/default_rules.yml",
            id=inc_id,
            format="md",
            output=out_path,
        )
        cmd_incidents_report(report_args)
        captured = capsys.readouterr()
        assert "Report saved to" in captured.out
        assert os.path.exists(out_path)
        content = open(out_path).read()
        assert "# Incident Report:" in content
