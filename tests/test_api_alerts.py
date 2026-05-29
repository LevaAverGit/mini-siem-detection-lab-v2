import pytest


async def _ingest_brute_force(client, ip: str = "192.0.2.100", count: int = 15):
    line = f"Jan 10 09:10:15 web-01 sshd[1300]: Failed password for root from {ip} port 43210 ssh2"
    content = "\n".join([line] * count)
    return await client.post("/events/ingest", json={"source_type": "linux_auth", "content": content})


class TestAlertsEndpoint:
    async def test_list_alerts_empty(self, client):
        resp = await client.get("/alerts/")
        assert resp.status_code == 200
        assert resp.json() == []

    async def test_list_alerts_after_ingest(self, client):
        await _ingest_brute_force(client)
        resp = await client.get("/alerts/")
        assert resp.status_code == 200
        assert len(resp.json()) >= 1

    async def test_list_alerts_filter_by_severity(self, client):
        await _ingest_brute_force(client, count=15)
        resp = await client.get("/alerts/?severity=medium")
        assert resp.status_code == 200
        for alert in resp.json():
            assert alert["severity"] == "medium"

    async def test_update_alert_status_to_triaged(self, client):
        await _ingest_brute_force(client)
        alerts_resp = await client.get("/alerts/")
        alerts = alerts_resp.json()
        assert len(alerts) >= 1
        alert_id = alerts[0]["alert_id"]

        resp = await client.patch(f"/alerts/{alert_id}/status", json={"status": "triaged"})
        assert resp.status_code == 200
        assert resp.json()["status"] == "triaged"

    async def test_update_nonexistent_alert_returns_404(self, client):
        resp = await client.patch("/alerts/nonexistent-id/status", json={"status": "triaged"})
        assert resp.status_code == 404

    async def test_list_alerts_filter_by_status(self, client):
        await _ingest_brute_force(client)
        alerts = (await client.get("/alerts/")).json()
        alert_id = alerts[0]["alert_id"]
        await client.patch(f"/alerts/{alert_id}/status", json={"status": "triaged"})

        resp = await client.get("/alerts/?status=triaged")
        assert any(a["alert_id"] == alert_id for a in resp.json())


class TestIncidentsEndpoint:
    async def test_list_incidents_empty(self, client):
        resp = await client.get("/incidents/")
        assert resp.status_code == 200
        assert resp.json() == []

    async def test_list_incidents_after_ingest(self, client):
        await _ingest_brute_force(client)
        resp = await client.get("/incidents/")
        assert resp.status_code == 200
        assert len(resp.json()) >= 1

    async def test_get_incident_by_id(self, client):
        await _ingest_brute_force(client)
        incidents = (await client.get("/incidents/")).json()
        inc_id = incidents[0]["incident_id"]
        resp = await client.get(f"/incidents/{inc_id}")
        assert resp.status_code == 200
        assert resp.json()["incident_id"] == inc_id

    async def test_get_nonexistent_incident_returns_404(self, client):
        resp = await client.get("/incidents/INC-MISSING")
        assert resp.status_code == 404

    async def test_incident_report_md(self, client):
        await _ingest_brute_force(client)
        incidents = (await client.get("/incidents/")).json()
        inc_id = incidents[0]["incident_id"]
        resp = await client.get(f"/incidents/{inc_id}/report.md")
        assert resp.status_code == 200
        content = resp.text
        assert "# Incident Report:" in content
        assert "## Executive Summary" in content
        assert "## Recommended Analyst Actions" in content

    async def test_incident_report_json(self, client):
        await _ingest_brute_force(client)
        incidents = (await client.get("/incidents/")).json()
        inc_id = incidents[0]["incident_id"]
        resp = await client.get(f"/incidents/{inc_id}/report.json")
        assert resp.status_code == 200
        data = resp.json()
        assert "incident" in data
        assert "alerts" in data
        assert "schema_version" in data
        assert "generated_at" in data

    async def test_incident_has_alert_ids(self, client):
        await _ingest_brute_force(client)
        incidents = (await client.get("/incidents/")).json()
        assert len(incidents[0]["alert_ids"]) >= 1
