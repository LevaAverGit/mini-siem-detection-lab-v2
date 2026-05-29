import pytest


class TestHealthEndpoint:
    async def test_health_returns_ok(self, client):
        resp = await client.get("/health")
        assert resp.status_code == 200
        assert resp.json() == {"status": "ok"}


class TestIngestEndpoint:
    async def test_ingest_linux_auth(self, client):
        content = "\n".join([
            "Jan 10 09:10:15 web-01 sshd[1300]: Failed password for root from 192.0.2.100 port 43210 ssh2"
            for _ in range(5)
        ])
        resp = await client.post("/events/ingest", json={
            "source_type": "linux_auth",
            "content": content,
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["events_ingested"] == 5

    async def test_ingest_creates_alerts_on_brute_force(self, client):
        line = "Jan 10 09:10:15 web-01 sshd[1300]: Failed password for root from 192.0.2.100 port 43210 ssh2"
        content = "\n".join([line] * 15)
        resp = await client.post("/events/ingest", json={
            "source_type": "linux_auth",
            "content": content,
        })
        assert resp.json()["alerts_created"] >= 1

    async def test_ingest_nginx_access(self, client):
        line = '192.0.2.200 - - [10/Jan/2026:08:01:00 +0000] "GET /page1 HTTP/1.1" 404 128 "-" "Mozilla/5.0"'
        content = "\n".join([line] * 5)
        resp = await client.post("/events/ingest", json={
            "source_type": "nginx_access",
            "content": content,
        })
        assert resp.json()["events_ingested"] == 5

    async def test_ingest_empty_content_returns_zero(self, client):
        resp = await client.post("/events/ingest", json={
            "source_type": "linux_auth",
            "content": "",
        })
        assert resp.status_code == 200
        assert resp.json()["events_ingested"] == 0

    async def test_ingest_malformed_lines_counted_as_skipped(self, client):
        content = "not a valid log line\nalso not valid"
        resp = await client.post("/events/ingest", json={
            "source_type": "linux_auth",
            "content": content,
        })
        assert resp.status_code == 200
        assert resp.json()["events_ingested"] == 0

    async def test_list_events_after_ingest(self, client):
        line = "Jan 10 09:00:01 web-01 sshd[1234]: Accepted password for deploy from 203.0.113.5 port 52100 ssh2"
        await client.post("/events/ingest", json={"source_type": "linux_auth", "content": line})
        resp = await client.get("/events/")
        assert resp.status_code == 200
        assert len(resp.json()) >= 1

    async def test_list_events_filter_by_source_type(self, client):
        line = "Jan 10 09:00:01 web-01 sshd[1234]: Accepted password for deploy from 203.0.113.5 port 52100 ssh2"
        await client.post("/events/ingest", json={"source_type": "linux_auth", "content": line})
        resp = await client.get("/events/?source_type=linux_auth")
        assert resp.status_code == 200
        data = resp.json()
        assert all(e["source_type"] == "linux_auth" for e in data)
