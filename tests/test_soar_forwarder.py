"""Tests for the SOAR/webhook incident forwarder.

Every case runs against an httpx MockTransport, so the retry and error handling
are exercised without a live server: the transport decides what the receiver
"returns", and the tests assert what the forwarder did in response.
"""

import httpx

from app.services.soar_forwarder import build_payload, forward_incident

SAMPLE_INCIDENT = {
    "incident_id": "INC-0001",
    "title": "Critical Incident — 198.51.100.7",
    "severity": "critical",
    "score": 100,
    "status": "open",
    "created_at": "2026-01-10T09:15:00+00:00",
    "summary": "SSH brute force followed by a successful login.",
    "involved_entities": {
        "source_ips": ["198.51.100.7"],
        "usernames": ["deploy"],
        "hosts": ["web-01"],
    },
}
SAMPLE_ALERTS = [
    {
        "rule_id": "SSH_BRUTE_FORCE",
        "rule_name": "SSH Brute Force",
        "severity": "high",
        "mitre_technique_id": "T1110.001",
    },
    {
        "rule_id": "SSH_BRUTE_FORCE_SUCCESS",
        "rule_name": "Successful Login After SSH Brute Force",
        "severity": "critical",
        "mitre_technique_id": "T1078",
    },
]


def _client(handler) -> httpx.Client:
    return httpx.Client(transport=httpx.MockTransport(handler))


def test_payload_is_flat_and_carries_the_essentials():
    payload = build_payload(SAMPLE_INCIDENT, SAMPLE_ALERTS)
    assert payload["source"] == "mini-siem"
    assert payload["incident_id"] == "INC-0001"
    assert payload["alert_count"] == 2
    assert payload["entities"]["source_ips"] == ["198.51.100.7"]
    # Alerts are trimmed to the fields a receiver needs, not dumped whole.
    assert payload["alerts"][0]["rule_id"] == "SSH_BRUTE_FORCE"
    assert set(payload["alerts"][0]) == {
        "rule_id", "rule_name", "severity", "mitre_technique_id"
    }


def test_successful_post_is_delivered_in_one_attempt():
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["url"] = str(request.url)
        seen["json"] = request.read()
        return httpx.Response(200, json={"ok": True})

    result = forward_incident(
        SAMPLE_INCIDENT, SAMPLE_ALERTS, "https://soar.example/intake",
        client=_client(handler),
    )
    assert result.delivered is True
    assert result.attempts == 1
    assert result.status_code == 200
    assert seen["url"] == "https://soar.example/intake"
    assert b"INC-0001" in seen["json"]


def test_5xx_is_retried_then_succeeds():
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        if calls["n"] < 3:
            return httpx.Response(503)
        return httpx.Response(200)

    result = forward_incident(
        SAMPLE_INCIDENT, SAMPLE_ALERTS, "https://soar.example/intake",
        retries=2, backoff=0.0, client=_client(handler),
    )
    assert result.delivered is True
    assert result.attempts == 3


def test_persistent_5xx_gives_up_after_all_attempts():
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(500)

    result = forward_incident(
        SAMPLE_INCIDENT, SAMPLE_ALERTS, "https://soar.example/intake",
        retries=2, backoff=0.0, client=_client(handler),
    )
    assert result.delivered is False
    assert result.attempts == 3  # first + 2 retries
    assert calls["n"] == 3
    assert result.status_code == 500


def test_4xx_is_not_retried():
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(400, json={"error": "bad payload"})

    result = forward_incident(
        SAMPLE_INCIDENT, SAMPLE_ALERTS, "https://soar.example/intake",
        retries=3, backoff=0.0, client=_client(handler),
    )
    assert result.delivered is False
    # A 4xx is permanent: exactly one attempt, no retries.
    assert calls["n"] == 1
    assert result.status_code == 400


def test_network_error_is_retried_then_reported():
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        raise httpx.ConnectError("connection refused")

    result = forward_incident(
        SAMPLE_INCIDENT, SAMPLE_ALERTS, "https://soar.example/intake",
        retries=1, backoff=0.0, client=_client(handler),
    )
    assert result.delivered is False
    assert calls["n"] == 2  # first + 1 retry
    assert "ConnectError" in (result.error or "")
