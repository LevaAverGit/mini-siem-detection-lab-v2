"""soar_forwarder.py -- push a detected incident to an external service over REST.

This is the egress side of the pipeline: once an incident is grouped, a SOC
usually forwards it to a SOAR platform, a ticketing system, or a chat webhook so
a case gets opened automatically. This module does that with a plain HTTP POST,
so it works against anything that accepts JSON on a URL -- a SOAR intake webhook,
a generic automation endpoint, a Slack/Telegram incoming webhook.

The transport is deliberately small and dependency-light (httpx, already used by
the API tests). The two things a real integration needs and a naive `requests`
call skips are here: a bounded timeout, and a retry that distinguishes a
retryable failure (a network error, or a 5xx from the receiver) from a permanent
one (a 4xx -- a bad URL or payload, which retrying only repeats).
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Optional

import httpx


def build_payload(incident: dict, alerts: list[dict]) -> dict[str, Any]:
    """Shape an incident and its alerts into the JSON a receiver gets.

    Kept flat and explicit rather than dumping the raw rows, so the contract with
    the downstream system is visible and stable: whatever internal columns change,
    the webhook payload does not drift unless this function is edited.
    """
    entities = incident.get("involved_entities", {}) or {}
    return {
        "source": "mini-siem",
        "incident_id": incident.get("incident_id"),
        "title": incident.get("title"),
        "severity": incident.get("severity"),
        "score": incident.get("score"),
        "status": incident.get("status", "open"),
        "created_at": incident.get("created_at"),
        "summary": incident.get("summary", ""),
        "entities": {
            "source_ips": entities.get("source_ips", []),
            "usernames": entities.get("usernames", []),
            "hosts": entities.get("hosts", []),
        },
        "alert_count": len(alerts),
        "alerts": [
            {
                "rule_id": a.get("rule_id"),
                "rule_name": a.get("rule_name"),
                "severity": a.get("severity"),
                "mitre_technique_id": a.get("mitre_technique_id"),
            }
            for a in alerts
        ],
    }


@dataclass
class ForwardResult:
    """Outcome of a forward attempt, so callers can log or exit-code on it."""

    delivered: bool
    attempts: int
    status_code: Optional[int] = None
    error: Optional[str] = None
    detail: dict[str, Any] = field(default_factory=dict)


def forward_incident(
    incident: dict,
    alerts: list[dict],
    webhook_url: str,
    *,
    timeout: float = 10.0,
    retries: int = 2,
    backoff: float = 0.5,
    client: Optional[httpx.Client] = None,
) -> ForwardResult:
    """POST the incident to ``webhook_url``; return whether it was delivered.

    ``retries`` is the number of *extra* attempts after the first, so ``retries=2``
    means up to three POSTs. Only network errors and 5xx responses are retried; a
    4xx is returned immediately because retrying a rejected request just repeats
    the rejection. ``client`` can be injected (e.g. an ``httpx.Client`` on a
    ``MockTransport``) so the retry logic is testable without a live server.
    """
    payload = build_payload(incident, alerts)
    owns_client = client is None
    client = client or httpx.Client(timeout=timeout)
    attempts = 0
    last_error: Optional[str] = None
    last_status: Optional[int] = None
    try:
        for attempt in range(retries + 1):
            attempts = attempt + 1
            try:
                response = client.post(webhook_url, json=payload)
            except httpx.TransportError as exc:
                # Connection refused, DNS failure, timeout: retryable.
                last_error = f"{type(exc).__name__}: {exc}"
                last_status = None
            else:
                last_status = response.status_code
                if response.status_code < 400:
                    return ForwardResult(
                        delivered=True,
                        attempts=attempts,
                        status_code=response.status_code,
                    )
                if response.status_code < 500:
                    # 4xx is a permanent client error -- do not retry.
                    return ForwardResult(
                        delivered=False,
                        attempts=attempts,
                        status_code=response.status_code,
                        error=f"receiver rejected the request ({response.status_code})",
                    )
                last_error = f"receiver error ({response.status_code})"

            if attempt < retries:
                time.sleep(backoff * (attempt + 1))

        return ForwardResult(
            delivered=False,
            attempts=attempts,
            status_code=last_status,
            error=last_error or "delivery failed",
        )
    finally:
        if owns_client:
            client.close()
