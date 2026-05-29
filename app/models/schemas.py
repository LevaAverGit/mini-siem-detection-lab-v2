from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class SourceType(str, Enum):
    linux_auth = "linux_auth"
    nginx_access = "nginx_access"
    windows_security = "windows_security"
    cloud_audit = "cloud_audit"


class AlertSeverity(str, Enum):
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class AlertStatus(str, Enum):
    new = "new"
    triaged = "triaged"
    false_positive = "false_positive"
    escalated = "escalated"
    closed = "closed"


class IncidentStatus(str, Enum):
    open = "open"
    triaged = "triaged"
    escalated = "escalated"
    closed = "closed"


class Event(BaseModel):
    event_id: str
    timestamp: datetime
    source_type: SourceType
    source_host: str = "unknown"
    source_ip: str | None = None
    username: str | None = None
    action: str
    status: str = ""
    raw_event: dict[str, Any] = Field(default_factory=dict)
    normalized_message: str
    severity_hint: str | None = None


class Alert(BaseModel):
    alert_id: str
    rule_id: str
    rule_name: str
    severity: AlertSeverity
    score: int
    event_ids: list[str] = Field(default_factory=list)
    source_ip: str | None = None
    username: str | None = None
    title: str
    description: str
    evidence: list[str] = Field(default_factory=list)
    recommendation: str
    created_at: datetime = Field(default_factory=datetime.utcnow)
    status: AlertStatus = AlertStatus.new
    mitre_tactic: str | None = None
    mitre_technique_id: str | None = None
    mitre_technique_name: str | None = None
    mitre_mapping_confidence: str | None = None


class InvolvedEntities(BaseModel):
    source_ips: list[str] = Field(default_factory=list)
    usernames: list[str] = Field(default_factory=list)
    hosts: list[str] = Field(default_factory=list)


class TimelineEntry(BaseModel):
    timestamp: datetime
    description: str
    event_id: str | None = None
    alert_id: str | None = None


class Incident(BaseModel):
    incident_id: str
    title: str
    severity: AlertSeverity
    score: int
    alert_ids: list[str] = Field(default_factory=list)
    involved_entities: InvolvedEntities = Field(default_factory=InvolvedEntities)
    timeline: list[TimelineEntry] = Field(default_factory=list)
    summary: str
    analyst_notes: str | None = None
    recommended_actions: list[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=datetime.utcnow)
    status: IncidentStatus = IncidentStatus.open


class RawLogIngestion(BaseModel):
    source_type: SourceType
    content: str


class AlertStatusUpdate(BaseModel):
    status: AlertStatus


class IngestionResult(BaseModel):
    events_ingested: int
    skipped: int
    alerts_created: int
    incidents_created: int


class ParseResult(BaseModel):
    events: list[Event]
    skipped_count: int
    error_count: int
