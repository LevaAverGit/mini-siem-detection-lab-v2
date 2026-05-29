CREATE TABLE IF NOT EXISTS events (
    event_id          TEXT PRIMARY KEY,
    timestamp         TEXT NOT NULL,
    source_type       TEXT NOT NULL,
    source_host       TEXT NOT NULL DEFAULT 'unknown',
    source_ip         TEXT,
    username          TEXT,
    action            TEXT NOT NULL,
    status            TEXT NOT NULL DEFAULT '',
    raw_event         TEXT NOT NULL DEFAULT '{}',
    normalized_message TEXT NOT NULL,
    severity_hint     TEXT
);

CREATE TABLE IF NOT EXISTS alerts (
    alert_id     TEXT PRIMARY KEY,
    rule_id      TEXT NOT NULL,
    rule_name    TEXT NOT NULL,
    severity     TEXT NOT NULL,
    score        INTEGER NOT NULL,
    event_ids    TEXT NOT NULL DEFAULT '[]',
    source_ip    TEXT,
    username     TEXT,
    title        TEXT NOT NULL,
    description  TEXT NOT NULL,
    evidence     TEXT NOT NULL DEFAULT '[]',
    recommendation TEXT NOT NULL,
    created_at   TEXT NOT NULL,
    status       TEXT NOT NULL DEFAULT 'new',
    mitre_tactic            TEXT,
    mitre_technique_id      TEXT,
    mitre_technique_name    TEXT,
    mitre_mapping_confidence TEXT
);

CREATE TABLE IF NOT EXISTS incidents (
    incident_id         TEXT PRIMARY KEY,
    title               TEXT NOT NULL,
    severity            TEXT NOT NULL,
    score               INTEGER NOT NULL,
    alert_ids           TEXT NOT NULL DEFAULT '[]',
    involved_entities   TEXT NOT NULL DEFAULT '{}',
    timeline            TEXT NOT NULL DEFAULT '[]',
    summary             TEXT NOT NULL,
    analyst_notes       TEXT,
    recommended_actions TEXT NOT NULL DEFAULT '[]',
    created_at          TEXT NOT NULL,
    status              TEXT NOT NULL DEFAULT 'open'
);
