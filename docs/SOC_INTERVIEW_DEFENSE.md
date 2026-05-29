# SOC Interview Defense

Talking points for presenting this project in a SOC / detection-engineering interview.
Junior-level framing: honest about scope, clear about trade-offs.

---

## 30-second pitch

> I built a lab-grade detection pipeline that mirrors a SOC monitoring workflow:
> log ingestion → normalization → detection rules → alerts → incident grouping → reports.
> Four log sources feed a unified Event model, nine YAML-defined rules raise alerts,
> each rule carries a MITRE ATT&CK mapping, alerts move through a lifecycle
> (new → triaged → escalated → closed), and correlated alerts are grouped into
> incidents by source IP with a Markdown/JSON report and an analyst playbook.
> It is a learning lab, not a production SIEM.

---

## 60-second technical explanation

- **Log sources (4):** `linux_auth.log`, `nginx_access.log`, `windows_security.jsonl`,
  `cloud_audit.jsonl` — a mix of line-based and JSON formats so the normalizer has to
  handle more than one shape.
- **Events → alerts:** the normalization service maps every raw line into a unified
  `Event` model. The detection engine runs nine rules (loaded from
  `app/rules/default_rules.yml`) against those events and emits `Alert` objects with a
  severity and score.
- **Alerts → incidents:** the incident grouping service correlates alerts that share a
  `source_ip` into a single `Incident` with a timeline and entity tracking, so an analyst
  sees one story per attacker instead of dozens of isolated alerts.
- **MITRE mapping:** each rule declares a tactic, technique, and a confidence flag
  (`direct` or `approximate`) — see `docs/DETECTION_RULES.md`.
- **Sigma-style rules:** the `sigma_rules/` directory holds detections expressed in
  Sigma-like YAML to show I understand the portable-rule format; it is not a full Sigma
  compilation engine.
- **What to show:** `make demo` ingests the sample logs and prints a summary; the
  FastAPI endpoints expose ingest/list/triage/report; 124 tests run with `make test`.

---

## What this project demonstrates

- Detection logic expressed as deterministic, testable rules
- Triage thinking — alert lifecycle and incident correlation, not just raw alerts
- Rule-based alerting with explicit thresholds instead of opaque heuristics
- Severity scoring and prioritization
- MITRE ATT&CK awareness at the rule level, with honest confidence labelling
- Structured Markdown/JSON reporting suitable for handoff
- Test coverage (124 tests) and CI as part of the workflow

---

## What this project is NOT

- Not a production SIEM
- Not a Splunk / QRadar / KUMA / MaxPatrol SIEM replacement
- Not a full Sigma engine (Sigma-style rules are illustrative, not compiled)
- Not real-time enterprise monitoring — it processes batches of static logs
- Not a threat intelligence platform — no external feeds, no enrichment

---

## Files to show during interview

| Interview topic | File to show | What to explain |
|---|---|---|
| Detection rules | `app/rules/default_rules.yml` | Thresholds and config live in YAML, separate from engine code |
| Rule logic + MITRE | `docs/DETECTION_RULES.md` | Per-rule trigger, score, tactic/technique, confidence, false positives |
| Sigma-style examples | `sigma_rules/` | Portable rule format; why Sigma matters for sharing detections |
| Alert lifecycle | `app/services/detection_engine.py` | How events become scored alerts |
| Incident grouping | `app/services/incident_grouping_service.py` | Correlation by source IP into an incident timeline |
| Reports | `app/services/report_service.py` | Markdown for humans, JSON for downstream tooling |
| Tests | `tests/` | Per-service unit tests, API tests via `ASGITransport`, `tmp_path` isolation |

---

## Likely questions and short answers

1. **Why did you build this project?**
   To show I understand the full detection pipeline a SOC relies on — not just what an
   alert is, but how raw logs become alerts, incidents, and a report an analyst can act on.

2. **How does detection work?**
   The engine loads nine rules from YAML and runs them over normalized events. Each rule
   has explicit thresholds (e.g. failed-login count) and produces a scored alert.

3. **How do you reduce false positives?**
   Thresholds are tunable in YAML, and each rule documents known benign triggers
   (pen tests, scanners). In production I'd add allow-lists and baseline tuning per source.

4. **What does MITRE mapping add?**
   It gives every detection a shared vocabulary — tactic and technique — so alerts can be
   grouped by attacker behaviour and gaps in coverage become visible.

5. **Are these real Sigma rules?**
   They are Sigma-style YAML to demonstrate the format. I did not build a Sigma compiler;
   a real deployment would run them through `sigma-cli` against a backend.

6. **How are alerts grouped into incidents?**
   By shared `source_ip`. Alerts from the same IP are correlated into one incident with a
   timeline, so an analyst investigates one entity instead of many alerts.

7. **What is the difference between this and a real SIEM?**
   A real SIEM ingests in real time at scale, has connectors, RBAC, retention, and a UI.
   This is a batch pipeline over static logs that demonstrates the same core concepts.

8. **What would you improve in production?**
   Real-time ingestion, a proper datastore, enrichment from threat intel, allow-listing,
   and running the Sigma rules through a real Sigma backend.

9. **How did you test it?**
   124 pytest tests — unit tests per service, API tests through `httpx.ASGITransport`,
   and per-test SQLite isolation via `tmp_path`.

10. **What was the hardest part?**
    Designing one normalized Event model that fits four different log formats without
    leaking source-specific assumptions into the detection rules.

---

## Phrases to avoid

- "production-ready SIEM"
- "enterprise SOC platform"
- "complete Sigma engine"
- "replaces commercial SIEM"
- "real-time detection platform"

---

## Good closing explanation

> This project demonstrates that I understand the detection pipeline and SOC workflow
> end to end — ingestion, normalization, rule-based detection, MITRE mapping, alert
> lifecycle, incident correlation, and reporting. It is a controlled learning lab built
> to be read and discussed, not a finished enterprise SIEM.
