from __future__ import annotations

import argparse
import json
import os
import sys

from app.core.config import settings
from app.db.database import init_db
from app.models.schemas import SourceType
from app.services.detection_engine import load_rules, run_detections
from app.services.incident_grouping_service import group_alerts, reset_incident_counter
from app.services.normalization_service import normalize_file
from app.services.report_service import generate_json_report, generate_markdown_report
from app.services.storage_service import StorageService


def _source_type(s: str) -> SourceType:
    try:
        return SourceType(s)
    except ValueError:
        raise argparse.ArgumentTypeError(
            f"Unknown source type: {s}. Choices: {[e.value for e in SourceType]}"
        )


def cmd_ingest(args: argparse.Namespace) -> None:
    db_path = args.db or settings.db_path
    rules_path = args.rules or settings.rules_path
    init_db(db_path)

    storage = StorageService(db_path)
    rules = load_rules(rules_path)

    parse_result = normalize_file(args.file, args.source)
    events = parse_result.events
    storage.insert_events(events)

    alerts = run_detections(events, rules)
    storage.insert_alerts(alerts)

    incidents = group_alerts(alerts, events)
    storage.insert_incidents(incidents)

    print(f"Events ingested : {len(events)}")
    print(f"Skipped         : {parse_result.skipped_count}")
    print(f"Alerts created  : {len(alerts)}")
    print(f"Incidents created: {len(incidents)}")


def cmd_alerts_list(args: argparse.Namespace) -> None:
    db_path = args.db or settings.db_path
    storage = StorageService(db_path)
    alerts = storage.list_alerts(
        status=getattr(args, "status", None),
        severity=getattr(args, "severity", None),
    )
    if not alerts:
        print("No alerts found.")
        return
    for a in alerts:
        print(f"[{a['severity'].upper()}] {a['title']} (status: {a['status']})")


def cmd_incidents_list(args: argparse.Namespace) -> None:
    db_path = args.db or settings.db_path
    storage = StorageService(db_path)
    incidents = storage.list_incidents(
        status=getattr(args, "status", None),
        severity=getattr(args, "severity", None),
    )
    if not incidents:
        print("No incidents found.")
        return
    for i in incidents:
        print(f"[{i['incident_id']}] [{i['severity'].upper()}] {i['title']}")


def cmd_incidents_report(args: argparse.Namespace) -> None:
    db_path = args.db or settings.db_path
    storage = StorageService(db_path)
    incident = storage.get_incident(args.id)
    if not incident:
        print(f"Incident {args.id} not found.", file=sys.stderr)
        sys.exit(1)
    alerts = storage.get_alerts_for_incident(incident.get("alert_ids", []))

    if args.format == "md":
        content = generate_markdown_report(incident, alerts)
    else:
        content = json.dumps(generate_json_report(incident, alerts), indent=2, default=str)

    if args.output:
        os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(content)
        print(f"Report saved to {args.output}")
    else:
        print(content)


def cmd_demo(args: argparse.Namespace) -> None:
    db_path = args.db or "demo.db"
    rules_path = args.rules or settings.rules_path
    reset_incident_counter()

    if os.path.exists(db_path):
        os.unlink(db_path)
    init_db(db_path)

    storage = StorageService(db_path)
    rules = load_rules(rules_path)

    sample_sources = [
        ("sample_logs/linux_auth.log", SourceType.linux_auth),
        ("sample_logs/nginx_access.log", SourceType.nginx_access),
        ("sample_logs/windows_security.jsonl", SourceType.windows_security),
        ("sample_logs/cloud_audit.jsonl", SourceType.cloud_audit),
    ]

    all_events = []
    total_skipped = 0

    print("=" * 60)
    print("Mini SIEM Detection Lab — Demo Run")
    print("=" * 60)

    for path, source_type in sample_sources:
        if not os.path.exists(path):
            print(f"  [SKIP] {path} not found")
            continue
        result = normalize_file(path, source_type)
        storage.insert_events(result.events)
        all_events.extend(result.events)
        total_skipped += result.skipped_count
        print(f"  Ingested {len(result.events):4d} events from {path}")

    print()
    print(f"Total events ingested : {len(all_events)}")
    print(f"Total skipped         : {total_skipped}")

    alerts = run_detections(all_events, rules)
    storage.insert_alerts(alerts)
    print(f"Alerts generated      : {len(alerts)}")

    incidents = group_alerts(alerts, all_events)
    storage.insert_incidents(incidents)
    print(f"Incidents created     : {len(incidents)}")

    if alerts:
        print()
        print("Alert breakdown by severity:")
        from collections import Counter
        sev_counts = Counter(a.severity.value for a in alerts)
        for sev in ("critical", "high", "medium", "low"):
            count = sev_counts.get(sev, 0)
            if count:
                print(f"  {sev.upper():8s}: {count}")

    if incidents:
        print()
        print("Incidents:")
        for inc in incidents:
            print(f"  [{inc.incident_id}] [{inc.severity.value.upper()}] {inc.title}")

    print()
    print(f"Database : {db_path}")
    print("Run `python -m cli.main incidents report --id INC-0001 --format md` to export a report.")
    print("=" * 60)


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="python -m cli.main",
        description="Mini SIEM Detection Lab CLI",
    )
    parser.add_argument("--db", help="SQLite database path")
    parser.add_argument("--rules", help="Rules YAML path")

    sub = parser.add_subparsers(dest="command")

    # ingest
    p_ingest = sub.add_parser("ingest", help="Ingest a log file")
    p_ingest.add_argument("--source", required=True, type=_source_type,
                          help="Source type: linux_auth, nginx_access, windows_security, cloud_audit")
    p_ingest.add_argument("--file", required=True, help="Path to log file")
    p_ingest.set_defaults(func=cmd_ingest)

    # alerts list
    p_alerts = sub.add_parser("alerts", help="Alert commands")
    alerts_sub = p_alerts.add_subparsers(dest="subcommand")
    p_al = alerts_sub.add_parser("list", help="List alerts")
    p_al.add_argument("--status", help="Filter by status")
    p_al.add_argument("--severity", help="Filter by severity")
    p_al.set_defaults(func=cmd_alerts_list)

    # incidents
    p_incidents = sub.add_parser("incidents", help="Incident commands")
    incidents_sub = p_incidents.add_subparsers(dest="subcommand")
    p_il = incidents_sub.add_parser("list", help="List incidents")
    p_il.add_argument("--status", help="Filter by status")
    p_il.add_argument("--severity", help="Filter by severity")
    p_il.set_defaults(func=cmd_incidents_list)

    p_ir = incidents_sub.add_parser("report", help="Export incident report")
    p_ir.add_argument("--id", required=True, help="Incident ID")
    p_ir.add_argument("--format", choices=["md", "json"], default="md")
    p_ir.add_argument("--output", help="Output file path")
    p_ir.set_defaults(func=cmd_incidents_report)

    # demo
    p_demo = sub.add_parser("demo", help="Run full demo with sample logs")
    p_demo.set_defaults(func=cmd_demo)

    args = parser.parse_args()
    if not hasattr(args, "func"):
        parser.print_help()
        sys.exit(0)
    args.func(args)


if __name__ == "__main__":
    main()
