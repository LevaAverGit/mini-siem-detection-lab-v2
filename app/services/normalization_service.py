from __future__ import annotations

import json
import re
import uuid
from datetime import datetime, timezone

from app.models.schemas import Event, ParseResult, SourceType

# Linux auth log patterns
_LINUX_TIMESTAMP_FMT = "%b %d %H:%M:%S"
_RE_SSH_FAILED = re.compile(
    r"^(\w+\s+\d+\s+\d+:\d+:\d+)\s+(\S+)\s+sshd\[[\d]+\]:\s+Failed password for(?: invalid user)?\s+(\S+)\s+from\s+(\S+)"
)
_RE_SSH_INVALID = re.compile(
    r"^(\w+\s+\d+\s+\d+:\d+:\d+)\s+(\S+)\s+sshd\[[\d]+\]:\s+Invalid user\s+(\S+)\s+from\s+(\S+)"
)
_RE_SSH_ACCEPTED = re.compile(
    r"^(\w+\s+\d+\s+\d+:\d+:\d+)\s+(\S+)\s+sshd\[[\d]+\]:\s+Accepted password for\s+(\S+)\s+from\s+(\S+)"
)
_RE_SUDO = re.compile(
    r"^(\w+\s+\d+\s+\d+:\d+:\d+)\s+(\S+)\s+sudo\s*:\s+(\S+)\s+:.*COMMAND=(.*)"
)
_RE_SUDO_FAIL = re.compile(
    r"^(\w+\s+\d+\s+\d+:\d+:\d+)\s+(\S+)\s+sudo\s*:\s+(\S+)\s+:.*NOT in sudoers"
)

# Nginx combined log pattern
_RE_NGINX = re.compile(
    r'^(\S+)\s+-\s+(\S+)\s+\[([^\]]+)\]\s+"(\S+)\s+(\S+)\s+\S+"\s+(\d+)\s+\d+(?:\s+"[^"]*"\s+"([^"]*)")?'
)
_NGINX_TIMESTAMP_FMT = "%d/%b/%Y:%H:%M:%S %z"

# PostgreSQL server log, log_line_prefix = '%m [%p] %q%u@%d %h '
# Example: 2026-01-10 09:12:03.412 UTC [2841] postgres@appdb 203.0.113.99 FATAL:  password ...
_RE_PG_PREFIX = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})(?:\.\d+)?\s+\S+\s+\[(?P<pid>\d+)\]\s+"
    r"(?:(?P<user>[^@\s]+)@(?P<db>\S+)\s+)?"
    r"(?:(?P<host>\d{1,3}(?:\.\d{1,3}){3})\s+)?"
    r"(?P<level>[A-Z]+):\s+(?P<message>.*)$"
)
_PG_TIMESTAMP_FMT = "%Y-%m-%d %H:%M:%S"
_RE_PG_AUTH_FAILED = re.compile(r'^password authentication failed for user "([^"]+)"')
_RE_PG_CONN_AUTHORIZED = re.compile(
    r"^connection authorized:\s+user=(\S+?)(?:\s+database=(\S+?))?(?:\s|$)"
)
_RE_PG_PRIVILEGE = re.compile(
    r"^statement:\s+((?:GRANT|REVOKE|CREATE\s+ROLE|CREATE\s+USER|ALTER\s+ROLE|ALTER\s+USER)\b.*)",
    re.IGNORECASE,
)


def _parse_linux_timestamp(ts_str: str) -> datetime:
    current_year = datetime.now().year
    try:
        dt = datetime.strptime(ts_str.strip(), _LINUX_TIMESTAMP_FMT)
        return dt.replace(year=current_year, tzinfo=timezone.utc)
    except ValueError:
        return datetime.now(timezone.utc)


def normalize_linux_auth_line(line: str) -> Event | None:
    line = line.strip()
    if not line:
        return None

    m = _RE_SSH_FAILED.match(line)
    if m:
        ts, host, user, src_ip = m.group(1), m.group(2), m.group(3), m.group(4)
        return Event(
            event_id=str(uuid.uuid4()),
            timestamp=_parse_linux_timestamp(ts),
            source_type=SourceType.linux_auth,
            source_host=host,
            source_ip=src_ip,
            username=user,
            action="ssh_failed_password",
            status="failure",
            raw_event={"line": line},
            normalized_message=f"SSH failed password for {user} from {src_ip}",
            severity_hint="medium",
        )

    m = _RE_SSH_INVALID.match(line)
    if m:
        ts, host, user, src_ip = m.group(1), m.group(2), m.group(3), m.group(4)
        return Event(
            event_id=str(uuid.uuid4()),
            timestamp=_parse_linux_timestamp(ts),
            source_type=SourceType.linux_auth,
            source_host=host,
            source_ip=src_ip,
            username=user,
            action="ssh_invalid_user",
            status="failure",
            raw_event={"line": line},
            normalized_message=f"SSH invalid user {user} from {src_ip}",
            severity_hint="medium",
        )

    m = _RE_SSH_ACCEPTED.match(line)
    if m:
        ts, host, user, src_ip = m.group(1), m.group(2), m.group(3), m.group(4)
        return Event(
            event_id=str(uuid.uuid4()),
            timestamp=_parse_linux_timestamp(ts),
            source_type=SourceType.linux_auth,
            source_host=host,
            source_ip=src_ip,
            username=user,
            action="ssh_accepted_password",
            status="success",
            raw_event={"line": line},
            normalized_message=f"SSH accepted password for {user} from {src_ip}",
            severity_hint="info",
        )

    m = _RE_SUDO.match(line)
    if m:
        ts, host, user, cmd = m.group(1), m.group(2), m.group(3), m.group(4).strip()
        return Event(
            event_id=str(uuid.uuid4()),
            timestamp=_parse_linux_timestamp(ts),
            source_type=SourceType.linux_auth,
            source_host=host,
            source_ip=None,
            username=user,
            action="sudo_command",
            status="success",
            raw_event={"line": line, "command": cmd},
            normalized_message=f"sudo command by {user}: {cmd}",
            severity_hint="info",
        )

    m = _RE_SUDO_FAIL.match(line)
    if m:
        ts, host, user = m.group(1), m.group(2), m.group(3)
        return Event(
            event_id=str(uuid.uuid4()),
            timestamp=_parse_linux_timestamp(ts),
            source_type=SourceType.linux_auth,
            source_host=host,
            source_ip=None,
            username=user,
            action="sudo_not_in_sudoers",
            status="failure",
            raw_event={"line": line},
            normalized_message=f"sudo denied: {user} is not in sudoers",
            severity_hint="high",
        )

    return None


def normalize_nginx_line(line: str) -> Event | None:
    line = line.strip()
    if not line:
        return None

    m = _RE_NGINX.match(line)
    if not m:
        return None

    src_ip = m.group(1)
    remote_user = m.group(2) if m.group(2) != "-" else None
    ts_str = m.group(3)
    method = m.group(4)
    path = m.group(5)
    status_code = m.group(6)
    user_agent = m.group(7) or ""

    try:
        ts = datetime.strptime(ts_str, _NGINX_TIMESTAMP_FMT).astimezone(timezone.utc)
    except ValueError:
        ts = datetime.now(timezone.utc)

    return Event(
        event_id=str(uuid.uuid4()),
        timestamp=ts,
        source_type=SourceType.nginx_access,
        source_host="nginx",
        source_ip=src_ip,
        username=remote_user,
        action=f"http_{method.lower()}",
        status=status_code,
        raw_event={"line": line, "path": path, "method": method, "user_agent": user_agent},
        normalized_message=f"{method} {path} {status_code} from {src_ip}",
        severity_hint=None,
    )


def normalize_windows_json(event: dict) -> Event | None:
    try:
        ts_raw = event.get("timestamp", "")
        try:
            ts = datetime.fromisoformat(ts_raw).astimezone(timezone.utc)
        except (ValueError, TypeError):
            ts = datetime.now(timezone.utc)

        event_code = str(event.get("event_code", ""))
        action_map = {
            "4624": "logon_success",
            "4625": "logon_failure",
            "4672": "special_privileges_assigned",
            "4688": "process_creation",
            "4720": "user_account_created",
        }
        action = action_map.get(event_code, f"windows_event_{event_code}")
        status = "success" if event_code in ("4624", "4672", "4720") else "failure"
        if event_code == "4688":
            status = "success"

        return Event(
            event_id=str(uuid.uuid4()),
            timestamp=ts,
            source_type=SourceType.windows_security,
            source_host=event.get("host", "unknown"),
            source_ip=event.get("source_ip"),
            username=event.get("username"),
            action=action,
            status=status,
            raw_event=event,
            normalized_message=f"Windows {event_code}: {action} by {event.get('username', 'unknown')} on {event.get('host', 'unknown')}",
            severity_hint="info",
        )
    except Exception:
        return None


def normalize_cloud_json(event: dict) -> Event | None:
    try:
        ts_raw = event.get("timestamp", "")
        try:
            ts = datetime.fromisoformat(ts_raw).astimezone(timezone.utc)
        except (ValueError, TypeError):
            ts = datetime.now(timezone.utc)

        action = event.get("action", "unknown")
        status = event.get("status", "unknown")

        return Event(
            event_id=str(uuid.uuid4()),
            timestamp=ts,
            source_type=SourceType.cloud_audit,
            source_host=event.get("region", "unknown"),
            source_ip=event.get("source_ip"),
            username=event.get("username"),
            action=action,
            status=status,
            raw_event=event,
            normalized_message=f"Cloud {action} by {event.get('username', 'unknown')} [{status}]",
            severity_hint=None,
        )
    except Exception:
        return None


def _parse_pg_timestamp(ts_str: str) -> datetime:
    try:
        return datetime.strptime(ts_str.strip(), _PG_TIMESTAMP_FMT).replace(tzinfo=timezone.utc)
    except ValueError:
        return datetime.now(timezone.utc)


def normalize_postgres_line(line: str) -> Event | None:
    """Normalize one PostgreSQL server log line into an Event.

    Recognized events: failed password authentication, authorized connection and
    privilege-granting statements (GRANT/REVOKE, role creation and modification).
    Operational noise such as checkpoints or autovacuum returns None, so the
    ingestion counter reports it as skipped rather than as a parse error.
    """
    line = line.strip()
    if not line:
        return None

    m = _RE_PG_PREFIX.match(line)
    if not m:
        return None

    message = m.group("message")
    database = m.group("db")
    source_ip = m.group("host")
    ts = _parse_pg_timestamp(m.group("ts"))
    raw: dict[str, object] = {"line": line, "pid": m.group("pid")}
    if database:
        raw["database"] = database

    failed = _RE_PG_AUTH_FAILED.match(message)
    if failed:
        user = failed.group(1)
        return Event(
            event_id=str(uuid.uuid4()),
            timestamp=ts,
            source_type=SourceType.postgres_audit,
            source_host="postgres",
            source_ip=source_ip,
            username=user,
            action="db_auth_failed",
            status="failure",
            raw_event=raw,
            normalized_message=(
                f"PostgreSQL authentication failed for {user} from {source_ip or 'unknown'}"
            ),
            severity_hint="medium",
        )

    authorized = _RE_PG_CONN_AUTHORIZED.match(message)
    if authorized:
        user = authorized.group(1) or m.group("user")
        db = authorized.group(2) or database
        if db:
            raw["database"] = db
        return Event(
            event_id=str(uuid.uuid4()),
            timestamp=ts,
            source_type=SourceType.postgres_audit,
            source_host="postgres",
            source_ip=source_ip,
            username=user,
            action="db_auth_success",
            status="success",
            raw_event=raw,
            normalized_message=(
                f"PostgreSQL connection authorized for {user} from {source_ip or 'unknown'}"
            ),
            severity_hint="info",
        )

    privilege = _RE_PG_PRIVILEGE.match(message)
    if privilege:
        statement = privilege.group(1).strip()
        raw["statement"] = statement
        return Event(
            event_id=str(uuid.uuid4()),
            timestamp=ts,
            source_type=SourceType.postgres_audit,
            source_host="postgres",
            source_ip=source_ip,
            username=m.group("user"),
            action="db_privilege_change",
            status="success",
            raw_event=raw,
            normalized_message=(
                f"PostgreSQL privilege statement by {m.group('user') or 'unknown'}: {statement}"
            ),
            severity_hint="high",
        )

    return None


def normalize_lines(lines: list[str], source_type: str) -> ParseResult:
    events: list[Event] = []
    skipped = 0
    errors = 0

    for line in lines:
        line = line.strip()
        if not line:
            skipped += 1
            continue
        try:
            if source_type == SourceType.linux_auth:
                ev = normalize_linux_auth_line(line)
            elif source_type == SourceType.nginx_access:
                ev = normalize_nginx_line(line)
            elif source_type == SourceType.windows_security:
                ev = normalize_windows_json(json.loads(line))
            elif source_type == SourceType.cloud_audit:
                ev = normalize_cloud_json(json.loads(line))
            elif source_type == SourceType.postgres_audit:
                ev = normalize_postgres_line(line)
            else:
                skipped += 1
                continue

            if ev is not None:
                events.append(ev)
            else:
                skipped += 1
        except Exception:
            errors += 1

    return ParseResult(events=events, skipped_count=skipped, error_count=errors)


def normalize_content(content: str, source_type: str) -> ParseResult:
    return normalize_lines(content.splitlines(), source_type)


def normalize_file(path: str, source_type: str) -> ParseResult:
    try:
        with open(path, encoding="utf-8") as f:
            content = f.read()
    except OSError:
        return ParseResult(events=[], skipped_count=0, error_count=1)
    return normalize_lines(content.splitlines(), source_type)
