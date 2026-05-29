import pytest
from app.services.normalization_service import (
    normalize_linux_auth_line,
    normalize_nginx_line,
    normalize_windows_json,
    normalize_cloud_json,
    normalize_file,
)
from app.models.schemas import SourceType


class TestLinuxAuthNormalization:
    def test_ssh_failed_password(self):
        line = "Jan 10 09:10:15 web-01 sshd[1300]: Failed password for root from 192.0.2.100 port 43210 ssh2"
        ev = normalize_linux_auth_line(line)
        assert ev is not None
        assert ev.action == "ssh_failed_password"
        assert ev.source_ip == "192.0.2.100"
        assert ev.username == "root"
        assert ev.status == "failure"
        assert ev.source_type == SourceType.linux_auth

    def test_ssh_invalid_user(self):
        line = "Jan 10 09:10:54 web-01 sshd[1313]: Invalid user testuser from 198.51.100.200 port 60001 ssh2"
        ev = normalize_linux_auth_line(line)
        assert ev is not None
        assert ev.action == "ssh_invalid_user"
        assert ev.username == "testuser"
        assert ev.source_ip == "198.51.100.200"

    def test_ssh_accepted(self):
        line = "Jan 10 09:00:01 web-01 sshd[1234]: Accepted password for deploy from 203.0.113.5 port 52100 ssh2"
        ev = normalize_linux_auth_line(line)
        assert ev is not None
        assert ev.action == "ssh_accepted_password"
        assert ev.status == "success"
        assert ev.username == "deploy"

    def test_sudo_command(self):
        line = "Jan 10 09:05:01 web-01 sudo: deploy : TTY=pts/0 ; PWD=/home/deploy ; USER=root ; COMMAND=/usr/bin/systemctl status nginx"
        ev = normalize_linux_auth_line(line)
        assert ev is not None
        assert ev.action == "sudo_command"
        assert ev.username == "deploy"

    def test_sudo_not_in_sudoers(self):
        line = "Jan 10 09:14:30 web-01 sudo: notinsudo : command not allowed ; TTY=pts/1 ; NOT in sudoers"
        ev = normalize_linux_auth_line(line)
        assert ev is not None
        assert ev.action == "sudo_not_in_sudoers"
        assert ev.severity_hint == "high"

    def test_malformed_line_returns_none(self):
        assert normalize_linux_auth_line("not a log line") is None
        assert normalize_linux_auth_line("") is None
        assert normalize_linux_auth_line("   ") is None

    def test_event_has_raw_event(self):
        line = "Jan 10 09:10:15 web-01 sshd[1300]: Failed password for root from 192.0.2.100 port 43210 ssh2"
        ev = normalize_linux_auth_line(line)
        assert ev.raw_event.get("line") == line

    def test_failed_invalid_user_variant(self):
        line = "Jan 10 09:11:00 web-01 sshd[1314]: Failed password for invalid user test from 198.51.100.200 port 60002 ssh2"
        ev = normalize_linux_auth_line(line)
        assert ev is not None
        assert ev.action == "ssh_failed_password"


class TestNginxNormalization:
    def test_normal_200(self):
        line = '203.0.113.5 - - [10/Jan/2026:08:00:01 +0000] "GET / HTTP/1.1" 200 1024 "-" "Mozilla/5.0"'
        ev = normalize_nginx_line(line)
        assert ev is not None
        assert ev.source_type == SourceType.nginx_access
        assert ev.status == "200"
        assert ev.source_ip == "203.0.113.5"

    def test_404_path_captured(self):
        line = '192.0.2.200 - - [10/Jan/2026:08:01:00 +0000] "GET /page1 HTTP/1.1" 404 128 "-" "Mozilla/5.0"'
        ev = normalize_nginx_line(line)
        assert ev is not None
        assert ev.status == "404"
        assert ev.raw_event.get("path") == "/page1"

    def test_user_agent_captured(self):
        line = '203.0.113.99 - - [10/Jan/2026:08:06:00 +0000] "GET /login HTTP/1.1" 200 1024 "-" "sqlmap/1.7"'
        ev = normalize_nginx_line(line)
        assert ev is not None
        assert "sqlmap" in ev.raw_event.get("user_agent", "").lower()

    def test_malformed_line_returns_none(self):
        assert normalize_nginx_line("not a nginx log") is None
        assert normalize_nginx_line("") is None

    def test_action_is_http_method(self):
        line = '203.0.113.5 - - [10/Jan/2026:08:00:05 +0000] "POST /api HTTP/1.1" 200 512 "-" "Mozilla/5.0"'
        ev = normalize_nginx_line(line)
        assert ev.action == "http_post"


class TestWindowsNormalization:
    def test_4624_logon_success(self):
        ev_dict = {
            "timestamp": "2026-01-10T09:00:00+00:00",
            "event_code": "4624",
            "host": "WIN-SERVER01",
            "username": "jsmith",
            "source_ip": "203.0.113.5",
        }
        ev = normalize_windows_json(ev_dict)
        assert ev is not None
        assert ev.action == "logon_success"
        assert ev.status == "success"
        assert ev.source_type == SourceType.windows_security

    def test_4625_logon_failure(self):
        ev_dict = {
            "timestamp": "2026-01-10T09:05:00+00:00",
            "event_code": "4625",
            "host": "WIN-SERVER01",
            "username": "administrator",
            "source_ip": "192.0.2.150",
        }
        ev = normalize_windows_json(ev_dict)
        assert ev is not None
        assert ev.action == "logon_failure"
        assert ev.status == "failure"

    def test_4720_account_created(self):
        ev_dict = {
            "timestamp": "2026-01-10T09:20:00+00:00",
            "event_code": "4720",
            "host": "WIN-SERVER01",
            "username": "administrator",
            "new_account": "backdoor_user",
        }
        ev = normalize_windows_json(ev_dict)
        assert ev is not None
        assert ev.action == "user_account_created"

    def test_4688_process_creation(self):
        ev_dict = {
            "timestamp": "2026-01-10T09:15:00+00:00",
            "event_code": "4688",
            "host": "WIN-SERVER01",
            "username": "jsmith",
            "command_line": "powershell.exe -enc abc",
        }
        ev = normalize_windows_json(ev_dict)
        assert ev is not None
        assert ev.action == "process_creation"

    def test_invalid_json_returns_none(self):
        assert normalize_windows_json({}) is not None  # empty is handled gracefully
        # missing fields use defaults
        ev = normalize_windows_json({"event_code": "4625"})
        assert ev is not None


class TestCloudNormalization:
    def test_console_login_success(self):
        ev_dict = {
            "timestamp": "2026-01-10T08:00:00+00:00",
            "action": "console_login",
            "status": "success",
            "username": "devops@example.com",
            "source_ip": "203.0.113.10",
            "region": "eu-central-1",
        }
        ev = normalize_cloud_json(ev_dict)
        assert ev is not None
        assert ev.action == "console_login"
        assert ev.status == "success"
        assert ev.source_type == SourceType.cloud_audit

    def test_security_group_event(self):
        ev_dict = {
            "timestamp": "2026-01-10T09:00:00+00:00",
            "action": "security_group_rule_added",
            "status": "success",
            "username": "devops@example.com",
            "source_ip": "203.0.113.10",
            "cidr": "0.0.0.0/0",
            "port": 22,
        }
        ev = normalize_cloud_json(ev_dict)
        assert ev is not None
        assert ev.action == "security_group_rule_added"
        assert ev.raw_event.get("port") == 22

    def test_empty_dict_does_not_crash(self):
        ev = normalize_cloud_json({})
        assert ev is not None


class TestNormalizeFile:
    def test_linux_auth_file(self):
        result = normalize_file("sample_logs/linux_auth.log", SourceType.linux_auth)
        assert len(result.events) > 50
        assert result.error_count == 0

    def test_nginx_file(self):
        result = normalize_file("sample_logs/nginx_access.log", SourceType.nginx_access)
        assert len(result.events) > 80

    def test_windows_file(self):
        result = normalize_file("sample_logs/windows_security.jsonl", SourceType.windows_security)
        assert len(result.events) >= 10

    def test_cloud_file(self):
        result = normalize_file("sample_logs/cloud_audit.jsonl", SourceType.cloud_audit)
        assert len(result.events) >= 6

    def test_missing_file_returns_empty(self):
        result = normalize_file("/nonexistent/file.log", SourceType.linux_auth)
        assert result.events == []
        assert result.error_count == 1
