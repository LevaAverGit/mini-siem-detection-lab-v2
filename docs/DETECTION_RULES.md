# Detection Rules

All rules are defined in `app/rules/default_rules.yml` and loaded at runtime.

---

## SSH_BRUTE_FORCE

**Source:** linux_auth
**Logic:** Count of `ssh_failed_password` or `ssh_invalid_user` events from the same source_ip.
**Thresholds:** medium >= 10, high >= 30, critical >= 100
**Scores:** medium = 40, high = 70, critical = 100
**Evidence:** Failure count, IP address, threshold hit
**Recommendation:** Block source IP at firewall. Configure fail2ban. Verify no privileged accounts targeted.
**False positives:** Authorized pen testing, security scanners, vulnerability assessment tools.

**MITRE ATT&CK mapping:**
- Tactic: Credential Access
- Technique: T1110.001 — Brute Force: Password Guessing
- Confidence: direct
- Notes: Repeated failed SSH authentication from a single IP is a direct indicator of T1110.001.

---

## SSH_BRUTE_FORCE_SUCCESS

**Source:** linux_auth
**Logic:** Same source_ip has >= 5 failed SSH attempts AND at least one accepted login.
**Severity:** critical
**Score:** 100
**Evidence:** Failure count, successful login username
**Recommendation:** Review session immediately. Rotate credentials. Consider system compromised until verified.
**False positives:** Authorized access after multiple typos. Verify with asset owner.

**MITRE ATT&CK mapping:**
- Tactic: Initial Access
- Technique: T1078 — Valid Accounts
- Confidence: approximate
- Notes: Mapping is approximate. The rule detects a successful login following brute force activity, which is consistent with T1078 (use of valid credentials). The rule does not confirm that the account was obtained by the attacker — analyst validation is required.

---

## WEB_DIR_SCAN

**Source:** nginx_access
**Logic:** Count of HTTP 404 responses from the same source_ip.
**Thresholds:** medium >= 30, high >= 80
**Scores:** medium = 40, high = 70
**Evidence:** 404 count, sample paths probed
**Recommendation:** Block scanning IP at WAF or firewall. Review if any sensitive paths returned 200.
**False positives:** Broken internal links, misconfigured redirects, legitimate crawlers.

**MITRE ATT&CK mapping:**
- Tactic: Reconnaissance
- Technique: T1595.002 — Active Scanning: Vulnerability Scanning
- Confidence: approximate
- Notes: Mapping is approximate. High 404 volume is consistent with automated directory enumeration, which is a form of active scanning. Not all 404 spikes are malicious — analyst validation is required.

---

## SENSITIVE_PATH_ACCESS

**Source:** nginx_access
**Logic:** HTTP request path matches a list of known sensitive paths.
**Paths:** `/.env`, `/.git`, `/admin`, `/phpmyadmin`, `/backup`, `/wp-admin`, `/config`
**Severity:** high if status 200/302; medium if 403/404/other
**Scores:** high = 80, medium = 35
**Evidence:** Path, HTTP status, source IP
**Recommendation:** Block sensitive paths at web server level. If /.env returned 200, treat as data exposure.
**False positives:** Developer tools, internal monitoring agents, authorized admin access.

**MITRE ATT&CK mapping:**
- Tactic: Discovery
- Technique: T1083 — File and Directory Discovery
- Confidence: approximate
- Notes: Mapping is approximate. Access to sensitive paths via HTTP is a surface-level indicator of file discovery. The technique applies more precisely to local filesystem enumeration; analyst validation is required for web-facing access.

---

## SUSPICIOUS_USER_AGENT

**Source:** nginx_access
**Logic:** Request `User-Agent` header contains a known security scanner string.
**Scanner strings:** sqlmap, nikto, nmap, masscan, gobuster, dirbuster, python-requests
**Severity:** high if accessing sensitive path or status 200/302; medium otherwise
**Scores:** high = 75, medium = 40
**Evidence:** User agent string, path, HTTP status
**Recommendation:** Verify if authorized pentest. Block IP if unauthorized. Review all requests for data exposure.
**False positives:** Authorized pentest tools, security assessments. Always check authorization records.

**MITRE ATT&CK mapping:**
- Tactic: Reconnaissance
- Technique: T1595 — Active Scanning
- Confidence: approximate
- Notes: Mapping is approximate. A scanner user agent indicates automated reconnaissance activity but does not confirm a specific sub-technique without reviewing the paths accessed. Analyst validation is required.

---

## WEB_EXPLOIT_ATTEMPT

**Source:** nginx_access
**Logic:** The request path is URL-decoded (WAF-style) and, together with the `User-Agent` header, matched against known web-exploit payload signatures.
**Categories:** SQL injection, path traversal, Log4Shell (JNDI), OS command injection, cross-site scripting
**Severity:** high
**Score:** 85
**Evidence:** Matched category, raw and decoded request path, User-Agent, HTTP status, source IP
**Recommendation:** Confirm whether the request reached a vulnerable endpoint (2xx/5xx). Block the source IP at the WAF, review the targeted parameter, and check for signs of successful exploitation. For Log4Shell, verify affected Java services are patched and outbound LDAP/RMI is blocked.
**False positives:** Authorized pentest/WAF tuning; legitimate paths that coincidentally contain a flagged substring. Always check authorization records.

**MITRE ATT&CK mapping:**
- Tactic: Initial Access
- Technique: T1190 — Exploit Public-Facing Application
- Confidence: direct
- Notes: A known exploit payload in the request is a direct indicator of an attempt to exploit a public-facing application (T1190). The alert reflects an *attempt*; whether exploitation succeeded requires reviewing the response and downstream activity.

---

## WIN_ACCOUNT_CREATED_AFTER_FAILURES

**Source:** windows_security
**Logic:** Event 4720 (user account created) on a host that had >= 3 events of type 4625 (logon failure).
**Severity:** high
**Score:** 80
**Evidence:** 4625 failure count, 4720 account name
**Recommendation:** Verify account creation is authorized. Disable account if unexpected. Review 4672 context.
**False positives:** Scheduled account provisioning, IT onboarding workflows. Correlate with ITSM tickets.

**MITRE ATT&CK mapping:**
- Tactic: Persistence
- Technique: T1136.001 — Create Account: Local Account
- Confidence: direct
- Notes: Event 4720 (user account created) is a direct indicator of T1136.001. The correlation with preceding 4625 logon failures elevates the suspicion level but does not change the technique mapping.

---

## CLOUD_SG_OPEN

**Source:** cloud_audit
**Logic:** `security_group_rule_added` event with CIDR `0.0.0.0/0` on a dangerous port.
**Dangerous ports:** 22, 3389, 3306, 5432, 27017
**Severity:** critical for DB ports (5432, 3306, 27017); high for remote access ports (22, 3389)
**Scores:** critical = 95, high = 80
**Evidence:** SG ID, CIDR, port, region, modifier
**Recommendation:** Restrict rule to known IP ranges immediately. Audit who added the rule.
**False positives:** Maintenance windows with intentionally open rules. Always require a ticket.

**MITRE ATT&CK mapping:**
- Tactic: Defense Evasion
- Technique: T1562.007 — Impair Defenses: Disable or Modify Cloud Firewall
- Confidence: approximate
- Notes: Mapping is approximate. Opening a security group to 0.0.0.0/0 weakens network perimeter controls, which is consistent with T1562.007. However, the event may represent a misconfiguration rather than deliberate defense evasion — analyst validation is required.

---

## CLOUD_IAM_CHANGE_AFTER_FAILURE

**Source:** cloud_audit
**Logic:** IAM policy change (`iam_policy_changed`) by a user or from a source IP that had recent `console_login` failures.
**Severity:** high
**Score:** 85
**Evidence:** Failure count, policy name, change type, target user
**Recommendation:** Verify IAM change is authorized. If failures preceded the change from same entity, treat as possible account takeover.
**False positives:** Scheduled automation, password rotation followed by legitimate IAM change. Verify with CloudTrail.

**MITRE ATT&CK mapping:**
- Tactic: Persistence
- Technique: T1098 — Account Manipulation
- Confidence: approximate
- Notes: Mapping is approximate. IAM policy modification is consistent with T1098 when performed to maintain or escalate access. The correlation with prior login failures increases suspicion but does not confirm malicious intent — analyst validation is required.

---

## MULTI_SOURCE_SUSPICIOUS_IP

**Source:** all (cross-source)
**Logic:** A source_ip that appears in suspicious alerts from 2 or more different source types.
**Severity:** critical
**Score:** 100
**Evidence:** List of involved source types, related alert IDs
**Recommendation:** Block IP at perimeter immediately. Initiate incident response. Preserve all logs.
**False positives:** Authorized security scanner operating across multiple systems. Always check change records.

**MITRE ATT&CK mapping:**
- Tactic: Multiple
- Technique: Multiple — Cross-source correlation indicator
- Confidence: approximate
- Notes: This is a correlation rule, not a direct ATT&CK technique. An IP appearing across multiple source types simultaneously suggests coordinated activity but the specific techniques depend on the underlying single-source alerts. Review the contributing alerts for individual technique mappings.
