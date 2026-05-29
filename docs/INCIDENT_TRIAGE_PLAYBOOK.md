# Incident Triage Playbook

This playbook describes how to handle alerts produced by each detection rule.
Status transitions: `new` → `triaged` → (`escalated` | `false_positive` | `closed`).

---

## SSH_BRUTE_FORCE

**Meaning:** A single source IP attempted to authenticate via SSH many times in a short period.

**MITRE ATT&CK:** T1110.001 — Brute Force: Password Guessing (Credential Access, direct)

**How to validate:**
1. Check the source IP against known IPs (VPN pool, IT team, pentest scope).
2. Count failures over time: is the rate automated (many per second) or manual?
3. Check if any account was eventually compromised (see SSH_BRUTE_FORCE_SUCCESS).

**Analyst action:**
- If unauthorized: add IP to firewall blocklist. Enable fail2ban if not already.
- If authorized pentest: mark `false_positive`, note ticket number.
- If uncertain: mark `triaged`, request confirmation from IT.

**Escalation criteria:** Severity is `high` or `critical`, or the same IP triggered SSH_BRUTE_FORCE_SUCCESS.

**False positives:** Authorized pentest, vulnerability scanner, IT team scripted access.

---

## SSH_BRUTE_FORCE_SUCCESS

**Meaning:** An IP that was actively brute-forcing SSH managed to authenticate successfully.

**MITRE ATT&CK:** T1078 — Valid Accounts (Initial Access, approximate)

**How to validate:**
1. Confirm the successful login: check `who` output and `last` logs on the target host.
2. Identify the authenticated username and whether it is a privileged account.
3. Review what commands were run in the session (audit logs, bash_history).

**Analyst action:**
- Lock the compromised account immediately.
- Rotate credentials for the affected user.
- Isolate the host if privileged access was gained.
- Preserve logs and initiate incident response.

**Escalation criteria:** Always escalate unless confirmed authorized test.

**False positives:** Authorized pentest where authentication is expected. Verify against scope document.

---

## WEB_DIR_SCAN

**Meaning:** An IP generated a high volume of HTTP 404 responses, indicating automated directory enumeration.

**MITRE ATT&CK:** T1595.002 — Active Scanning: Vulnerability Scanning (Reconnaissance, approximate)

**How to validate:**
1. Check what paths were requested — are they guessing admin panels, CMS paths, or backup files?
2. Verify the User-Agent — scanner tools often identify themselves.
3. Check if any sensitive path returned 200 or 302 (cross-check with SENSITIVE_PATH_ACCESS).

**Analyst action:**
- Block the scanning IP at the WAF or firewall.
- Review if any sensitive content was exposed.
- Mark `triaged` and document what was found.

**Escalation criteria:** Any sensitive path returned 200 during the scan.

**False positives:** Broken links, misconfigured redirects, legitimate search engine crawlers.

---

## SENSITIVE_PATH_ACCESS

**Meaning:** An HTTP request was made to a file or path that should not be publicly accessible.

**MITRE ATT&CK:** T1083 — File and Directory Discovery (Discovery, approximate)

**How to validate:**
1. Check the HTTP status code: 200/302 means content was served — treat as data exposure.
2. Identify what file was requested: /.env may contain database credentials.
3. Check the server logs for the full response body if possible.

**Analyst action:**
- Severity high (200/302): Treat as data exposure incident. Rotate any credentials in the exposed file.
- Severity medium (403/404): Configure server to block the path. Monitor for repeated attempts.

**Escalation criteria:** HTTP status is 200 or 302. Escalate to data exposure incident.

**False positives:** Internal monitoring agents, developer tools, authorized admin access.

---

## SUSPICIOUS_USER_AGENT

**Meaning:** A request was made with a User-Agent string associated with a known security scanning tool.

**MITRE ATT&CK:** T1595 — Active Scanning (Reconnaissance, approximate)

**How to validate:**
1. Check if there is an active pentest engagement that covers this system.
2. Identify what paths were accessed and whether any returned sensitive data.
3. Correlate with WEB_DIR_SCAN and SENSITIVE_PATH_ACCESS alerts.

**Analyst action:**
- If unauthorized: block IP, open investigation.
- If authorized: mark `false_positive`, document pentest scope.

**Escalation criteria:** Tool accessed sensitive paths that returned 200.

**False positives:** Authorized penetration testing. Always check the change management calendar.

---

## WIN_ACCOUNT_CREATED_AFTER_FAILURES

**Meaning:** A user account was created on a Windows host that recently experienced multiple failed logon attempts.

**MITRE ATT&CK:** T1136.001 — Create Account: Local Account (Persistence, direct)

**How to validate:**
1. Identify the new account name from Event 4720.
2. Check if there is an ITSM ticket authorizing the account creation.
3. Check Event 4672 — did the creating session have privileged access?
4. Verify the source IP of the 4625 failures matches the context of the 4720.

**Analyst action:**
- Disable the new account immediately if not authorized.
- Investigate the source of the login failures.
- Review all privileged events on the host for the relevant time window.

**Escalation criteria:** No ITSM ticket found for the account creation, or the new account has admin rights.

**False positives:** IT onboarding coinciding with system-level authentication errors.

---

## CLOUD_SG_OPEN

**Meaning:** A cloud security group rule was added that allows inbound traffic from the internet (0.0.0.0/0) on a sensitive port.

**MITRE ATT&CK:** T1562.007 — Impair Defenses: Disable or Modify Cloud Firewall (Defense Evasion, approximate)

**How to validate:**
1. Check the change management system for an authorized ticket.
2. Identify who made the change (username, source IP).
3. Verify the affected resource and whether the port is exposed to production data.

**Analyst action:**
- Restrict the rule to known IP ranges immediately.
- If no ticket: treat as unauthorized change and escalate.
- Review all activity from the modifying account in the same time window.

**Escalation criteria:** Rule applies to DB ports (5432, 3306, 27017) or was made without a ticket.

**False positives:** Short-lived rules for maintenance windows. Always require a ticket.

---

## CLOUD_IAM_CHANGE_AFTER_FAILURE

**Meaning:** An IAM policy was modified by an account that had recent failed console login attempts.

**MITRE ATT&CK:** T1098 — Account Manipulation (Persistence, approximate)

**How to validate:**
1. Check CloudTrail for the full event context.
2. Verify whether the login failures and the IAM change are from the same session or different sessions.
3. Check the target of the IAM change — was admin access granted to an unusual account?

**Analyst action:**
- If unauthorized: revert the IAM change immediately. Investigate account compromise.
- If authorized: mark `triaged`, document the reason for the failures.

**Escalation criteria:** IAM change granted AdminFullAccess or broad permissions to a service account.

**False positives:** Password rotation followed by a scheduled IAM policy update.

---

## MULTI_SOURCE_SUSPICIOUS_IP

**Meaning:** The same IP address appears in suspicious events across multiple log sources simultaneously.

**MITRE ATT&CK:** Multiple techniques (cross-source correlation indicator, approximate — see contributing alerts for individual mappings)

**How to validate:**
1. Review all alerts involving this IP.
2. Determine the time range and whether access was concurrent.
3. Assess the combined impact: SSH + web + cloud activity from one IP is a strong signal.

**Analyst action:**
- Block IP at perimeter firewall immediately.
- Initiate incident response procedure.
- Preserve all relevant logs before they rotate.
- Notify the security team.

**Escalation criteria:** Always escalate. Multi-source activity indicates coordinated or automated attack.

**False positives:** Authorized multi-system security scanner or pentest. Verify against scope document before blocking.
