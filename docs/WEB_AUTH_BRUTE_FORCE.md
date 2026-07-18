# Detection Write-up — Web Application Login Brute Force

**Rule ID:** `WEB_AUTH_BRUTE_FORCE`
**Source:** `nginx_access`
**MITRE ATT&CK:** T1110 — Brute Force (Tactic: Credential Access)

---

## Scenario

An attacker (or a botnet running a credential-stuffing list) hammers the
application's login endpoint with username/password guesses. Each failed attempt
returns an HTTP `401 Unauthorized` (or `403 Forbidden`). Unlike SSH brute force,
this activity never touches the OS auth log — it is only visible in the **web
server access log**, which is why it needs its own detection separate from
`SSH_BRUTE_FORCE`.

## Detection logic

For each source IP, count responses that satisfy **all** of:

1. Source type is `nginx_access`.
2. HTTP status is in `fail_statuses` (`401`, `403`).
3. The request path starts with a known login endpoint
   (`/login`, `/api/login`, `/admin/login`, `/wp-login.php`, `/signin`, `/auth`).

Severity escalates with volume:

| Failed logins from one IP | Severity | Score |
|---|---|---|
| >= 5 | medium | 40 |
| >= 20 | high | 70 |
| >= 50 | critical | 95 |

Configuration lives in `app/rules/default_rules.yml`; the logic is in
`_detect_web_auth_brute_force` in `app/services/detection_engine.py`. The Sigma
equivalent is `sigma_rules/web_auth_brute_force.yml`.

## Why status-scoping matters

The rule only counts `401`/`403`. A **`200` on the login path is deliberately not
counted** as a failure — but it is the single most important thing to check next: a
`200`/`302` following a burst of `401`s (as in `sample_logs/nginx_auth_bruteforce.log`)
suggests the attacker finally guessed valid credentials. Treat that session as a
possible account takeover.

## Tuning / false positives

- **Corporate NAT:** many employees behind one egress IP can inflate the count.
  Raise the threshold or key on IP + username where the log carries a username.
- **Forgotten password sprees:** a single real user rarely exceeds ~5–10 attempts;
  the `high` threshold (20) filters most of this out.
- **Health-check bots** hitting an authenticated endpoint — allowlist their IPs.

## Response

1. Confirm the volume and time window; check for a trailing `200`/`302`.
2. Rate-limit the login endpoint; enforce lockout or exponential backoff.
3. Require MFA/CAPTCHA after N failures.
4. Block or challenge the source IP if it is clearly automated.
5. If a success followed the burst, force a password reset and review the session.
