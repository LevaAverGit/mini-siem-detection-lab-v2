# Example Incident Report: SSH Brute Force with Successful Compromise

> **Note:** This is a synthetic example generated from the lab's sample logs.
> All IP addresses, usernames, and timestamps are fictional and used for
> demonstration purposes only. This format illustrates what a SOC L1 analyst
> would produce during initial triage using this detection pipeline.

---

## Incident Summary

| Field | Value |
|---|---|
| **Incident ID** | INC-2026-0042 |
| **Severity** | Critical |
| **Status** | Escalated |
| **Detection time** | 2026-05-20 03:17:42 UTC |
| **Source IP** | 198.51.100.47 |
| **Affected host** | prod-web-01 (10.0.1.15) |
| **Affected account** | deploy |
| **Detection rules triggered** | SSH_BRUTE_FORCE, SSH_BRUTE_FORCE_SUCCESS |
| **Score** | 100 (Critical) |
| **MITRE ATT&CK** | T1110.001 (Brute Force: Password Guessing) → T1078 (Valid Accounts) |
| **Analyst** | SOC L1 |

---

## Timeline

| Time (UTC) | Event | Source | Detail |
|---|---|---|---|
| 03:11:02 | First failed SSH attempt | linux_auth | user=root from 198.51.100.47 |
| 03:11:03 | Rapid failure sequence begins | linux_auth | 10 attempts in 15 seconds |
| 03:14:28 | SSH_BRUTE_FORCE alert fired | detection | 47 failures — threshold HIGH (30) crossed |
| 03:17:41 | 112 total failures logged | linux_auth | threshold CRITICAL (100) crossed |
| 03:17:42 | **Successful SSH login** | linux_auth | user=deploy, same source IP |
| 03:17:42 | **SSH_BRUTE_FORCE_SUCCESS alert fired** | detection | Score: 100 / Critical |
| 03:17:45 | Incident grouped by source IP | incident engine | Correlation: same IP triggered both rules |

---

## Evidence

**Rule 1: SSH_BRUTE_FORCE**
- 112 failed authentication attempts from 198.51.100.47
- Targeted users: root (89 attempts), admin (14), deploy (9)
- Failure rate: ~1.2 attempts/second (automated pattern)
- Log sample: `May 20 03:11:03 prod-web-01 sshd[4821]: Failed password for root from 198.51.100.47 port 52341 ssh2`

**Rule 2: SSH_BRUTE_FORCE_SUCCESS**
- Successful login as `deploy` at 03:17:42 — same source IP after 9 targeted failures on that account
- Log sample: `May 20 03:17:42 prod-web-01 sshd[4891]: Accepted password for deploy from 198.51.100.47 port 52389 ssh2`

---

## MITRE ATT&CK Mapping

| Stage | Tactic | Technique | Confidence |
|---|---|---|---|
| Initial attack | Credential Access (TA0006) | T1110.001 Brute Force: Password Guessing | direct |
| Compromise achieved | Initial Access (TA0001) | T1078 Valid Accounts | direct |
| Potential next stage | Persistence (TA0003) | T1136.001 Create Account: Local Account | not observed |
| Potential next stage | Lateral Movement (TA0008) | T1021.004 Remote Services: SSH | not observed |

---

## Affected Assets

| Asset | Role | Risk |
|---|---|---|
| prod-web-01 (10.0.1.15) | Production web server | Potentially fully compromised |
| `deploy` account | Deployment service account | Credentials confirmed compromised |
| Deployment pipeline | CI/CD access | Unknown — requires investigation |

---

## Detection Logic

The incident was detected by correlation of two rules:

1. **SSH_BRUTE_FORCE** — threshold-based: fires when a single source IP accumulates > 30 failed SSH logins (medium), > 30 (high), > 100 (critical)
2. **SSH_BRUTE_FORCE_SUCCESS** — pattern-based: fires when a source IP with ≥ 5 prior failures achieves a successful login

Both alerts were grouped into one incident by the incident engine (source IP correlation).

---

## Recommended Response

**Immediate (0–15 minutes):**
- [ ] Block 198.51.100.47 at the firewall/security group level
- [ ] Kill the active SSH session (`who`, `w`, `last`, `pkill -u deploy`)
- [ ] Rotate the `deploy` account credentials immediately
- [ ] Revoke any active SSH keys associated with `deploy`

**Short-term (15–60 minutes):**
- [ ] Review all commands executed by `deploy` since 03:17:42 (bash history, auth.log, /var/log/secure)
- [ ] Check for new crontabs, SSH authorized_keys, systemd services, or new user accounts
- [ ] Review deployment pipeline access and revoke tokens if pipeline keys were stored on the host
- [ ] Check for data exfiltration: outbound connections from prod-web-01 since compromise

**Escalation:**
- Escalate to L2/IR team — potential full system compromise
- Preserve logs before rotation: `cp /var/log/auth.log /evidence/auth_INC-2026-0042.log`

---

## False Positive Assessment

**Is this a false positive?** No.

- 112 failures in 6 minutes at 1.2/second = automated tooling (not human mistyping)
- Successful login immediately after 9 targeted failures on the `deploy` account
- Production host targeted at 03:17 UTC (unusual hours)
- 198.51.100.47 not in known IP allowlist

---

## Lessons Learned

- `deploy` account had a weak/guessable password — should be replaced with key-based auth only
- fail2ban was not configured on prod-web-01 — would have blocked the IP after 5 failures
- SSH should not be exposed on port 22 to 0.0.0.0 — restrict to VPN or bastion host IP range
- Alert latency: 6 minutes from first failure to SSH_BRUTE_FORCE_SUCCESS — acceptable for lab, too slow for production

---

*Generated by Mini SIEM Detection Lab — synthetic example for portfolio demonstration.*
*See `app/rules/default_rules.yml` for rule definitions. See `docs/INCIDENT_TRIAGE_PLAYBOOK.md` for analyst procedures.*
