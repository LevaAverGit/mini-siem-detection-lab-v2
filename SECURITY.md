# Security policy

This is a personal, educational security project. It is a lab, not a production
service — but if you find a genuine vulnerability in the code (as opposed to the
examples it ships on purpose to demonstrate a risk), I'd like to hear about it.

## Reporting

Email **levaaverianov@gmail.com** with a description and, if you can, a way to
reproduce it. Please don't file a public issue for a real security bug — reach
out privately first and give me a reasonable window to fix it before disclosure.

## Scope

The ingestion, detection, and reporting code, plus the Grafana dashboard setup.

## Grafana dashboard

The dashboard (`docker-compose.yml` + `grafana/`) is a local analyst tool. Its
whole security posture rests on the `127.0.0.1` port bind:

- It binds to `127.0.0.1` only — never exposed to a network.
- The SIEM database is mounted **read-only**, so a dashboard query cannot write
  back to the detection data. The `frser-sqlite-datasource` plugin runs
  server-side, so any principal who can view a panel can also send arbitrary
  read-only SQL to the datasource via Grafana's `/api/ds/query` endpoint — the
  static panel queries do not limit that. On loopback the only such principal is
  the local user, who already owns the db file; off localhost it would be
  world-readable.
- Anonymous access is read-only `Viewer`; sign-up is disabled; telemetry, update
  checks, and the news feed are off.
- The `admin` / `admin` credentials in `docker-compose.yml` are a **dev-only
  local value**, documented, not a secret.
- The Grafana image and the community plugin are pinned by version. The plugin
  is fetched from the Grafana catalog at container start (signature-verified);
  update the image periodically against Grafana's security advisories.

**Do not expose this stack off `127.0.0.1`.** Making it network-reachable
requires, together: disabling anonymous access, replacing `admin/admin`, adding
TLS, updating the image, and adding container-hardening flags (`cap_drop`,
read-only rootfs). Any one of those alone leaves a hole.
