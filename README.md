# VulnScan — Authorized Web Vulnerability Scanning Platform

A local web dashboard that automates first-pass vulnerability discovery against
web targets. Built for authorized penetration testing and security assessments.

**Hybrid engine:** a self-contained crawler and set of checks (no external tools
required), with optional hooks into `nuclei` and `nmap` when they are installed.

> ⚠️ **Authorization is mandatory.** Every scan requires you to confirm you have
> written permission to test the target. The platform refuses to scan without it,
> blocks cloud-metadata endpoints, and will not touch private/internal IPs unless
> you explicitly opt in. Scanning systems you don't own or lack permission to test
> is illegal. You are responsible for staying within your engagement's scope.

## What it checks

**Built-in (always available)**
- Recon & fingerprinting — server/tech banners, version disclosure, robots/security.txt
- TLS — expired/expiring certificates, deprecated TLS 1.0/1.1, HTTP-only services
- Security headers — HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy
- Cookies — missing HttpOnly / Secure / SameSite flags
- HTTP methods — risky PUT/DELETE/TRACE/CONNECT
- Exposure — `.env`, `.git`, backups, DB dumps, phpinfo, directory listing, etc.
- Crawler — same-origin page/form/parameter mapping
- Injection heuristics — reflected XSS, error-based SQLi, open redirect (non-destructive probes)
- CORS — reflected-origin, credentialed wildcard, and `null`-origin misconfigurations
- JWT — `alg:none` unsigned tokens, weak/guessable HMAC secrets (offline cracking),
  expired tokens, sensitive claims (harvested from cookies & Authorization headers)
- SSRF — maps URL-taking parameters as sinks; with an OAST callback host, injects
  out-of-band probes for blind-SSRF confirmation
- Subdomain enumeration (opt-in) — DNS-resolves a wordlist under the registrable domain

**Optional (auto-detected on PATH)**
- `nuclei` — community template scan, results normalized into the report
- `nmap` — common-port service scan

## Install

```bash
cd vulnscan
python -m venv .venv
# Windows:
.venv\Scripts\activate
# macOS/Linux:
source .venv/bin/activate

pip install -r requirements.txt
```

Optional, for the extra engines, install separately and ensure they're on your PATH:
- nuclei: https://github.com/projectdiscovery/nuclei
- nmap: https://nmap.org/download

## Run

```bash
python run.py
```

Open http://127.0.0.1:8000, enter a target, tick **"I am authorized to test this
target,"** and launch. Scans run in the background; the detail view streams live
logs and findings. Export an HTML or JSON report per scan.

## Authenticated scanning

Most real bugs live behind the login wall. VulnScan can carry an authenticated
session so the crawler and checks reach protected pages. Three modes (in **Scan
options → Authentication**):

- **Header / Bearer token** — attaches an `Authorization` (or custom) header to every
  request. Paste `Bearer eyJ...` or an API key.
- **Session cookie** — attaches a raw `Cookie` string (e.g. session cookies copied
  from your browser's devtools).
- **Form login** — submits a login form for you. Give the login URL, the username/
  password field names and values. CSRF/hidden fields are auto-extracted from the
  login page. Optionally set a **logged-in indicator** (text that appears only when
  authenticated) so the scanner can verify the session took.

Safety & hygiene:
- **Secrets are never written to disk.** Passwords, tokens and cookies are held in
  memory for the duration of the scan only; the database stores a redacted summary
  (auth type, login URL, field names, `username: ***`) for the report.
- **Logout avoidance.** The crawler never follows `logout`/`signout` links, so it
  won't destroy its own session mid-scan.
- A finding is recorded for whether auth **succeeded** (`Authenticated scan`) or
  **failed** (so you know when results only reflect the unauthenticated surface).

## Scan diffing

Across an engagement you re-scan the same target repeatedly. Open any completed
scan and VulnScan automatically compares it to the **previous completed scan of the
same host**, showing:

- **▲ new** — findings that appeared since last run (flagged with a red **NEW** badge
  on the finding cards)
- **▼ fixed** — findings present last time but gone now (listed in the diff panel)
- **= unchanged** — findings present in both

Findings are matched by (title + location), so moving from "0 new / N fixed" to
"N new / 0 fixed" tells you at a glance whether a deploy introduced or resolved
issues. Available via the UI (detail view) and the API: `GET /api/scans/{id}/diff`.

## Scheduled scans

Set **Repeat** on a new scan (hourly / daily / weekly) to register a recurring scan
instead of a one-off. A background scheduler runs each due schedule, and after every
run **auto-diffs** against the previous run of the same target, recording how many
findings are new (shown as "N new last run" in the Schedules panel). Manage schedules
inline: **Run** now, **Pause/Resume**, or delete.

API: `POST /api/schedules`, `GET /api/schedules`, `POST /api/schedules/{id}/run`,
`POST /api/schedules/{id}/toggle`, `DELETE /api/schedules/{id}`.

> **Credential storage caveat.** One-off scans keep auth secrets in memory only. A
> *scheduled* authenticated scan must replay credentials unattended, so for schedules
> the auth config (including secrets) **is** stored in the `schedules` table to enable
> re-runs. The API never returns it. Prefer revocable, least-privilege **tokens or
> session cookies** over account passwords for scheduled authenticated scans, and
> treat `vulnscan.db` as sensitive. (Encrypting this at rest is a good future upgrade.)

## Alerts

Get notified when a **scheduled** run surfaces new findings. Open **🔔 Alerts** in the
header to configure:

- **Webhook** — Slack, Discord, or any generic endpoint. Slack/Discord get a formatted
  message; other URLs receive a structured JSON payload (`event`, `target`, `scan_id`,
  `findings[]`).
- **Email (SMTP)** — host/port/credentials with STARTTLS.
- **Severity threshold** — only alert when a new finding is at or above the chosen
  severity (default High), so you aren't paged for info-level noise.

Use **Send test** to verify delivery. Alerts fire from the scheduler after a scheduled
scan's auto-diff; manual one-off scans don't alert. As with schedules, the webhook URL
and SMTP password are stored (to send unattended), the API returns them redacted, and
revocable webhook URLs / app passwords are recommended.

API: `GET/POST /api/alerts`, `POST /api/alerts/test`.

## Design notes

- **Non-destructive by default.** Active tests inject benign markers (a quote, a
  harmless tag, a probe URL) and look for reflections/errors/redirects. No exploit
  payloads, no data modification.
- **Scope enforced per request.** Every outbound request is checked against the
  target host; links to other domains are never followed or tested.
- **Throttling.** Configure concurrency and per-request delay to stay gentle on the target.
- **Data** is stored in `vulnscan.db` (SQLite) next to the backend.

## Layout

```
vulnscan/
├── run.py                 # launcher
├── requirements.txt
├── backend/
│   ├── app.py             # FastAPI API + static serving
│   ├── db.py              # SQLite persistence
│   ├── report.py          # JSON/HTML report rendering
│   └── scanner/
│       ├── engine.py      # orchestrator + scope gate + throttled HTTP
│       ├── util.py        # target normalization, scope enforcement
│       ├── recon.py
│       ├── tls_checks.py
│       ├── http_checks.py
│       ├── crawler.py
│       ├── web_vulns.py   # XSS/SQLi/open-redirect heuristics
│       └── external.py    # nuclei/nmap hooks
└── frontend/              # dashboard (vanilla HTML/CSS/JS)
```

## Extending

Add a new check module under `backend/scanner/` exposing `async def run(ctx)`, then
register it in `engine.py::_stages`. Use `ctx.get(url)` / `ctx.request(...)` (scope
enforced + throttled) and `ctx.report(severity, title, ...)` to record findings.

## Roadmap ideas

- Encrypt stored schedule/alert credentials at rest
- Export to Markdown / PDF; Jira/DefectDojo integration
- Authenticated scanning via headless browser (SPA/JS-heavy apps)
