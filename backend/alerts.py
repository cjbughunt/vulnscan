"""New-finding alerts: webhook (Slack/Discord/generic) and email (SMTP).

Alerts fire from the scheduler after a scheduled scan's auto-diff, when new findings
meet the configured severity threshold. Config is stored in the settings table; the
API returns it with secrets redacted.
"""
import asyncio
import json
import smtplib
import ssl
from email.message import EmailMessage

import httpx

from . import db

SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

DEFAULT_CONFIG = {
    "enabled": False,
    "min_severity": "high",
    "webhook_url": "",
    "email": {"enabled": False, "host": "", "port": 587, "username": "",
              "password": "", "from_addr": "", "to_addr": "", "tls": True},
}


def get_config() -> dict:
    raw = db.get_setting("alerts")
    cfg = json.loads(raw) if raw else {}
    merged = {**DEFAULT_CONFIG, **cfg}
    merged["email"] = {**DEFAULT_CONFIG["email"], **(cfg.get("email") or {})}
    return merged


def save_config(new: dict) -> dict:
    """Merge incoming config; keep existing secrets when the client sends blanks/masks."""
    cur = get_config()
    cur["enabled"] = bool(new.get("enabled", cur["enabled"]))
    cur["min_severity"] = new.get("min_severity", cur["min_severity"])
    wh = new.get("webhook_url", cur["webhook_url"])
    if wh != "***":
        cur["webhook_url"] = wh
    ne = new.get("email") or {}
    em = cur["email"]
    for k in ("enabled", "host", "port", "from_addr", "to_addr", "tls", "username"):
        if k in ne:
            em[k] = ne[k]
    if ne.get("password") not in (None, "", "***"):
        em["password"] = ne["password"]
    cur["email"] = em
    db.set_setting("alerts", json.dumps(cur))
    return redact(cur)


def redact(cfg: dict) -> dict:
    c = json.loads(json.dumps(cfg))
    if c.get("webhook_url"):
        c["webhook_url_set"] = True
    em = c.get("email", {})
    em["password"] = "***" if em.get("password") else ""
    return c


async def maybe_alert(scan: dict, new_findings: list) -> None:
    cfg = get_config()
    if not cfg.get("enabled"):
        return
    thr = SEV_RANK.get(cfg.get("min_severity", "high"), 3)
    relevant = [f for f in new_findings if SEV_RANK.get(f["severity"], 0) >= thr]
    if not relevant:
        return
    await dispatch(cfg, scan, relevant, len(new_findings))


def _format(scan, relevant, total_new):
    subject = f"VulnScan: {len(relevant)} new finding(s) on {scan['target']}"
    lines = [f"[{f['severity'].upper()}] {f['title']}"
             + (f" — {f['location']}" if f.get("location") else "")
             for f in relevant[:15]]
    more = f"\n…and {len(relevant) - 15} more" if len(relevant) > 15 else ""
    body = (f"{subject}\nScan #{scan['id']} · {total_new} new finding(s) total "
            f"({len(relevant)} at/above threshold):\n\n" + "\n".join(lines) + more)
    return subject, body


def _log(scan, msg, level="info"):
    # Only log against a real scan row (the test path uses a synthetic scan id 0).
    if scan.get("id"):
        db.add_log(scan["id"], msg, level)


async def dispatch(cfg, scan, relevant, total_new) -> None:
    subject, body = _format(scan, relevant, total_new)
    errors = []
    url = cfg.get("webhook_url")
    if url:
        try:
            await _webhook(url, subject, body, scan, relevant, total_new)
            _log(scan, f"Alert sent to webhook ({len(relevant)} findings).")
        except Exception as e:
            errors.append(f"webhook: {e}")
            _log(scan, f"Webhook alert failed: {e}", "warn")
    em = cfg.get("email", {})
    if em.get("enabled"):
        try:
            await asyncio.get_event_loop().run_in_executor(None, _send_email, em, subject, body)
            _log(scan, "Alert email sent.")
        except Exception as e:
            errors.append(f"email: {e}")
            _log(scan, f"Email alert failed: {e}", "warn")
    return errors


async def _webhook(url, subject, body, scan, relevant, total_new):
    if "hooks.slack.com" in url:
        data = {"text": body}
    elif "discord" in url:
        data = {"content": body[:1900]}
    else:
        data = {
            "event": "vulnscan.new_findings",
            "target": scan["target"], "scan_id": scan["id"],
            "summary": subject, "total_new": total_new,
            "findings": [{"severity": f["severity"], "title": f["title"],
                          "location": f.get("location"), "category": f.get("category")}
                         for f in relevant],
        }
    async with httpx.AsyncClient(timeout=15) as c:
        r = await c.post(url, json=data)
        r.raise_for_status()


def _send_email(em, subject, body):
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = em.get("from_addr") or em.get("username")
    msg["To"] = em.get("to_addr")
    msg.set_content(body)
    host, port = em.get("host"), int(em.get("port") or 587)
    with smtplib.SMTP(host, port, timeout=20) as s:
        if em.get("tls", True):
            s.starttls(context=ssl.create_default_context())
        if em.get("username"):
            s.login(em["username"], em.get("password", ""))
        s.send_message(msg)


async def send_test() -> dict:
    cfg = get_config()
    fake_scan = {"id": 0, "target": "https://example.test"}
    fake = [{"severity": "high", "title": "Test alert from VulnScan",
             "location": "https://example.test/", "category": "test"}]
    channels = []
    if cfg.get("webhook_url"):
        channels.append("webhook")
    if cfg.get("email", {}).get("enabled"):
        channels.append("email")
    if not channels:
        return {"ok": False, "error": "No webhook or email configured."}
    errors = await dispatch(cfg, fake_scan, fake, 1)
    if errors:
        return {"ok": False, "channels": channels, "error": "; ".join(errors)}
    return {"ok": True, "channels": channels}
