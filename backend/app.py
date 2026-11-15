"""FastAPI application: scan management API + static dashboard."""
import asyncio
import json
import os

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from . import db, scheduler, alerts
from .scanner import util
from .scanner.engine import run_scan
from .report import render_html_report, build_report_dict, build_diff

FRONTEND_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "frontend")

app = FastAPI(title="VulnScan", version="1.0")
_running: dict[int, asyncio.Task] = {}


@app.on_event("startup")
async def _startup():
    db.init_db()
    scheduler.start()


class ScanRequest(BaseModel):
    target: str
    authorized: bool = False
    authorized_by: str | None = None
    options: dict = {}
    auth: dict = {}


# Secret auth material (passwords, tokens, cookies) kept in memory only, never in the DB.
_SECRET_KEYS = {"password", "header_value", "cookie", "username", "extra_fields"}


def _redact_auth(auth: dict) -> dict:
    """A DB-safe summary of the auth config, with no secret values."""
    if not auth or (auth.get("type") or "none") == "none":
        return {"type": "none"}
    out = {"type": auth.get("type")}
    for k in ("header_name", "login_url", "username_field", "password_field",
              "success_indicator", "verify_url"):
        if auth.get(k):
            out[k] = auth[k]
    if auth.get("username"):
        out["username"] = "***"
    if auth.get("type") in ("header", "cookie"):
        out["credential"] = "*** (not stored)"
    return out


@app.post("/api/scans")
async def create_scan(req: ScanRequest):
    if not req.authorized:
        raise HTTPException(
            status_code=403,
            detail="You must confirm you are authorized to test this target before scanning.",
        )
    try:
        base_url = util.normalize_target(req.target)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    host = util.target_host(base_url)

    options = dict(req.options or {})
    options["auth_summary"] = _redact_auth(req.auth or {})

    scan_id = db.create_scan(base_url, host, req.authorized,
                             req.authorized_by or "operator", options)
    task = asyncio.create_task(_supervise(scan_id, req.auth or {}))
    _running[scan_id] = task
    return {"id": scan_id, "target": base_url, "host": host, "status": "queued"}


async def _supervise(scan_id: int, auth: dict):
    try:
        await run_scan(scan_id, auth=auth)
    finally:
        _running.pop(scan_id, None)


@app.get("/api/scans")
async def get_scans():
    return db.list_scans()


@app.get("/api/scans/{scan_id}")
async def get_scan(scan_id: int):
    scan = db.get_scan(scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    scan["options"] = json.loads(scan.get("options") or "{}")
    return scan


@app.get("/api/scans/{scan_id}/findings")
async def get_findings(scan_id: int):
    if not db.get_scan(scan_id):
        raise HTTPException(404, "Scan not found")
    return db.list_findings(scan_id)


@app.get("/api/scans/{scan_id}/logs")
async def get_logs(scan_id: int, after: int = 0):
    if not db.get_scan(scan_id):
        raise HTTPException(404, "Scan not found")
    return db.list_logs(scan_id, after)


@app.get("/api/scans/{scan_id}/report")
async def get_report(scan_id: int, format: str = "json"):
    scan = db.get_scan(scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    findings = db.list_findings(scan_id)
    if format == "html":
        return HTMLResponse(render_html_report(scan, findings))
    return JSONResponse(build_report_dict(scan, findings))


@app.get("/api/scans/{scan_id}/diff")
async def get_diff(scan_id: int):
    scan = db.get_scan(scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    prev = db.find_previous_scan(scan["host"], scan_id)
    current = db.list_findings(scan_id)
    if not prev:
        return {"previous": None, "new": current, "fixed": [],
                "unchanged": 0, "counts": {"new": len(current), "fixed": 0, "unchanged": 0}}
    diff = build_diff(current, db.list_findings(prev["id"]))
    diff["previous"] = {"id": prev["id"], "finished_at": prev["finished_at"]}
    return diff


@app.delete("/api/scans/{scan_id}")
async def remove_scan(scan_id: int):
    task = _running.get(scan_id)
    if task:
        task.cancel()
    db.delete_scan(scan_id)
    return {"deleted": scan_id}


class ScheduleRequest(BaseModel):
    target: str
    authorized: bool = False
    authorized_by: str | None = None
    interval_minutes: int = 1440
    options: dict = {}
    auth: dict = {}
    run_now: bool = True


@app.post("/api/schedules")
async def create_schedule(req: ScheduleRequest):
    if not req.authorized:
        raise HTTPException(403, "You must confirm authorization before scheduling scans.")
    if req.interval_minutes < 5:
        raise HTTPException(400, "Minimum interval is 5 minutes.")
    try:
        base_url = util.normalize_target(req.target)
    except ValueError as e:
        raise HTTPException(400, str(e))
    host = util.target_host(base_url)

    options = dict(req.options or {})
    options["auth_summary"] = _redact_auth(req.auth or {})
    # First run is due now if run_now, else after one interval.
    first = db.now() if req.run_now else scheduler.iso_in(req.interval_minutes)
    sid = db.create_schedule(base_url, host, req.authorized_by or "operator",
                             options, req.auth or {}, req.interval_minutes, first)
    return {"id": sid, "target": base_url, "interval_minutes": req.interval_minutes,
            "next_run": first}


@app.get("/api/schedules")
async def get_schedules():
    out = []
    for s in db.list_schedules():
        s.pop("auth_json", None)  # never expose stored secrets
        s["options"] = json.loads(s.get("options") or "{}")
        out.append(s)
    return out


@app.post("/api/schedules/{sid}/toggle")
async def toggle_schedule(sid: int):
    s = db.get_schedule(sid)
    if not s:
        raise HTTPException(404, "Schedule not found")
    new = 0 if s["enabled"] else 1
    db.update_schedule(sid, enabled=new)
    return {"id": sid, "enabled": new}


@app.post("/api/schedules/{sid}/run")
async def run_schedule_now(sid: int):
    s = db.get_schedule(sid)
    if not s:
        raise HTTPException(404, "Schedule not found")
    asyncio.create_task(scheduler._run_schedule(s))
    return {"id": sid, "status": "running"}


@app.delete("/api/schedules/{sid}")
async def remove_schedule(sid: int):
    db.delete_schedule(sid)
    return {"deleted": sid}


@app.get("/api/alerts")
async def get_alerts():
    return alerts.redact(alerts.get_config())


@app.post("/api/alerts")
async def set_alerts(cfg: dict):
    return alerts.save_config(cfg or {})


@app.post("/api/alerts/test")
async def test_alerts():
    return await alerts.send_test()


@app.get("/api/health")
async def health():
    from .scanner import external
    return {
        "status": "ok",
        "tools": {"nuclei": external.available("nuclei"), "nmap": external.available("nmap")},
    }


# ---- static frontend ----
if os.path.isdir(FRONTEND_DIR):
    app.mount("/", StaticFiles(directory=FRONTEND_DIR, html=True), name="static")
else:
    @app.get("/", response_class=PlainTextResponse)
    async def _no_frontend():
        return "VulnScan API is running. Frontend directory not found."
