"""Background scheduler: launches recurring scans when they fall due, auto-diffs results.

The loop wakes every CHECK_SECONDS, finds schedules whose next_run has passed, advances
their next_run immediately (so a long scan can't double-fire), then runs the scan and
records how many findings are new versus the previous run of the same target.
"""
import asyncio
import json
from datetime import datetime, timedelta, timezone

from . import db, alerts
from .report import build_diff
from .scanner.engine import run_scan

CHECK_SECONDS = 30
_task = None


def iso_in(minutes: int) -> str:
    return (datetime.now(timezone.utc) + timedelta(minutes=minutes)).isoformat()


async def _run_schedule(sch: dict):
    options = json.loads(sch.get("options") or "{}")
    auth = json.loads(sch.get("auth_json") or "{}")

    scan_id = db.create_scan(sch["target"], sch["host"], True,
                             sch.get("authorized_by") or "schedule", options)
    db.update_schedule(sch["id"], last_run=db.now(), last_scan_id=scan_id,
                       next_run=iso_in(sch["interval_minutes"]))
    db.add_log(scan_id, f"Started by schedule #{sch['id']} "
                        f"(every {sch['interval_minutes']} min).")
    try:
        await run_scan(scan_id, auth=auth)
        # Auto-diff vs the previous completed run of the same host.
        prev = db.find_previous_scan(sch["host"], scan_id)
        if prev:
            diff = build_diff(db.list_findings(scan_id), db.list_findings(prev["id"]))
            n = diff["counts"]["new"]
            db.update_schedule(sch["id"], last_new_count=n)
            db.add_log(scan_id, f"Auto-diff vs scan #{prev['id']}: {n} new, "
                                f"{diff['counts']['fixed']} fixed.")
            if n:
                scan = db.get_scan(scan_id)
                await alerts.maybe_alert(scan, diff["new"])
        else:
            db.update_schedule(sch["id"], last_new_count=0)
    except Exception as e:
        db.add_log(scan_id, f"Scheduled scan error: {e}", "error")


async def _loop():
    while True:
        try:
            for sch in db.due_schedules(db.now()):
                asyncio.create_task(_run_schedule(sch))
        except Exception:
            pass
        await asyncio.sleep(CHECK_SECONDS)


def start():
    global _task
    if _task is None or _task.done():
        _task = asyncio.create_task(_loop())
    return _task
