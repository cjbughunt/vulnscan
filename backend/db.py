"""SQLite persistence layer for the vulnerability scanning platform."""
import sqlite3
import json
import os
import threading
from datetime import datetime, timezone

DB_PATH = os.environ.get(
    "VULNSCAN_DB",
    os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "vulnscan.db"),
)

_local = threading.local()


def _conn() -> sqlite3.Connection:
    """One connection per thread (FastAPI + background asyncio share the loop thread)."""
    c = getattr(_local, "conn", None)
    if c is None:
        c = sqlite3.connect(DB_PATH, check_same_thread=False)
        c.row_factory = sqlite3.Row
        c.execute("PRAGMA journal_mode=WAL;")
        c.execute("PRAGMA foreign_keys=ON;")
        _local.conn = c
    return c


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def init_db() -> None:
    c = _conn()
    c.executescript(
        """
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT NOT NULL,
            host TEXT,
            authorized INTEGER NOT NULL DEFAULT 0,
            authorized_by TEXT,
            status TEXT NOT NULL DEFAULT 'queued',
            progress INTEGER NOT NULL DEFAULT 0,
            current_stage TEXT,
            options TEXT,
            created_at TEXT NOT NULL,
            started_at TEXT,
            finished_at TEXT,
            error TEXT
        );

        CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER NOT NULL,
            severity TEXT NOT NULL,
            title TEXT NOT NULL,
            category TEXT,
            location TEXT,
            description TEXT,
            evidence TEXT,
            remediation TEXT,
            source TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER NOT NULL,
            ts TEXT NOT NULL,
            level TEXT NOT NULL,
            message TEXT NOT NULL,
            FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS schedules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT NOT NULL,
            host TEXT,
            authorized_by TEXT,
            options TEXT,
            auth_json TEXT,
            interval_minutes INTEGER NOT NULL,
            enabled INTEGER NOT NULL DEFAULT 1,
            next_run TEXT,
            last_run TEXT,
            last_scan_id INTEGER,
            last_new_count INTEGER,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT
        );

        CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
        CREATE INDEX IF NOT EXISTS idx_logs_scan ON logs(scan_id);
        """
    )
    c.commit()


def get_setting(key: str, default=None):
    row = _conn().execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
    return row["value"] if row else default


def set_setting(key: str, value: str) -> None:
    c = _conn()
    c.execute(
        "INSERT INTO settings (key, value) VALUES (?,?) "
        "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        (key, value),
    )
    c.commit()


# ---------- scans ----------

def create_scan(target: str, host: str, authorized: bool, authorized_by: str, options: dict) -> int:
    c = _conn()
    cur = c.execute(
        "INSERT INTO scans (target, host, authorized, authorized_by, status, options, created_at) "
        "VALUES (?,?,?,?,?,?,?)",
        (target, host, 1 if authorized else 0, authorized_by, "queued",
         json.dumps(options or {}), now()),
    )
    c.commit()
    return cur.lastrowid


def update_scan(scan_id: int, **fields) -> None:
    if not fields:
        return
    cols = ", ".join(f"{k}=?" for k in fields)
    c = _conn()
    c.execute(f"UPDATE scans SET {cols} WHERE id=?", (*fields.values(), scan_id))
    c.commit()


def get_scan(scan_id: int):
    row = _conn().execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
    return dict(row) if row else None


def list_scans():
    rows = _conn().execute(
        "SELECT s.*, "
        "(SELECT COUNT(*) FROM findings f WHERE f.scan_id=s.id) AS finding_count "
        "FROM scans s ORDER BY s.id DESC"
    ).fetchall()
    return [dict(r) for r in rows]


def delete_scan(scan_id: int) -> None:
    c = _conn()
    c.execute("DELETE FROM scans WHERE id=?", (scan_id,))
    c.commit()


def find_previous_scan(host: str, before_id: int):
    """Most recent completed scan of the same host before this one (for diffing)."""
    row = _conn().execute(
        "SELECT * FROM scans WHERE host=? AND id<? AND status='completed' "
        "ORDER BY id DESC LIMIT 1",
        (host, before_id),
    ).fetchone()
    return dict(row) if row else None


# ---------- findings ----------

def add_finding(scan_id: int, severity: str, title: str, **kw) -> None:
    c = _conn()
    c.execute(
        "INSERT INTO findings (scan_id, severity, title, category, location, description, "
        "evidence, remediation, source, created_at) VALUES (?,?,?,?,?,?,?,?,?,?)",
        (
            scan_id, severity, title,
            kw.get("category"), kw.get("location"), kw.get("description"),
            kw.get("evidence"), kw.get("remediation"), kw.get("source", "builtin"),
            now(),
        ),
    )
    c.commit()


def list_findings(scan_id: int):
    order = "CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 " \
            "WHEN 'low' THEN 3 WHEN 'info' THEN 4 ELSE 5 END"
    rows = _conn().execute(
        f"SELECT * FROM findings WHERE scan_id=? ORDER BY {order}, id", (scan_id,)
    ).fetchall()
    return [dict(r) for r in rows]


# ---------- logs ----------

# ---------- schedules ----------

def create_schedule(target, host, authorized_by, options, auth_json,
                    interval_minutes, next_run) -> int:
    c = _conn()
    cur = c.execute(
        "INSERT INTO schedules (target, host, authorized_by, options, auth_json, "
        "interval_minutes, enabled, next_run, created_at) VALUES (?,?,?,?,?,?,1,?,?)",
        (target, host, authorized_by, json.dumps(options or {}),
         json.dumps(auth_json or {}), int(interval_minutes), next_run, now()),
    )
    c.commit()
    return cur.lastrowid


def list_schedules():
    rows = _conn().execute("SELECT * FROM schedules ORDER BY id DESC").fetchall()
    return [dict(r) for r in rows]


def get_schedule(sid: int):
    row = _conn().execute("SELECT * FROM schedules WHERE id=?", (sid,)).fetchone()
    return dict(row) if row else None


def update_schedule(sid: int, **fields) -> None:
    if not fields:
        return
    cols = ", ".join(f"{k}=?" for k in fields)
    c = _conn()
    c.execute(f"UPDATE schedules SET {cols} WHERE id=?", (*fields.values(), sid))
    c.commit()


def delete_schedule(sid: int) -> None:
    c = _conn()
    c.execute("DELETE FROM schedules WHERE id=?", (sid,))
    c.commit()


def due_schedules(ts: str):
    rows = _conn().execute(
        "SELECT * FROM schedules WHERE enabled=1 AND next_run IS NOT NULL AND next_run<=?",
        (ts,),
    ).fetchall()
    return [dict(r) for r in rows]


def add_log(scan_id: int, message: str, level: str = "info") -> None:
    c = _conn()
    c.execute(
        "INSERT INTO logs (scan_id, ts, level, message) VALUES (?,?,?,?)",
        (scan_id, now(), level, message),
    )
    c.commit()


def list_logs(scan_id: int, after_id: int = 0):
    rows = _conn().execute(
        "SELECT * FROM logs WHERE scan_id=? AND id>? ORDER BY id", (scan_id, after_id)
    ).fetchall()
    return [dict(r) for r in rows]
