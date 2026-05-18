"""Database module — SQLite backend for users, scans, scan history."""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import sqlite3
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any

DB_PATH = Path(os.environ.get("DB_PATH", Path(__file__).parent / "securescan.db"))


def _get_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


@contextmanager
def get_db():
    conn = _get_conn()
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db() -> None:
    with get_db() as conn:
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            full_name TEXT NOT NULL,
            company TEXT DEFAULT '',
            phone TEXT DEFAULT '',
            role TEXT DEFAULT 'user',
            is_verified INTEGER DEFAULT 0,
            verification_token TEXT,
            verification_expires TEXT,
            api_key TEXT UNIQUE,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            last_login TEXT,
            scan_count INTEGER DEFAULT 0,
            is_active INTEGER DEFAULT 1
        );

        CREATE TABLE IF NOT EXISTS scan_history (
            id TEXT PRIMARY KEY,
            user_id TEXT,
            url TEXT NOT NULL,
            hostname TEXT NOT NULL,
            scan_types TEXT NOT NULL,
            status TEXT DEFAULT 'queued',
            grade TEXT DEFAULT '',
            total_issues INTEGER DEFAULT 0,
            critical_count INTEGER DEFAULT 0,
            high_count INTEGER DEFAULT 0,
            medium_count INTEGER DEFAULT 0,
            low_count INTEGER DEFAULT 0,
            risk_score REAL DEFAULT 0.0,
            risk_level TEXT DEFAULT '',
            results_json TEXT DEFAULT '{}',
            started_at TEXT,
            completed_at TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS scheduled_scans (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            url TEXT NOT NULL,
            hostname TEXT NOT NULL,
            scan_types TEXT NOT NULL,
            interval TEXT NOT NULL,
            is_active INTEGER DEFAULT 1,
            last_run TEXT,
            next_run TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id)
        );

        CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
        CREATE INDEX IF NOT EXISTS idx_users_api_key ON users(api_key);
        CREATE INDEX IF NOT EXISTS idx_scan_history_user ON scan_history(user_id);
        CREATE INDEX IF NOT EXISTS idx_scan_history_url ON scan_history(url);
        CREATE INDEX IF NOT EXISTS idx_scheduled_scans_user ON scheduled_scans(user_id);
        CREATE INDEX IF NOT EXISTS idx_scheduled_scans_next ON scheduled_scans(next_run);
        """)


def hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    pw_hash = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 100_000)
    return f"{salt}:{pw_hash.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        salt, pw_hash = stored.split(":")
        check = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 100_000)
        return check.hex() == pw_hash
    except Exception:
        return False


def create_user(email: str, password: str, full_name: str, company: str = "", phone: str = "") -> dict | None:
    now = datetime.now(timezone.utc).isoformat()
    user_id = str(uuid.uuid4())[:12]
    api_key = f"ssp_{secrets.token_hex(20)}"
    verification_token = secrets.token_urlsafe(32)
    verification_expires = (datetime.now(timezone.utc) + timedelta(hours=24)).isoformat()

    with get_db() as conn:
        try:
            conn.execute(
                """INSERT INTO users (id, email, password_hash, full_name, company, phone,
                   api_key, verification_token, verification_expires, created_at, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (user_id, email.lower().strip(), hash_password(password), full_name.strip(),
                 company.strip(), phone.strip(), api_key, verification_token,
                 verification_expires, now, now),
            )
            return {
                "id": user_id,
                "email": email.lower().strip(),
                "full_name": full_name.strip(),
                "company": company.strip(),
                "api_key": api_key,
                "verification_token": verification_token,
                "is_verified": False,
            }
        except sqlite3.IntegrityError:
            return None


def authenticate_user(email: str, password: str) -> dict | None:
    with get_db() as conn:
        row = conn.execute(
            "SELECT * FROM users WHERE email = ? AND is_active = 1",
            (email.lower().strip(),),
        ).fetchone()
        if not row:
            return None
        if not verify_password(password, row["password_hash"]):
            return None
        conn.execute(
            "UPDATE users SET last_login = ? WHERE id = ?",
            (datetime.now(timezone.utc).isoformat(), row["id"]),
        )
        return dict(row)


def verify_user_email(token: str) -> bool:
    with get_db() as conn:
        row = conn.execute(
            "SELECT id, verification_expires FROM users WHERE verification_token = ?",
            (token,),
        ).fetchone()
        if not row:
            return False
        expires = datetime.fromisoformat(row["verification_expires"])
        if datetime.now(timezone.utc) > expires:
            return False
        conn.execute(
            "UPDATE users SET is_verified = 1, verification_token = NULL WHERE id = ?",
            (row["id"],),
        )
        return True


def get_user_by_id(user_id: str) -> dict | None:
    with get_db() as conn:
        row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        return dict(row) if row else None


def get_user_by_api_key(api_key: str) -> dict | None:
    with get_db() as conn:
        row = conn.execute("SELECT * FROM users WHERE api_key = ?", (api_key,)).fetchone()
        return dict(row) if row else None


def save_scan(scan_data: dict, user_id: str | None = None) -> str:
    scan_id = scan_data.get("scan_id", str(uuid.uuid4())[:8])
    now = datetime.now(timezone.utc).isoformat()
    summary = scan_data.get("summary", {})
    severity = summary.get("by_severity", {})

    with get_db() as conn:
        conn.execute(
            """INSERT OR REPLACE INTO scan_history
               (id, user_id, url, hostname, scan_types, status, grade,
                total_issues, critical_count, high_count, medium_count, low_count,
                risk_score, risk_level, results_json, started_at, completed_at, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (scan_id, user_id, scan_data.get("url", ""), scan_data.get("hostname", ""),
             json.dumps(scan_data.get("scan_types", [])), scan_data.get("status", "completed"),
             summary.get("grade", ""), summary.get("total_issues", 0),
             severity.get("critical", 0), severity.get("high", 0),
             severity.get("medium", 0), severity.get("low", 0),
             summary.get("risk_score", 0.0), summary.get("risk_level", ""),
             json.dumps(scan_data), scan_data.get("started_at", now),
             scan_data.get("completed_at", now), now),
        )
        if user_id:
            conn.execute(
                "UPDATE users SET scan_count = scan_count + 1 WHERE id = ?",
                (user_id,),
            )
    return scan_id


def get_user_scans(user_id: str, limit: int = 50) -> list[dict]:
    with get_db() as conn:
        rows = conn.execute(
            """SELECT id, url, hostname, status, grade, total_issues,
                      critical_count, high_count, medium_count, low_count,
                      risk_score, risk_level, started_at, completed_at, created_at
               FROM scan_history WHERE user_id = ?
               ORDER BY created_at DESC LIMIT ?""",
            (user_id, limit),
        ).fetchall()
        return [dict(r) for r in rows]


def get_scan_detail(scan_id: str) -> dict | None:
    with get_db() as conn:
        row = conn.execute(
            "SELECT results_json FROM scan_history WHERE id = ?",
            (scan_id,),
        ).fetchone()
        if not row:
            return None
        return json.loads(row["results_json"])


def get_url_scan_history(url: str, limit: int = 20) -> list[dict]:
    with get_db() as conn:
        rows = conn.execute(
            """SELECT id, grade, total_issues, risk_score, risk_level,
                      critical_count, high_count, medium_count, low_count,
                      completed_at
               FROM scan_history WHERE url = ? AND status = 'completed'
               ORDER BY completed_at DESC LIMIT ?""",
            (url, limit),
        ).fetchall()
        return [dict(r) for r in rows]


def create_scheduled_scan(user_id: str, url: str, hostname: str,
                          scan_types: list[str], interval: str) -> str:
    scan_id = str(uuid.uuid4())[:12]
    now = datetime.now(timezone.utc)
    delta = {"daily": timedelta(days=1), "weekly": timedelta(weeks=1),
             "monthly": timedelta(days=30)}.get(interval, timedelta(days=1))
    next_run = (now + delta).isoformat()

    with get_db() as conn:
        conn.execute(
            """INSERT INTO scheduled_scans
               (id, user_id, url, hostname, scan_types, interval, next_run, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (scan_id, user_id, url, hostname, json.dumps(scan_types),
             interval, next_run, now.isoformat()),
        )
    return scan_id


def get_due_scheduled_scans() -> list[dict]:
    now = datetime.now(timezone.utc).isoformat()
    with get_db() as conn:
        rows = conn.execute(
            """SELECT * FROM scheduled_scans
               WHERE is_active = 1 AND next_run <= ?""",
            (now,),
        ).fetchall()
        return [dict(r) for r in rows]


def update_scheduled_scan_run(scan_id: str, interval: str) -> None:
    now = datetime.now(timezone.utc)
    delta = {"daily": timedelta(days=1), "weekly": timedelta(weeks=1),
             "monthly": timedelta(days=30)}.get(interval, timedelta(days=1))
    next_run = (now + delta).isoformat()

    with get_db() as conn:
        conn.execute(
            "UPDATE scheduled_scans SET last_run = ?, next_run = ? WHERE id = ?",
            (now.isoformat(), next_run, scan_id),
        )


def get_user_scheduled_scans(user_id: str) -> list[dict]:
    with get_db() as conn:
        rows = conn.execute(
            """SELECT id, url, interval, is_active, last_run, next_run, created_at
               FROM scheduled_scans WHERE user_id = ?
               ORDER BY created_at DESC""",
            (user_id,),
        ).fetchall()
        return [dict(r) for r in rows]


def delete_scheduled_scan(scan_id: str, user_id: str) -> bool:
    with get_db() as conn:
        result = conn.execute(
            "DELETE FROM scheduled_scans WHERE id = ? AND user_id = ?",
            (scan_id, user_id),
        )
        return result.rowcount > 0


def get_dashboard_stats(user_id: str) -> dict:
    with get_db() as conn:
        total = conn.execute(
            "SELECT COUNT(*) as c FROM scan_history WHERE user_id = ?",
            (user_id,),
        ).fetchone()["c"]

        critical = conn.execute(
            "SELECT SUM(critical_count) as c FROM scan_history WHERE user_id = ?",
            (user_id,),
        ).fetchone()["c"] or 0

        avg_risk = conn.execute(
            "SELECT AVG(risk_score) as c FROM scan_history WHERE user_id = ? AND status='completed'",
            (user_id,),
        ).fetchone()["c"] or 0.0

        scheduled = conn.execute(
            "SELECT COUNT(*) as c FROM scheduled_scans WHERE user_id = ? AND is_active = 1",
            (user_id,),
        ).fetchone()["c"]

        return {
            "total_scans": total,
            "total_critical": critical,
            "avg_risk_score": round(avg_risk, 1),
            "active_monitors": scheduled,
        }
