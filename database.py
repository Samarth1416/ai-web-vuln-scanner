"""database.py

Simple SQLite-backed persistence layer for CyberScan AI.

Provides user auth, scan history, scan notes, and user settings storage.
"""

import sqlite3
from datetime import datetime

from config import Config


def _get_conn():
    conn = sqlite3.connect(Config.DATABASE, timeout=10, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Create the database schema if it doesn't already exist."""
    conn = _get_conn()
    try:
        cur = conn.cursor()
        cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        """)
        cur.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            url TEXT NOT NULL,
            vulnerability TEXT NOT NULL,
            severity TEXT NOT NULL,
            details TEXT,
            remediation TEXT,
            scan_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(user_id) REFERENCES users(id)
        );
        """)
        cur.execute("""
        CREATE TABLE IF NOT EXISTS scan_notes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            url TEXT NOT NULL,
            note TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id)
        );
        """)
        cur.execute("""
        CREATE TABLE IF NOT EXISTS user_settings (
            user_id INTEGER PRIMARY KEY,
            email_alerts INTEGER DEFAULT 0,
            default_scan_mode TEXT DEFAULT 'full',
            FOREIGN KEY(user_id) REFERENCES users(id)
        );
        """)
        conn.commit()
    finally:
        conn.close()


def get_user_by_username(username: str):
    conn = _get_conn()
    try:
        cur = conn.cursor()
        cur.execute("SELECT * FROM users WHERE username = ?", (username,))
        row = cur.fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def get_user_by_id(user_id: int):
    conn = _get_conn()
    try:
        cur = conn.cursor()
        cur.execute("SELECT * FROM users WHERE id = ?", (user_id,))
        row = cur.fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def create_user(username: str, password_hash: str) -> bool:
    """Return True if user created, False if username is taken."""
    conn = _get_conn()
    try:
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO users (username, password, created_at) VALUES (?, ?, ?)",
            (username, password_hash, datetime.utcnow().isoformat() + 'Z'),
        )
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False
    finally:
        conn.close()


def update_user_password(user_id: int, new_hash: str):
    conn = _get_conn()
    try:
        cur = conn.cursor()
        cur.execute("UPDATE users SET password = ? WHERE id = ?", (new_hash, user_id))
        conn.commit()
    finally:
        conn.close()


def save_scan(user_id: int, url: str, vulnerability: str, severity: str, details: str, remediation: str):
    conn = _get_conn()
    try:
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO scans (user_id, url, vulnerability, severity, details, remediation, scan_date)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (user_id, url, vulnerability, severity, details, remediation,
             datetime.utcnow().isoformat() + 'Z'),
        )
        conn.commit()
    finally:
        conn.close()


def get_scans_by_user(user_id: int, limit: int | None = None):
    conn = _get_conn()
    try:
        cur = conn.cursor()
        query = "SELECT * FROM scans WHERE user_id = ? ORDER BY scan_date DESC"
        params = [user_id]
        if limit:
            query += " LIMIT ?"
            params.append(limit)
        cur.execute(query, params)
        rows = cur.fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def get_scan_stats(user_id: int):
    """Return (rows, total) for dashboard charts."""
    conn = _get_conn()
    try:
        cur = conn.cursor()
        cur.execute(
            """
            SELECT vulnerability, severity, COUNT(*) AS cnt
            FROM scans
            WHERE user_id = ?
            GROUP BY vulnerability, severity
            ORDER BY cnt DESC
            """,
            (user_id,)
        )
        rows = [dict(r) for r in cur.fetchall()]

        cur.execute("SELECT COUNT(*) AS total FROM scans WHERE user_id = ?", (user_id,))
        total = cur.fetchone()[0]

        return rows, total
    finally:
        conn.close()


def get_distinct_targets(user_id: int) -> int:
    """Return count of distinct URLs scanned by user."""
    conn = _get_conn()
    try:
        cur = conn.cursor()
        cur.execute("SELECT COUNT(DISTINCT url) AS cnt FROM scans WHERE user_id = ?", (user_id,))
        row = cur.fetchone()
        return row[0] if row else 0
    finally:
        conn.close()


def get_high_critical_count(user_id: int) -> int:
    """Return count of High + Critical findings for user."""
    conn = _get_conn()
    try:
        cur = conn.cursor()
        cur.execute(
            "SELECT COUNT(*) FROM scans WHERE user_id = ? AND severity IN ('Critical', 'High')",
            (user_id,)
        )
        row = cur.fetchone()
        return row[0] if row else 0
    finally:
        conn.close()


def clear_scan_history(user_id: int):
    """Delete all scan records for a user."""
    conn = _get_conn()
    try:
        cur = conn.cursor()
        cur.execute("DELETE FROM scans WHERE user_id = ?", (user_id,))
        conn.commit()
    finally:
        conn.close()


# ── Scan Notes ────────────────────────────────────

def save_note(user_id: int, url: str, note: str):
    conn = _get_conn()
    try:
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO scan_notes (user_id, url, note, created_at) VALUES (?, ?, ?, ?)",
            (user_id, url, note, datetime.utcnow().isoformat() + 'Z'),
        )
        conn.commit()
        return cur.lastrowid
    finally:
        conn.close()


def get_notes_by_user(user_id: int):
    conn = _get_conn()
    try:
        cur = conn.cursor()
        cur.execute(
            "SELECT * FROM scan_notes WHERE user_id = ? ORDER BY created_at DESC",
            (user_id,)
        )
        return [dict(r) for r in cur.fetchall()]
    finally:
        conn.close()


def get_notes_by_url(user_id: int, url: str):
    conn = _get_conn()
    try:
        cur = conn.cursor()
        cur.execute(
            "SELECT * FROM scan_notes WHERE user_id = ? AND url = ? ORDER BY created_at DESC",
            (user_id, url)
        )
        return [dict(r) for r in cur.fetchall()]
    finally:
        conn.close()


def delete_note(note_id: int, user_id: int):
    conn = _get_conn()
    try:
        cur = conn.cursor()
        cur.execute("DELETE FROM scan_notes WHERE id = ? AND user_id = ?", (note_id, user_id))
        conn.commit()
    finally:
        conn.close()


# ── User Settings ─────────────────────────────────

def get_user_settings(user_id: int) -> dict:
    conn = _get_conn()
    try:
        cur = conn.cursor()
        cur.execute("SELECT * FROM user_settings WHERE user_id = ?", (user_id,))
        row = cur.fetchone()
        if row:
            return dict(row)
        return {"user_id": user_id, "email_alerts": 0, "default_scan_mode": "full"}
    finally:
        conn.close()


def save_user_settings(user_id: int, email_alerts: int, default_scan_mode: str):
    conn = _get_conn()
    try:
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO user_settings (user_id, email_alerts, default_scan_mode)
            VALUES (?, ?, ?)
            ON CONFLICT(user_id) DO UPDATE SET
                email_alerts = excluded.email_alerts,
                default_scan_mode = excluded.default_scan_mode
            """,
            (user_id, email_alerts, default_scan_mode),
        )
        conn.commit()
    finally:
        conn.close()
