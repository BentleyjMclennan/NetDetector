#sqlite3 database handler

import os
import sqlite3
from datetime import datetime

DB_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "network_log.db")


def get_connection():
    return sqlite3.connect(DB_FILE)


def init_db():
    """Create tables if they don't exist yet. Safe to call on every startup."""
    with get_connection() as conn:
        conn.execute("PRAGMA journal_mode=WAL")

        conn.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                mac         TEXT    NOT NULL,
                ip          TEXT    NOT NULL,
                vendor      TEXT,
                hostname    TEXT,
                first_seen  TEXT    NOT NULL,
                last_seen   TEXT    NOT NULL,
                alert_count INTEGER DEFAULT 1
            )
        """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS events (
                id        INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                type      TEXT NOT NULL,      -- e.g. "arp_spoof"
                severity  TEXT NOT NULL,      -- "INFO" / "WARNING" / "CRITICAL"
                ip        TEXT,
                mac       TEXT,               -- the new/offending MAC
                details   TEXT                -- human-readable description
            )
        """)
        conn.commit()



def log_alert(mac: str, ip: str, vendor: str = None, hostname: str = None):
    """Insert a new device, or update the existing row if the MAC is already known."""
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with get_connection() as conn:
        existing = conn.execute(
            "SELECT id, hostname FROM alerts WHERE mac = ?", (mac,)
        ).fetchone()

        if existing:
            # Keep an existing hostname if this sighting didn't supply one
            kept_hostname = hostname or existing[1]
            conn.execute("""
                UPDATE alerts
                SET last_seen   = ?,
                    ip          = ?,
                    hostname    = ?,
                    alert_count = alert_count + 1
                WHERE mac = ?
            """, (now, ip, kept_hostname, mac))
        else:
            conn.execute("""
                INSERT INTO alerts (mac, ip, vendor, hostname, first_seen, last_seen)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (mac, ip, vendor, hostname, now, now))

        conn.commit()


def get_all_alerts():
    with get_connection() as conn:
        conn.row_factory = sqlite3.Row
        return conn.execute(
            "SELECT * FROM alerts ORDER BY last_seen DESC"
        ).fetchall()


def get_alert_by_mac(mac: str):
    with get_connection() as conn:
        conn.row_factory = sqlite3.Row
        return conn.execute(
            "SELECT * FROM alerts WHERE mac = ?", (mac,)
        ).fetchone()


def get_recent_alerts(limit: int = 200) -> list[dict]:
    """Recent devices as plain dicts (JSON-serializable), newest first."""
    with get_connection() as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT * FROM alerts ORDER BY last_seen DESC LIMIT ?", (limit,)
        ).fetchall()
        return [dict(row) for row in rows]



def log_event(event_type: str, severity: str, ip: str = None,
              mac: str = None, details: str = None):
    """Append-only — each incident is its own row, giving a full history."""
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with get_connection() as conn:
        conn.execute("""
            INSERT INTO events (timestamp, type, severity, ip, mac, details)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (now, event_type, severity, ip, mac, details))
        conn.commit()


def get_recent_events(limit: int = 200) -> list[dict]:
    """Recent incidents as plain dicts, newest first."""
    with get_connection() as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT * FROM events ORDER BY timestamp DESC, id DESC LIMIT ?", (limit,)
        ).fetchall()
        return [dict(row) for row in rows]


if __name__ == "__main__":
    # Running this file directly just sets up the database.
    init_db()
    print(f"Database ready at {DB_FILE}")
