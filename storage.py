import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

DB_PATH = Path(__file__).with_name("alerts.db")


def initialize() -> None:
    with sqlite3.connect(DB_PATH) as connection:
        connection.execute("""CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT, created_at TEXT NOT NULL,
            event_key TEXT NOT NULL UNIQUE, host TEXT, user TEXT,
            risk_score INTEGER, payload TEXT NOT NULL)""")


def save_alert(event_key: str, host: str, user: str, risk_score: int, payload: dict[str, Any]) -> bool:
    initialize()
    with sqlite3.connect(DB_PATH) as connection:
        cursor = connection.execute(
            "INSERT OR IGNORE INTO alerts(created_at,event_key,host,user,risk_score,payload) VALUES(?,?,?,?,?,?)",
            (datetime.now(timezone.utc).isoformat(), event_key, host, user, risk_score, json.dumps(payload)),
        )
        return cursor.rowcount == 1


def recent_alerts(limit: int = 10, host: str | None = None) -> list[dict[str, Any]]:
    initialize()
    limit = max(1, min(int(limit), 50))
    query = "SELECT id, created_at, host, user, risk_score, payload FROM alerts"
    parameters: list[Any] = []
    if host:
        query += " WHERE lower(host) = lower(?)"
        parameters.append(host)
    query += " ORDER BY id DESC LIMIT ?"
    parameters.append(limit)
    with sqlite3.connect(DB_PATH) as connection:
        rows = connection.execute(query, parameters).fetchall()
    return [{"id": row[0], "created_at": row[1], "host": row[2], "user": row[3], "risk_score": row[4], "payload": json.loads(row[5])} for row in rows]
