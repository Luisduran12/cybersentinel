import json
import sqlite3
import threading
from contextlib import closing
from pathlib import Path
from typing import Any, Optional

from .models import ResponseAction, ActionStatus, ActionType


SCHEMA = """
CREATE TABLE IF NOT EXISTS response_actions (
    action_id TEXT PRIMARY KEY,
    incident_id TEXT NOT NULL,
    action_type TEXT NOT NULL,
    target TEXT NOT NULL,
    justification TEXT NOT NULL,
    status TEXT NOT NULL,
    requested_by TEXT NOT NULL,
    timestamp_requested TEXT NOT NULL,
    approved_by TEXT,
    timestamp_approved TEXT,
    result TEXT,
    dry_run INTEGER NOT NULL,
    audit_record TEXT
);

CREATE INDEX IF NOT EXISTS idx_response_actions_incident ON response_actions(incident_id);
"""


class ResponseStore:
    def __init__(self, db_path: str | Path):
        self.path = Path(db_path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        with closing(self._connect()) as con:
            con.executescript(SCHEMA)
            con.commit()

    def _connect(self) -> sqlite3.Connection:
        con = sqlite3.connect(self.path, timeout=30)
        con.row_factory = sqlite3.Row
        con.execute("PRAGMA journal_mode=WAL")
        con.execute("PRAGMA busy_timeout=10000")
        con.execute("PRAGMA synchronous=NORMAL")
        return con

    def create(self, action: ResponseAction) -> None:
        with self._lock, closing(self._connect()) as con:
            con.execute(
                """
                INSERT INTO response_actions (
                    action_id, incident_id, action_type, target, justification,
                    status, requested_by, timestamp_requested, approved_by,
                    timestamp_approved, result, dry_run, audit_record
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    action.action_id,
                    action.incident_id,
                    action.action_type.value,
                    json.dumps(action.target),
                    action.justification,
                    action.status.value,
                    action.requested_by,
                    action.timestamp_requested,
                    action.approved_by,
                    action.timestamp_approved,
                    json.dumps(action.result) if action.result else None,
                    1 if action.dry_run else 0,
                    action.audit_record
                )
            )
            con.commit()

    def get(self, action_id: str) -> Optional[ResponseAction]:
        with closing(self._connect()) as con:
            row = con.execute("SELECT * FROM response_actions WHERE action_id = ?", (action_id,)).fetchone()
            if not row:
                return None
            return self._row_to_model(row)

    def list_by_incident(self, incident_id: str) -> list[ResponseAction]:
        with closing(self._connect()) as con:
            rows = con.execute(
                "SELECT * FROM response_actions WHERE incident_id = ? ORDER BY timestamp_requested ASC",
                (incident_id,)
            ).fetchall()
            return [self._row_to_model(row) for row in rows]

    def update(self, action: ResponseAction) -> None:
        with self._lock, closing(self._connect()) as con:
            con.execute(
                """
                UPDATE response_actions SET
                    status = ?,
                    approved_by = ?,
                    timestamp_approved = ?,
                    result = ?,
                    audit_record = ?
                WHERE action_id = ?
                """,
                (
                    action.status.value,
                    action.approved_by,
                    action.timestamp_approved,
                    json.dumps(action.result) if action.result else None,
                    action.audit_record,
                    action.action_id
                )
            )
            con.commit()

    def _row_to_model(self, row: sqlite3.Row) -> ResponseAction:
        return ResponseAction(
            action_id=row["action_id"],
            incident_id=row["incident_id"],
            action_type=ActionType(row["action_type"]),
            target=json.loads(row["target"]),
            justification=row["justification"],
            status=ActionStatus(row["status"]),
            requested_by=row["requested_by"],
            timestamp_requested=row["timestamp_requested"],
            approved_by=row["approved_by"],
            timestamp_approved=row["timestamp_approved"],
            result=json.loads(row["result"]) if row["result"] else None,
            dry_run=bool(row["dry_run"]),
            audit_record=row["audit_record"]
        )
