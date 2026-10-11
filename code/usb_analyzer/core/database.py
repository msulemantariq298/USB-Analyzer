import json
import sqlite3
from pathlib import Path
from typing import Iterable

from usb_analyzer.core.events import DeviceEvent


class EventStore:
    """SQLite persistence for auditable analyzer events."""

    def __init__(self, database_path: Path) -> None:
        self.database_path = database_path
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.database_path)
        connection.row_factory = sqlite3.Row
        return connection

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS events (
                    id TEXT PRIMARY KEY,
                    time TEXT NOT NULL,
                    device_id TEXT NOT NULL,
                    source TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    details TEXT NOT NULL
                )
                """
            )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS idx_events_time ON events(time DESC)"
            )

    def add(self, event: DeviceEvent) -> DeviceEvent:
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO events
                    (id, time, device_id, source, severity, event_type, details)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    str(event.id),
                    event.time.isoformat(),
                    event.device_id,
                    event.source,
                    event.severity.value,
                    event.event_type,
                    json.dumps(event.details),
                ),
            )
        return event

    def list(self, limit: int = 100) -> list[DeviceEvent]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM events ORDER BY time DESC LIMIT ?",
                (limit,),
            ).fetchall()

        return [
            DeviceEvent(
                id=row["id"],
                time=row["time"],
                device_id=row["device_id"],
                source=row["source"],
                severity=row["severity"],
                event_type=row["event_type"],
                details=json.loads(row["details"]),
            )
            for row in rows
        ]

    def add_many(self, events: Iterable[DeviceEvent]) -> None:
        for event in events:
            self.add(event)
