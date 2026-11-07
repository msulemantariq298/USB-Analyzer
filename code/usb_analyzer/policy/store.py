import sqlite3
from pathlib import Path
from uuid import UUID

from usb_analyzer.policy.models import WhitelistEntry


class WhitelistStore:
    """SQLite storage for authorized USB devices (whitelist)."""

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
                CREATE TABLE IF NOT EXISTS whitelist (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    serial_number TEXT,
                    vendor_id TEXT,
                    product_id TEXT,
                    device_id TEXT,
                    created_at TEXT NOT NULL,
                    notes TEXT
                )
                """
            )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS idx_whitelist_serial ON whitelist(serial_number)"
            )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS idx_whitelist_vid_pid ON whitelist(vendor_id, product_id)"
            )

    def add(self, entry: WhitelistEntry) -> WhitelistEntry:
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO whitelist
                    (id, name, serial_number, vendor_id, product_id, device_id, created_at, notes)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    name = excluded.name,
                    serial_number = excluded.serial_number,
                    vendor_id = excluded.vendor_id,
                    product_id = excluded.product_id,
                    device_id = excluded.device_id,
                    notes = excluded.notes
                """,
                (
                    str(entry.id),
                    entry.name,
                    entry.serial_number,
                    entry.vendor_id,
                    entry.product_id,
                    entry.device_id,
                    entry.created_at.isoformat(),
                    entry.notes,
                ),
            )
        return entry

    def list(self) -> list[WhitelistEntry]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM whitelist ORDER BY created_at DESC"
            ).fetchall()

        return [
            WhitelistEntry(
                id=UUID(row["id"]),
                name=row["name"],
                serial_number=row["serial_number"],
                vendor_id=row["vendor_id"],
                product_id=row["product_id"],
                device_id=row["device_id"],
                created_at=row["created_at"],
                notes=row["notes"] or "",
            )
            for row in rows
        ]

    def get(self, entry_id: str | UUID) -> WhitelistEntry | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM whitelist WHERE id = ?",
                (str(entry_id),),
            ).fetchone()

        if row is None:
            return None

        return WhitelistEntry(
            id=UUID(row["id"]),
            name=row["name"],
            serial_number=row["serial_number"],
            vendor_id=row["vendor_id"],
            product_id=row["product_id"],
            device_id=row["device_id"],
            created_at=row["created_at"],
            notes=row["notes"] or "",
        )

    def remove(self, entry_id: str | UUID) -> bool:
        with self._connect() as connection:
            cursor = connection.execute(
                "DELETE FROM whitelist WHERE id = ?",
                (str(entry_id),),
            )
            return cursor.rowcount > 0

    def find_match(
        self,
        *,
        serial_number: str | None = None,
        vendor_id: str | None = None,
        product_id: str | None = None,
        device_id: str | None = None,
    ) -> WhitelistEntry | None:
        """Find the first matching whitelist entry for device identifiers."""
        entries = self.list()
        for entry in entries:
            if entry.matches(
                serial_number=serial_number,
                vendor_id=vendor_id,
                product_id=product_id,
                device_id=device_id,
            ):
                return entry
        return None

