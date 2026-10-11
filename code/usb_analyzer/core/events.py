from datetime import datetime, timezone
from enum import StrEnum
import json
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, Field


class EventSeverity(StrEnum):
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"


class DeviceEvent(BaseModel):
    """Stable event contract shared by every analyzer module."""

    id: UUID = Field(default_factory=uuid4)
    time: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    device_id: str
    source: str
    severity: EventSeverity = EventSeverity.INFO
    event_type: str
    details: dict[str, Any] = Field(default_factory=dict)

    def sqlite_values(self) -> tuple[str, str, str, str, str, str, str]:
        return (
            str(self.id),
            self.time.isoformat(),
            self.device_id,
            self.source,
            self.severity.value,
            self.event_type,
            json.dumps(self.details),
        )
