from datetime import datetime, timezone
from enum import StrEnum
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, Field


class PolicyMode(StrEnum):
    ENFORCE = "enforce"
    AUDIT_ONLY = "audit_only"


class WhitelistEntry(BaseModel):
    """An authorized USB device entry in the whitelist."""

    id: UUID = Field(default_factory=uuid4)
    name: str = Field(..., description="Descriptive name for the device")
    serial_number: str | None = Field(default=None, description="Device serial number")
    vendor_id: str | None = Field(default=None, description="4-digit hex USB Vendor ID")
    product_id: str | None = Field(default=None, description="4-digit hex USB Product ID")
    device_id: str | None = Field(default=None, description="Full or partial PnP / sysfs device ID")
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    notes: str = ""

    def matches(
        self,
        *,
        serial_number: str | None = None,
        vendor_id: str | None = None,
        product_id: str | None = None,
        device_id: str | None = None,
    ) -> bool:
        """Check if a device matches this whitelist entry.

        All attributes specified on this entry that are provided by the device must match.
        At least one attribute must be successfully matched.
        """
        matched_criteria = 0

        if self.serial_number:
            if serial_number is None:
                pass
            elif self.serial_number.strip().casefold() == serial_number.strip().casefold():
                matched_criteria += 1
            else:
                return False

        if self.vendor_id:
            if vendor_id is None:
                pass
            elif self.vendor_id.strip().upper() == vendor_id.strip().upper():
                matched_criteria += 1
            else:
                return False

        if self.product_id:
            if product_id is None:
                pass
            elif self.product_id.strip().upper() == product_id.strip().upper():
                matched_criteria += 1
            else:
                return False

        if self.device_id:
            if device_id is None:
                pass
            elif (
                self.device_id.strip().casefold() in device_id.strip().casefold()
                or device_id.strip().casefold() in self.device_id.strip().casefold()
            ):
                matched_criteria += 1
            else:
                return False

        return matched_criteria > 0


class PolicyDecision(BaseModel):
    """Decision produced by evaluating a device against the policy engine."""

    allowed: bool
    action: str  # "allow", "block", "audit_violation"
    reason: str
    device_id: str
    matched_entry: WhitelistEntry | None = None
    blocked_successfully: bool = False
    details: dict[str, Any] = Field(default_factory=dict)
