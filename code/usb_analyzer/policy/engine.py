import logging
from typing import Any

from usb_analyzer.core.events import DeviceEvent, EventSeverity
from usb_analyzer.policy.enforcement import DeviceBlocker, get_platform_blocker
from usb_analyzer.policy.models import PolicyDecision, PolicyMode, WhitelistEntry
from usb_analyzer.policy.store import WhitelistStore

logger = logging.getLogger(__name__)


class PolicyEngine:
    """Evaluates USB devices against whitelist policy and triggers containment/blocking."""

    def __init__(
        self,
        store: WhitelistStore,
        blocker: DeviceBlocker | None = None,
        mode: PolicyMode | str = PolicyMode.ENFORCE,
    ) -> None:
        self.store = store
        self.blocker = blocker or get_platform_blocker()
        self.mode = PolicyMode(mode)

    def evaluate_device(
        self,
        device_id: str,
        *,
        serial_number: str | None = None,
        vendor_id: str | None = None,
        product_id: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> tuple[PolicyDecision, list[DeviceEvent]]:
        """Evaluate a device connection against whitelist policy.
        
        Returns a tuple of (PolicyDecision, list of generated DeviceEvents).
        """
        details = details or {}
        matched_entry = self.store.find_match(
            serial_number=serial_number,
            vendor_id=vendor_id,
            product_id=product_id,
            device_id=device_id,
        )

        events: list[DeviceEvent] = []

        if matched_entry is not None:
            decision = PolicyDecision(
                allowed=True,
                action="allow",
                reason=f"Device matched whitelist entry: '{matched_entry.name}'",
                device_id=device_id,
                matched_entry=matched_entry,
                blocked_successfully=False,
                details={
                    "whitelist_id": str(matched_entry.id),
                    "whitelist_name": matched_entry.name,
                    **details,
                },
            )
            events.append(
                DeviceEvent(
                    device_id=device_id,
                    source="policy-engine",
                    severity=EventSeverity.INFO,
                    event_type="device.allowed",
                    details={
                        "action": "allow",
                        "reason": decision.reason,
                        "whitelist_id": str(matched_entry.id),
                        "whitelist_name": matched_entry.name,
                        **details,
                    },
                )
            )
            return decision, events

        # Device is not on the whitelist
        if self.mode == PolicyMode.ENFORCE:
            blocked, status_msg = self.blocker.disable_device(device_id)
            decision = PolicyDecision(
                allowed=False,
                action="block",
                reason="Unauthorized device: not found on the whitelist",
                device_id=device_id,
                matched_entry=None,
                blocked_successfully=blocked,
                details={"enforcement_status": status_msg, **details},
            )
            events.append(
                DeviceEvent(
                    device_id=device_id,
                    source="policy-engine",
                    severity=EventSeverity.CRITICAL,
                    event_type="device.blocked",
                    details={
                        "action": "block",
                        "reason": decision.reason,
                        "blocked": blocked,
                        "enforcement_message": status_msg,
                        **details,
                    },
                )
            )
            events.append(
                DeviceEvent(
                    device_id=device_id,
                    source="policy-engine",
                    severity=EventSeverity.WARNING,
                    event_type="policy.violation",
                    details={
                        "violation": "unauthorized_device_connected",
                        "device_id": device_id,
                        "mode": self.mode.value,
                        **details,
                    },
                )
            )
            return decision, events
        else:
            # Audit only mode
            decision = PolicyDecision(
                allowed=True,
                action="audit_violation",
                reason="Unknown device detected (audit-only policy mode)",
                device_id=device_id,
                matched_entry=None,
                blocked_successfully=False,
                details=details,
            )
            events.append(
                DeviceEvent(
                    device_id=device_id,
                    source="policy-engine",
                    severity=EventSeverity.WARNING,
                    event_type="policy.violation",
                    details={
                        "violation": "unauthorized_device_connected",
                        "device_id": device_id,
                        "mode": self.mode.value,
                        **details,
                    },
                )
            )
            return decision, events

    def block_threat(
        self,
        device_id: str,
        reason: str,
        *,
        threat_type: str = "detected_threat",
        details: dict[str, Any] | None = None,
    ) -> tuple[PolicyDecision, DeviceEvent]:
        """Directly block and disable a device identified as a threat (e.g. BadUSB, malware)."""
        details = details or {}
        blocked, status_msg = self.blocker.disable_device(device_id)
        decision = PolicyDecision(
            allowed=False,
            action="block",
            reason=reason,
            device_id=device_id,
            matched_entry=None,
            blocked_successfully=blocked,
            details={"threat_type": threat_type, "status": status_msg, **details},
        )
        event = DeviceEvent(
            device_id=device_id,
            source="policy-engine",
            severity=EventSeverity.CRITICAL,
            event_type="device.blocked",
            details={
                "action": "block",
                "reason": reason,
                "threat_type": threat_type,
                "blocked": blocked,
                "enforcement_message": status_msg,
                **details,
            },
        )
        return decision, event
