import logging
import re
from collections.abc import Mapping
from dataclasses import dataclass
from threading import Event
from typing import Any, Protocol

from usb_analyzer.core.events import DeviceEvent, EventSeverity
from usb_analyzer.device_monitor.fingerprint import (
    DeviceFingerprint,
    detect_spoofed_identity,
    extract_fingerprint,
    is_known_attacker_hardware,
    is_standard_peripheral,
)
from usb_analyzer.hid_detector.detector import BadUsbDetector
from usb_analyzer.policy.engine import PolicyEngine
from usb_analyzer.policy.models import PolicyMode

logger = logging.getLogger(__name__)

_USB_DEVICE_ID_PREFIXES = ("USB\\", "USBSTOR\\")
_USB_ID_PATTERN = re.compile(r"\b(VID|PID)_([0-9A-F]{4})\b", re.IGNORECASE)


@dataclass(frozen=True)
class UsbDevice:
    """Normalized subset of device metadata used by the shared event contract."""

    device_id: str
    name: str | None = None
    manufacturer: str | None = None
    pnp_class: str | None = None
    service: str | None = None
    hardware_ids: tuple[str, ...] = ()
    status: str | None = None
    volume_paths: tuple[str, ...] = ()
    serial_number: str | None = None
    device_type: str | None = None


class DeviceProvider(Protocol):
    def list_devices(self) -> Mapping[str, UsbDevice]:
        """Return currently present USB devices, keyed by stable instance ID."""


class EventSink(Protocol):
    def add(self, event: DeviceEvent) -> DeviceEvent:
        """Accept a device event and return the accepted event."""


class StorageScanScheduler(Protocol):
    def schedule(self, device_id: str, volume_path: str) -> None:
        """Schedule a read-only scan without blocking device polling."""


def is_usb_device_id(device_id: str) -> bool:
    return device_id.upper().startswith(_USB_DEVICE_ID_PREFIXES)


def _event_for(device: UsbDevice, connected: bool) -> DeviceEvent:
    fingerprint = extract_fingerprint(
        device_id=device.device_id,
        hardware_ids=device.hardware_ids,
        pnp_class=device.pnp_class,
        service=device.service,
        name=device.name,
        manufacturer=device.manufacturer,
    )

    serial = device.serial_number or fingerprint.serial_number
    dev_type = device.device_type or fingerprint.device_type
    dev_name = device.name or fingerprint.friendly_name or "USB Peripheral"

    details: dict[str, Any] = {
        "pnp_device_id": device.device_id,
        "name": dev_name,
        "friendly_name": dev_name,
        "device_type": dev_type,
        "manufacturer": device.manufacturer,
        "pnp_class": device.pnp_class,
        "service": device.service,
        "hardware_ids": list(device.hardware_ids),
        "status": device.status,
        "volume_paths": list(device.volume_paths),
        "serial_number": serial,
        "device_class": fingerprint.device_class,
        "interfaces": list(fingerprint.interfaces),
        "verdict": "SAFE" if connected else "INFO",
        "risk": "None",
        "action_taken": "Connected" if connected else "Disconnected",
        "summary": f"{dev_name} ({dev_type}) {'connected to system' if connected else 'disconnected'}",
    }
    if fingerprint.vendor_id:
        details["vendor_id"] = fingerprint.vendor_id
    if fingerprint.product_id:
        details["product_id"] = fingerprint.product_id
    if fingerprint.revision:
        details["revision"] = fingerprint.revision

    return DeviceEvent(
        device_id=device.device_id,
        source="device-monitor",
        event_type="device.connected" if connected else "device.disconnected",
        details=details,
    )


def diff_devices(
    previous: Mapping[str, UsbDevice],
    current: Mapping[str, UsbDevice],
) -> list[DeviceEvent]:
    """Create connection/disconnection events for inventory changes."""

    connected_ids = set(current) - set(previous)
    disconnected_ids = set(previous) - set(current)
    events = [_event_for(current[key], connected=True) for key in sorted(connected_ids)]
    events.extend(
        _event_for(previous[key], connected=False)
        for key in sorted(disconnected_ids)
    )
    return events


class DeviceMonitor:
    """Poll devices and send inventory changes to the configured event sink."""

    def __init__(
        self,
        provider: DeviceProvider,
        event_sink: EventSink,
        interval_seconds: float = 1.0,
        storage_scan_scheduler: StorageScanScheduler | None = None,
        policy_engine: PolicyEngine | None = None,
        hid_detector: BadUsbDetector | None = None,
    ) -> None:
        if interval_seconds <= 0:
            raise ValueError("interval_seconds must be greater than zero")
        self.provider = provider
        self.event_sink = event_sink
        self.interval_seconds = interval_seconds
        self.storage_scan_scheduler = storage_scan_scheduler
        self.policy_engine = policy_engine
        self.hid_detector = hid_detector
        self.blocked_device_ids: set[str] = set()

    def run(self, stop_event: Event, populate_initial: bool = False) -> None:
        initial = dict(self.provider.list_devices())
        logger.info(
            "Monitoring USB devices; initial inventory contains %d device(s)",
            len(initial),
        )

        previous: dict[str, UsbDevice] = {}
        if populate_initial and initial:
            initial_events = diff_devices({}, initial)
            for event in initial_events:
                self._process_event(event, initial)
            if self.storage_scan_scheduler is not None:
                for device_id, device in initial.items():
                    if device_id in self.blocked_device_ids:
                        continue
                    for volume_path in device.volume_paths:
                        self.storage_scan_scheduler.schedule(device_id, volume_path)
            previous = initial
        else:
            previous = initial

        while not stop_event.wait(self.interval_seconds):
            current = dict(self.provider.list_devices())
            events = diff_devices(previous, current)
            for event in events:
                self._process_event(event, current)

            if (
                self.policy_engine is not None
                and self.blocked_device_ids
                and hasattr(self.policy_engine.store, "is_device_allowed_session")
            ):
                for blocked_id in list(self.blocked_device_ids):
                    if self.policy_engine.store.is_device_allowed_session(blocked_id):
                        self.blocked_device_ids.discard(blocked_id)

            if self.storage_scan_scheduler is not None:
                for device_id, device in current.items():
                    if device_id in self.blocked_device_ids:
                        continue  # Do not scan blocked devices
                    old_device = previous.get(device_id)
                    previous_paths = {
                        path.casefold()
                        for path in old_device.volume_paths
                    } if old_device is not None else set()
                    for volume_path in device.volume_paths:
                        if volume_path.casefold() not in previous_paths:
                            self.storage_scan_scheduler.schedule(
                                device_id,
                                volume_path,
                            )
                        elif hasattr(self.storage_scan_scheduler, "check_and_reschedule"):
                            self.storage_scan_scheduler.check_and_reschedule(
                                device_id,
                                volume_path,
                            )
            previous = current

    def _process_event(self, event: DeviceEvent, current: Mapping[str, UsbDevice]) -> None:
        if event.event_type == "device.disconnected":
            self.event_sink.add(event)
            logger.info(
                "Sent %s event for %s (%s)",
                event.event_type,
                event.device_id,
                event.details.get("name") or "unnamed device",
            )
            self.blocked_device_ids.discard(event.device_id)
            if (
                self.policy_engine is not None
                and hasattr(self.policy_engine.store, "clear_device_session")
            ):
                self.policy_engine.store.clear_device_session(event.device_id)
            if self.hid_detector is not None:
                self.hid_detector.unregister_hid_device(event.device_id)
            return

        if event.event_type != "device.connected":
            self.event_sink.add(event)
            return

        if self.hid_detector is not None:
            dev_class = event.details.get("device_class") or ""
            if "HID" in dev_class or "Keyboard" in dev_class:
                self.hid_detector.register_hid_device(
                    event.device_id,
                    event.details.get("name"),
                )

        if self.policy_engine is None:
            self.event_sink.add(event)
            logger.info(
                "Sent %s event for %s (%s)",
                event.event_type,
                event.device_id,
                event.details.get("name") or "unnamed device",
            )
            return

        if hasattr(self.policy_engine.store, "get_policy_mode"):
            persisted_mode = self.policy_engine.store.get_policy_mode()
            if persisted_mode is not None:
                self.policy_engine.mode = persisted_mode

        device = current.get(event.device_id)
        fp = extract_fingerprint(
            device_id=event.device_id,
            hardware_ids=device.hardware_ids if device else (),
            pnp_class=device.pnp_class if device else None,
            service=device.service if device else None,
            name=device.name if device else None,
            manufacturer=device.manufacturer if device else None,
        )
        serial = event.details.get("serial_number") or fp.serial_number
        dev_label = event.details.get("friendly_name") or event.details.get("name") or "USB Device"
        dev_type = event.details.get("device_type") or fp.device_type

        # 1. Check Scenario 5: Spoofed Identity
        trusted_list = self.policy_engine.store.list()
        is_spoofed, spoof_reason, spoof_details = detect_spoofed_identity(fp, trusted_list)
        if is_spoofed:
            event.details["verdict"] = "DANGER"
            event.details["risk"] = "Identity Spoofing Detected"
            event.details["action_taken"] = "Inspecting & Isolating Threat"
            event.details["summary"] = (
                f"{dev_label} ({dev_type}) — DANGER: Identity spoofing detected ({spoof_reason})."
            )
            self.event_sink.add(event)
            logger.info("Sent %s event for %s (%s)", event.event_type, event.device_id, dev_label)

            spoof_event = DeviceEvent(
                device_id=event.device_id,
                source="device-monitor",
                severity=EventSeverity.CRITICAL,
                event_type="device.spoofed_identity",
                details={
                    "reason": spoof_reason,
                    "verdict": "DANGER",
                    "risk": "Identity Spoofing Detected",
                    "suppress_toast": True,
                    "summary": event.details["summary"],
                    **spoof_details,
                    **event.details,
                },
            )
            self.event_sink.add(spoof_event)

            block_decision, block_event = self.policy_engine.block_threat(
                device_id=event.device_id,
                reason=spoof_reason or "Spoofed USB identity detected",
                threat_type="spoofed_identity",
                details=spoof_details,
            )
            block_action = (
                "Hardware Blocked (Port Disabled)"
                if block_decision.blocked_successfully
                else "Block Failed (Administrator Privileges Required)"
            )
            block_event.details["verdict"] = "DANGER"
            block_event.details["risk"] = "Identity Spoofing Detected"
            block_event.details["action_taken"] = block_action
            block_event.details["summary"] = (
                f"{dev_label} ({dev_type}) — DANGER: Identity spoofing detected ({spoof_reason}). "
                f"Action taken: {block_action}."
            )
            self.event_sink.add(block_event)
            if block_decision.blocked_successfully:
                self.blocked_device_ids.add(event.device_id)
            return

        # 2. Check Known Attacker Hardware Signatures (Hak5 / MalDuino / BadUSB)
        is_attacker, attacker_reason = is_known_attacker_hardware(fp)
        if is_attacker:
            event.details["verdict"] = "DANGER"
            event.details["risk"] = "Malicious Attacker Hardware"
            event.details["action_taken"] = "Inspecting & Isolating Threat"
            event.details["summary"] = f"{dev_label} ({dev_type}) — DANGER: {attacker_reason}."
            self.event_sink.add(event)
            logger.info("Sent %s event for %s (%s)", event.event_type, event.device_id, dev_label)

            attacker_event = DeviceEvent(
                device_id=event.device_id,
                source="device-monitor",
                severity=EventSeverity.CRITICAL,
                event_type="device.attack_hardware",
                details={
                    "reason": attacker_reason,
                    "verdict": "DANGER",
                    "risk": "Malicious Attacker Hardware",
                    "suppress_toast": True,
                    "summary": event.details["summary"],
                    **event.details,
                },
            )
            self.event_sink.add(attacker_event)

            block_decision, block_event = self.policy_engine.block_threat(
                device_id=event.device_id,
                reason=attacker_reason or "Known attack hardware detected",
                threat_type="attack_hardware",
                details=event.details,
            )
            block_action = (
                "Hardware Blocked (Port Disabled)"
                if block_decision.blocked_successfully
                else "Block Failed (Administrator Privileges Required)"
            )
            block_event.details["verdict"] = "DANGER"
            block_event.details["risk"] = "Malicious Attacker Hardware"
            block_event.details["action_taken"] = block_action
            block_event.details["summary"] = (
                f"{dev_label} ({dev_type}) — DANGER: {attacker_reason}. Action taken: {block_action}."
            )
            self.event_sink.add(block_event)
            if block_decision.blocked_successfully:
                self.blocked_device_ids.add(event.device_id)
            return

        # 3. Whitelist check (if explicit whitelist entry exists)
        matched_rule = self.policy_engine.store.find_match(
            serial_number=serial,
            vendor_id=fp.vendor_id,
            product_id=fp.product_id,
            device_id=event.device_id,
        )

        if matched_rule is not None:
            event.details["verdict"] = "SAFE"
            event.details["risk"] = "None (Authorized Peripheral)"
            event.details["action_taken"] = "Allowed & Active"
            event.details["summary"] = (
                f"{dev_label} ({dev_type}) — SAFE: Authorized by whitelist rule '{matched_rule.name}'."
            )
            self.event_sink.add(event)
            logger.info("Sent %s event for %s (%s)", event.event_type, event.device_id, dev_label)

            wl_event = DeviceEvent(
                device_id=event.device_id,
                source="policy-engine",
                severity=EventSeverity.INFO,
                event_type="policy.allowed",
                details={
                    "reason": f"Device matched whitelist rule '{matched_rule.name}'.",
                    "action": "allow",
                    "verdict": "SAFE",
                    "risk": "None (Authorized Peripheral)",
                    "action_taken": "Allowed & Active",
                    "summary": event.details["summary"],
                    **event.details,
                },
            )
            self.event_sink.add(wl_event)
        elif is_standard_peripheral(dev_type):
            # Standard Everyday Peripherals (Keyboard, Mouse, Storage Drive, Card Reader, Hub, Audio, Webcam)
            event.details["verdict"] = "SAFE"
            event.details["risk"] = "None"
            event.details["action_taken"] = "Allowed & Monitored"
            event.details["summary"] = (
                f"{dev_label} ({dev_type}) — SAFE: Standard desktop peripheral connected and active."
            )
            self.event_sink.add(event)
            logger.info("Sent %s event for %s (%s)", event.event_type, event.device_id, dev_label)
        else:
            # Truly Unrecognized / Unknown Raw Hardware -> evaluate via policy engine
            decision, policy_events = self.policy_engine.evaluate_device(
                device_id=event.device_id,
                serial_number=serial,
                vendor_id=fp.vendor_id,
                product_id=fp.product_id,
                details=event.details,
            )
            if self.policy_engine.mode == PolicyMode.AUDIT_ONLY:
                risk_msg = "Unrecognized Hardware (Audit Only)"
                action_msg = "Logged (Audit Mode)"
                summary_msg = f"{dev_label} ({dev_type}) — WARNING: Unregistered hardware logged in audit-only mode."
            elif decision.blocked_successfully:
                risk_msg = "Unrecognized Hardware (Contained)"
                action_msg = "Contained (Blocked until Allowed)"
                summary_msg = (
                    f"{dev_label} ({dev_type}) — WARNING: Unregistered hardware held in containment until operator approval."
                )
            else:
                risk_msg = "Unrecognized Hardware (Elevation Required to Block)"
                action_msg = "Block Failed (Run as Admin)"
                summary_msg = (
                    f"{dev_label} ({dev_type}) — WARNING: Unregistered hardware detected; "
                    "Administrator privileges required to disable the USB port."
                )

            event.details["verdict"] = "WARNING"
            event.details["risk"] = risk_msg
            event.details["action_taken"] = action_msg
            event.details["summary"] = summary_msg
            event.details["blocked_successfully"] = decision.blocked_successfully
            self.event_sink.add(event)
            logger.info("Sent %s event for %s (%s)", event.event_type, event.device_id, dev_label)

            if decision.blocked_successfully:
                self.blocked_device_ids.add(event.device_id)

            for pe in policy_events:
                pe.details["verdict"] = "WARNING"
                pe.details["risk"] = risk_msg
                pe.details["action_taken"] = action_msg
                pe.details["summary"] = summary_msg
                pe.details["blocked_successfully"] = decision.blocked_successfully
                if pe.event_type == "device.blocked":
                    pe.details["suppress_toast"] = True
                self.event_sink.add(pe)


def run_monitor(
    provider: DeviceProvider,
    event_sink: EventSink,
    stop_event: Event,
    interval_seconds: float = 1.0,
    storage_scan_scheduler: StorageScanScheduler | None = None,
    policy_engine: PolicyEngine | None = None,
    hid_detector: BadUsbDetector | None = None,
    populate_initial: bool = False,
) -> None:
    """Run the monitor using an injectable provider for tests and OS backends."""

    DeviceMonitor(
        provider=provider,
        event_sink=event_sink,
        interval_seconds=interval_seconds,
        storage_scan_scheduler=storage_scan_scheduler,
        policy_engine=policy_engine,
        hid_detector=hid_detector,
    ).run(stop_event, populate_initial=populate_initial)
