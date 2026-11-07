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
)
from usb_analyzer.hid_detector.detector import BadUsbDetector
from usb_analyzer.policy.engine import PolicyEngine

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
    )

    serial = device.serial_number or fingerprint.serial_number

    details: dict[str, Any] = {
        "pnp_device_id": device.device_id,
        "name": device.name,
        "manufacturer": device.manufacturer,
        "pnp_class": device.pnp_class,
        "service": device.service,
        "hardware_ids": list(device.hardware_ids),
        "status": device.status,
        "volume_paths": list(device.volume_paths),
        "serial_number": serial,
        "device_class": fingerprint.device_class,
        "interfaces": list(fingerprint.interfaces),
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

    def run(self, stop_event: Event) -> None:
        previous = dict(self.provider.list_devices())
        logger.info(
            "Monitoring USB devices; initial inventory contains %d device(s)",
            len(previous),
        )

        while not stop_event.wait(self.interval_seconds):
            current = dict(self.provider.list_devices())
            events = diff_devices(previous, current)
            for event in events:
                self.event_sink.add(event)
                logger.info(
                    "Sent %s event for %s (%s)",
                    event.event_type,
                    event.device_id,
                    event.details.get("name") or "unnamed device",
                )

                if event.event_type == "device.disconnected":
                    self.blocked_device_ids.discard(event.device_id)
                    if self.hid_detector is not None:
                        self.hid_detector.unregister_hid_device(event.device_id)

                elif event.event_type == "device.connected":
                    if self.hid_detector is not None:
                        dev_class = event.details.get("device_class") or ""
                        if "HID" in dev_class or "Keyboard" in dev_class:
                            self.hid_detector.register_hid_device(
                                event.device_id,
                                event.details.get("name"),
                            )

                    if self.policy_engine is not None:
                        device = current.get(event.device_id)
                        fp = extract_fingerprint(
                            device_id=event.device_id,
                            hardware_ids=device.hardware_ids if device else (),
                            pnp_class=device.pnp_class if device else None,
                            service=device.service if device else None,
                        )
                        serial = event.details.get("serial_number") or fp.serial_number

                        # Check Scenario 5: Spoofed Identity
                        trusted_list = self.policy_engine.store.list()
                        is_spoofed, spoof_reason, spoof_details = detect_spoofed_identity(fp, trusted_list)
                        if is_spoofed:
                            spoof_event = DeviceEvent(
                                device_id=event.device_id,
                                source="device-monitor",
                                severity=EventSeverity.CRITICAL,
                                event_type="device.spoofed_identity",
                                details={
                                    "reason": spoof_reason,
                                    **spoof_details,
                                    **event.details,
                                },
                            )
                            self.event_sink.add(spoof_event)
                            # Block the spoofed device
                            _, block_event = self.policy_engine.block_threat(
                                device_id=event.device_id,
                                reason=spoof_reason or "Spoofed USB identity detected",
                                threat_type="spoofed_identity",
                                details=spoof_details,
                            )
                            self.event_sink.add(block_event)
                            self.blocked_device_ids.add(event.device_id)
                            continue

                        # Evaluate Policy Engine Whitelist
                        decision, policy_events = self.policy_engine.evaluate_device(
                            device_id=event.device_id,
                            serial_number=serial,
                            vendor_id=fp.vendor_id,
                            product_id=fp.product_id,
                            details=event.details,
                        )
                        for pe in policy_events:
                            self.event_sink.add(pe)

                        if not decision.allowed:
                            self.blocked_device_ids.add(event.device_id)

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
            previous = current


def run_monitor(
    provider: DeviceProvider,
    event_sink: EventSink,
    stop_event: Event,
    interval_seconds: float = 1.0,
    storage_scan_scheduler: StorageScanScheduler | None = None,
    policy_engine: PolicyEngine | None = None,
    hid_detector: BadUsbDetector | None = None,
) -> None:
    """Run the monitor using an injectable provider for tests and OS backends."""

    DeviceMonitor(
        provider=provider,
        event_sink=event_sink,
        interval_seconds=interval_seconds,
        storage_scan_scheduler=storage_scan_scheduler,
        policy_engine=policy_engine,
        hid_detector=hid_detector,
    ).run(stop_event)
