import logging
import re
from collections.abc import Mapping
from dataclasses import dataclass
from threading import Event
from typing import Protocol

from usb_analyzer.core.events import DeviceEvent

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


class DeviceProvider(Protocol):
    def list_devices(self) -> Mapping[str, UsbDevice]:
        """Return currently present USB devices, keyed by stable instance ID."""


class EventSink(Protocol):
    def add(self, event: DeviceEvent) -> DeviceEvent:
        """Accept a device event and return the accepted event."""


def is_usb_device_id(device_id: str) -> bool:
    return device_id.upper().startswith(_USB_DEVICE_ID_PREFIXES)


def _event_for(device: UsbDevice, connected: bool) -> DeviceEvent:
    identifiers: dict[str, str] = {}
    for value in (device.device_id, *device.hardware_ids):
        for match in _USB_ID_PATTERN.finditer(value):
            identifiers.setdefault(match.group(1).lower(), match.group(2).upper())

    details: dict[str, object] = {
        "pnp_device_id": device.device_id,
        "name": device.name,
        "manufacturer": device.manufacturer,
        "pnp_class": device.pnp_class,
        "service": device.service,
        "hardware_ids": list(device.hardware_ids),
        "status": device.status,
    }
    if "vid" in identifiers:
        details["vendor_id"] = identifiers["vid"]
    if "pid" in identifiers:
        details["product_id"] = identifiers["pid"]

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
    ) -> None:
        if interval_seconds <= 0:
            raise ValueError("interval_seconds must be greater than zero")
        self.provider = provider
        self.event_sink = event_sink
        self.interval_seconds = interval_seconds

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
            previous = current


def run_monitor(
    provider: DeviceProvider,
    event_sink: EventSink,
    stop_event: Event,
    interval_seconds: float = 1.0,
) -> None:
    """Run the monitor using an injectable provider for tests and OS backends."""

    DeviceMonitor(
        provider=provider,
        event_sink=event_sink,
        interval_seconds=interval_seconds,
    ).run(stop_event)
