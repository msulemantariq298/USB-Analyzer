from threading import Event
from unittest.mock import Mock

import pytest

from usb_analyzer.core.database import EventStore
from usb_analyzer.device_monitor.monitor import (
    DeviceMonitor,
    UsbDevice,
    diff_devices,
    is_usb_device_id,
)


def test_is_usb_device_id_accepts_usb_device_and_storage_ids() -> None:
    assert is_usb_device_id(r"USB\VID_1234&PID_ABCD\SERIAL")
    assert is_usb_device_id(r"USBSTOR\DISK&VEN_DEMO&PROD_DRIVE\123")
    assert not is_usb_device_id(r"BTHENUM\DEV_1234")


def test_diff_devices_creates_connect_and_disconnect_events() -> None:
    connected = UsbDevice(
        device_id=r"USB\VID_1234&PID_ABCD\SERIAL",
        name="Demo USB drive",
        manufacturer="Example",
    )
    disconnected = UsbDevice(device_id=r"USBSTOR\DISK&VEN_DEMO\OLD")

    events = diff_devices(
        {disconnected.device_id: disconnected},
        {connected.device_id: connected},
    )

    assert [event.event_type for event in events] == [
        "device.connected",
        "device.disconnected",
    ]
    assert events[0].source == "device-monitor"
    assert events[0].details["vendor_id"] == "1234"
    assert events[0].details["product_id"] == "ABCD"
    assert events[1].device_id == disconnected.device_id


def test_diff_devices_ignores_unchanged_inventory() -> None:
    device = UsbDevice(device_id=r"USB\VID_1234&PID_ABCD\SERIAL")

    assert diff_devices({device.device_id: device}, {device.device_id: device}) == []


def test_monitor_persists_inventory_changes(tmp_path) -> None:
    device = UsbDevice(
        device_id=r"USB\VID_1234&PID_ABCD\SERIAL",
        name="Demo USB drive",
    )

    class ChangingProvider:
        calls = 0

        def list_devices(self):
            self.calls += 1
            return {} if self.calls == 1 else {device.device_id: device}

    provider = ChangingProvider()
    store = EventStore(tmp_path / "events.db")
    stop_event = Mock(spec=Event)
    stop_event.wait.side_effect = [False, True]

    DeviceMonitor(provider, store, interval_seconds=0.01).run(stop_event)

    saved_events = store.list()
    assert len(saved_events) == 1
    assert saved_events[0].event_type == "device.connected"
    assert saved_events[0].device_id == device.device_id


def test_monitor_rejects_non_positive_interval(tmp_path) -> None:
    with pytest.raises(ValueError, match="greater than zero"):
        DeviceMonitor(object(), EventStore(tmp_path / "events.db"), interval_seconds=0)
