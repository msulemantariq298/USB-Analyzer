from pathlib import Path
from threading import Event

from usb_analyzer.core.events import DeviceEvent
from usb_analyzer.device_monitor.fingerprint import (
    DeviceFingerprint,
    detect_spoofed_identity,
    extract_fingerprint,
    extract_serial_number,
)
from usb_analyzer.device_monitor.monitor import DeviceMonitor, UsbDevice
from usb_analyzer.policy.engine import PolicyEngine
from usb_analyzer.policy.enforcement import MockDeviceBlocker
from usb_analyzer.policy.models import PolicyMode, WhitelistEntry
from usb_analyzer.policy.store import WhitelistStore


def test_extract_serial_number():
    assert extract_serial_number("USB\\VID_0951&PID_1666\\0014D12345678") == "0014D12345678"
    assert extract_serial_number("USBSTOR\\DISK&VEN_SANDISK&PROD_CRUZER\\4C531001460307111241&0") == "4C531001460307111241"
    assert extract_serial_number("USB\\VID_046D&PID_C52B\\6&1234567&0") == "6&1234567&0"
    assert extract_serial_number("INVALID_ID") is None


def test_extract_fingerprint():
    fp = extract_fingerprint(
        device_id="USB\\VID_046D&PID_C31C\\12345",
        hardware_ids=("USB\\VID_046D&PID_C31C&REV_0100", "USB\\VID_046D&PID_C31C&MI_00"),
        pnp_class="Keyboard",
    )

    assert fp.vendor_id == "046D"
    assert fp.product_id == "C31C"
    assert fp.revision == "0100"
    assert fp.serial_number == "12345"
    assert fp.device_class == "Human Interface Device (HID)"
    assert "Interface_00" in fp.interfaces
    assert fp.is_composite is True


def test_detect_spoofed_identity():
    # Scenario 5: Trusted VID/PID, different serial -> Mismatch alert
    trusted_entry = WhitelistEntry(
        name="Official Company YubiKey",
        vendor_id="1050",
        product_id="0407",
        serial_number="LEGIT_SERIAL_1234",
    )

    legit_fp = DeviceFingerprint(
        vendor_id="1050",
        product_id="0407",
        serial_number="LEGIT_SERIAL_1234",
    )
    is_spoofed, _, _ = detect_spoofed_identity(legit_fp, [trusted_entry])
    assert is_spoofed is False

    # Attacker device claims same VID/PID but different serial
    attacker_fp = DeviceFingerprint(
        vendor_id="1050",
        product_id="0407",
        serial_number="ATTACKER_FAKE_9999",
    )
    is_spoofed, reason, details = detect_spoofed_identity(attacker_fp, [trusted_entry])
    assert is_spoofed is True
    assert "Identity spoofing detected" in reason
    assert details["claimed_vid"] == "1050"
    assert details["expected_serial"] == "LEGIT_SERIAL_1234"
    assert details["observed_serial"] == "ATTACKER_FAKE_9999"


class FakeProvider:
    def __init__(self, devices_sequence):
        self.devices_sequence = list(devices_sequence)
        self.call_count = 0

    def list_devices(self):
        if self.call_count < len(self.devices_sequence):
            res = self.devices_sequence[self.call_count]
            self.call_count += 1
            return res
        return self.devices_sequence[-1]


class FakeSink:
    def __init__(self):
        self.events: list[DeviceEvent] = []

    def add(self, event: DeviceEvent) -> DeviceEvent:
        self.events.append(event)
        return event


def test_monitor_spoofed_identity_scenario(tmp_path: Path):
    store = WhitelistStore(tmp_path / "test.db")
    blocker = MockDeviceBlocker()
    engine = PolicyEngine(store=store, blocker=blocker, mode=PolicyMode.ENFORCE)

    # Register legitimate device
    store.add(
        WhitelistEntry(
            name="Secure Token",
            vendor_id="1050",
            product_id="0407",
            serial_number="LEGIT_SERIAL_1234",
        )
    )

    # Connected device has spoofed serial
    spoofed_device = UsbDevice(
        device_id="USB\\VID_1050&PID_0407\\SPOOFED_SERIAL_5555",
        name="Security Key",
    )

    provider = FakeProvider([
        {},  # initial baseline
        {spoofed_device.device_id: spoofed_device},  # newly connected
    ])
    sink = FakeSink()
    stop_event = Event()

    monitor = DeviceMonitor(
        provider=provider,
        event_sink=sink,
        interval_seconds=0.01,
        policy_engine=engine,
    )

    # Run one cycle then stop
    def stop_after_cycle():
        if len(sink.events) >= 2:
            stop_event.set()

    import threading
    timer = threading.Timer(0.1, stop_event.set)
    timer.start()
    try:
        monitor.run(stop_event)
    finally:
        timer.cancel()

    event_types = [e.event_type for e in sink.events]
    assert "device.connected" in event_types
    assert "device.spoofed_identity" in event_types
    assert "device.blocked" in event_types
    assert spoofed_device.device_id in blocker.blocked_devices
