from pathlib import Path
import time

from fastapi.testclient import TestClient

from usb_analyzer.api.main import app
from usb_analyzer.core.events import DeviceEvent, EventSeverity
from usb_analyzer.hid_detector.detector import BadUsbDetector
from usb_analyzer.hid_detector.tracker import KeystrokeDynamicsTracker
from usb_analyzer.policy.engine import PolicyEngine
from usb_analyzer.policy.enforcement import MockDeviceBlocker
from usb_analyzer.policy.models import PolicyMode
from usb_analyzer.policy.store import WhitelistStore


def test_keystroke_dynamics_human_typing():
    tracker = KeystrokeDynamicsTracker(window_size=10, burst_threshold_cps=20.0)

    # Human typing: 150ms to 250ms per key (~5 keystrokes per second)
    current_time = 1000.0
    delays = [0.18, 0.22, 0.15, 0.30, 0.19, 0.25, 0.17, 0.21, 0.28, 0.16]

    alert = None
    for delay in delays:
        current_time += delay
        res = tracker.record_keystroke("a", timestamp=current_time)
        if res:
            alert = res

    assert alert is None  # Benign human typing must NOT trigger false positive


def test_scenario_3_keystroke_injection_badusb():
    # Scenario 3 from proposal:
    # "Keystroke injection: Digispark / Arduino Leonardo, or uinput script -> Flagged and blocked"
    tracker = KeystrokeDynamicsTracker(window_size=15, burst_threshold_cps=20.0)

    # BadUSB injection: 5ms between keystrokes (200 keystrokes/sec!)
    current_time = 2000.0
    alert = None
    for _ in range(20):
        current_time += 0.005
        res = tracker.record_keystroke("x", timestamp=current_time)
        if res:
            alert = res

    assert alert is not None
    assert alert.characters_per_second >= 20.0
    assert alert.average_iki_ms <= 10.0
    assert alert.is_robotic is True
    assert "BadUSB" in alert.summary


class FakeSink:
    def __init__(self):
        self.events: list[DeviceEvent] = []

    def add(self, event: DeviceEvent) -> DeviceEvent:
        self.events.append(event)
        return event


def test_badusb_detector_attributing_and_blocking(tmp_path: Path):
    sink = FakeSink()
    store = WhitelistStore(tmp_path / "test.db")
    blocker = MockDeviceBlocker()
    engine = PolicyEngine(store=store, blocker=blocker, mode=PolicyMode.ENFORCE)

    detector = BadUsbDetector(event_sink=sink, policy_engine=engine)

    # Malicious Digispark / Rubber Ducky plugged in
    badusb_id = "USB\\VID_16C0&PID_05DF\\DIGISPARK_ATTACKER_001"
    detector.register_hid_device(badusb_id, "Digispark BadUSB")

    # Executes rapid automated keystrokes
    alert = detector.simulate_injection(char_count=25, delay_per_char_seconds=0.004)

    assert alert is not None
    assert len(sink.events) == 2
    event_types = [e.event_type for e in sink.events]
    assert "hid.injection_detected" in event_types
    assert "device.blocked" in event_types

    injection_event = next(e for e in sink.events if e.event_type == "hid.injection_detected")
    assert injection_event.device_id == badusb_id
    assert injection_event.severity == EventSeverity.CRITICAL

    # Device blocked
    assert badusb_id in blocker.blocked_devices


def test_api_simulate_badusb():
    client = TestClient(app)
    resp = client.post(
        "/api/v1/simulate/badusb",
        json={
            "device_id": "USB\\VID_1B4F&PID_9206\\TEST_BADUSB",
            "device_name": "Pro Micro BadUSB",
            "char_count": 30,
            "delay_ms": 3.0,
        },
    )

    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "simulated"
    assert data["detected"] is True
    assert "BadUSB" in data["summary"]

