import logging
from collections import deque
import threading
import time
from typing import Any, Protocol

from usb_analyzer.core.events import DeviceEvent, EventSeverity
from usb_analyzer.hid_detector.tracker import InjectionAlert, KeystrokeDynamicsTracker
from usb_analyzer.policy.engine import PolicyEngine

logger = logging.getLogger(__name__)


class HidEventSink(Protocol):
    def add(self, event: DeviceEvent) -> DeviceEvent:
        """Publish a device security event."""


class BadUsbDetector:
    """Detects keystroke injection attacks (BadUSB / Rubber Ducky) and mitigates threats."""

    def __init__(
        self,
        event_sink: HidEventSink,
        policy_engine: PolicyEngine | None = None,
        tracker: KeystrokeDynamicsTracker | None = None,
    ) -> None:
        self.event_sink = event_sink
        self.policy_engine = policy_engine
        self.tracker = tracker or KeystrokeDynamicsTracker()
        self._recent_hid_devices: deque[dict[str, Any]] = deque(maxlen=10)
        self._lock = threading.Lock()
        self._listener: Any = None
        self._running = False

    def register_hid_device(self, device_id: str, name: str | None = None) -> None:
        """Track newly connected HID device so fast typing can be attributed to it."""
        with self._lock:
            self._recent_hid_devices.append({
                "device_id": device_id,
                "name": name or "USB Keyboard Device",
                "connected_at": time.time(),
            })
            logger.info("Registered active HID device for monitoring: %s", device_id)

    def unregister_hid_device(self, device_id: str) -> None:
        with self._lock:
            self._recent_hid_devices = deque(
                [d for d in self._recent_hid_devices if d["device_id"] != device_id],
                maxlen=10,
            )

    def on_keystroke(self, key_name: str = "key", timestamp: float | None = None) -> InjectionAlert | None:
        """Handle individual keystroke event."""
        alert = self.tracker.record_keystroke(key=key_name, timestamp=timestamp)
        if alert is not None:
            self._handle_alert(alert)
        return alert

    def _handle_alert(self, alert: InjectionAlert) -> None:
        with self._lock:
            attributed_device = self._recent_hid_devices[-1] if self._recent_hid_devices else None

        device_id = attributed_device["device_id"] if attributed_device else "USB\\UNKNOWN_HID_DEVICE"
        device_name = attributed_device["name"] if attributed_device else "Unidentified Keyboard"

        logger.critical(
            "ALERT: %s on %s (%s)",
            alert.summary,
            device_id,
            device_name,
        )

        event = DeviceEvent(
            device_id=device_id,
            source="hid-detector",
            severity=EventSeverity.CRITICAL,
            event_type="hid.injection_detected",
            details={
                "threat": "Keystroke Injection Attack (BadUSB / Rubber Ducky)",
                "summary": alert.summary,
                "typing_speed_cps": alert.characters_per_second,
                "average_iki_ms": alert.average_iki_ms,
                "std_dev_iki_ms": alert.std_dev_iki_ms,
                "is_robotic_cadence": alert.is_robotic,
                "keystrokes_counted": alert.keystroke_count,
                "device_name": device_name,
            },
        )
        self.event_sink.add(event)

        if self.policy_engine is not None:
            _, block_event = self.policy_engine.block_threat(
                device_id=device_id,
                reason=alert.summary,
                threat_type="badusb_keystroke_injection",
                details={
                    "typing_speed_cps": alert.characters_per_second,
                    "device_name": device_name,
                },
            )
            self.event_sink.add(block_event)

    def simulate_injection(
        self,
        char_count: int = 30,
        delay_per_char_seconds: float = 0.005,
        key_label: str = "A",
    ) -> InjectionAlert | None:
        """Simulate high-speed hardware keystroke injection for testing and demos."""
        start = time.monotonic()
        alert = None
        for i in range(char_count):
            t = start + (i * delay_per_char_seconds)
            res = self.on_keystroke(key_name=key_label, timestamp=t)
            if res:
                alert = res
        return alert

    def start_listener(self) -> bool:
        """Start global keyboard hook via pynput if available."""
        try:
            from pynput import keyboard

            def on_press(key: Any) -> None:
                try:
                    k_name = key.char if hasattr(key, "char") and key.char else str(key)
                except Exception:
                    k_name = "key"
                self.on_keystroke(k_name)

            self._listener = keyboard.Listener(on_press=on_press)
            self._listener.daemon = True
            self._listener.start()
            self._running = True
            logger.info("Started pynput background keyboard monitoring for BadUSB detection")
            return True
        except ImportError:
            logger.warning("pynput is not installed; live global keyboard hook disabled")
            return False
        except Exception as exc:
            logger.warning("Could not start keyboard listener: %s", exc)
            return False

    def stop_listener(self) -> None:
        if self._listener is not None:
            try:
                self._listener.stop()
            except Exception:
                pass
            self._listener = None
        self._running = False
