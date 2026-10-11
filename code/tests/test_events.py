from datetime import datetime, timezone

from usb_analyzer.core.events import DeviceEvent, EventSeverity


def test_device_event_uses_utc_timestamp() -> None:
    event = DeviceEvent(
        device_id="usb:1234:5678:serial",
        source="device-monitor",
        event_type="device.connected",
    )

    assert event.time.tzinfo == timezone.utc
    assert event.severity is EventSeverity.INFO


def test_device_event_preserves_structured_details() -> None:
    event = DeviceEvent(
        time=datetime(2026, 10, 11, tzinfo=timezone.utc),
        device_id="usb:1234:5678:serial",
        source="storage-scanner",
        severity=EventSeverity.WARNING,
        event_type="file.flagged",
        details={"path": "autorun.inf", "sha256": "abc123"},
    )

    assert event.model_dump(mode="json")["details"]["path"] == "autorun.inf"
