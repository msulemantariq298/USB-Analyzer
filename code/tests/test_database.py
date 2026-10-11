from pathlib import Path

from usb_analyzer.core.database import EventStore
from usb_analyzer.core.events import DeviceEvent, EventSeverity


def test_event_store_round_trips_events(tmp_path: Path) -> None:
    store = EventStore(tmp_path / "events.db")
    event = DeviceEvent(
        device_id="usb:test",
        source="test",
        severity=EventSeverity.WARNING,
        event_type="device.flagged",
        details={"reason": "unknown"},
    )

    store.add(event)

    result = store.list()
    assert len(result) == 1
    assert result[0] == event
