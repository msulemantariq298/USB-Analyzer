from pathlib import Path

import pytest

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


def test_event_store_accepts_repeated_identical_event_id(tmp_path: Path) -> None:
    store = EventStore(tmp_path / "events.db")
    event = DeviceEvent(
        device_id="usb:test",
        source="test",
        event_type="scan.completed",
    )

    assert store.add(event) == event
    assert store.add(event) == event
    assert store.list() == [event]


def test_event_store_rejects_reused_id_with_different_data(tmp_path: Path) -> None:
    store = EventStore(tmp_path / "events.db")
    event = DeviceEvent(
        device_id="usb:test",
        source="test",
        event_type="scan.completed",
    )
    conflicting_event = event.model_copy(update={"event_type": "scan.failed"})

    store.add(event)

    with pytest.raises(ValueError, match="already exists with different data"):
        store.add(conflicting_event)
