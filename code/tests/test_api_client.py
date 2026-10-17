import httpx
import pytest
from fastapi.testclient import TestClient

from usb_analyzer.api import main as api_main
from usb_analyzer.core.api_client import ApiEventClient
from usb_analyzer.core.database import EventStore
from usb_analyzer.core.events import DeviceEvent


def test_api_event_client_delivers_event_to_api(tmp_path, monkeypatch) -> None:
    event_store = EventStore(tmp_path / "events.db")
    monkeypatch.setattr(api_main, "event_store", event_store)
    api_test_client = TestClient(api_main.app)

    def send_to_test_api(request: httpx.Request) -> httpx.Response:
        response = api_test_client.post(
            request.url.path,
            content=request.content,
            headers={"content-type": request.headers["content-type"]},
        )
        return httpx.Response(
            status_code=response.status_code,
            json=response.json(),
        )

    event = DeviceEvent(
        device_id=r"USB\VID_1234&PID_ABCD\SERIAL",
        source="device-monitor",
        event_type="device.connected",
        details={"name": "Demo USB device"},
    )

    with ApiEventClient(
        "http://usb-analyzer.test",
        "/api/v1",
        transport=httpx.MockTransport(send_to_test_api),
    ) as event_client:
        accepted_event = event_client.add(event)

    assert accepted_event == event
    assert event_store.list() == [event]


def test_api_event_client_raises_for_api_failure() -> None:
    transport = httpx.MockTransport(
        lambda request: httpx.Response(status_code=503, request=request)
    )
    event = DeviceEvent(
        device_id="usb:test",
        source="device-monitor",
        event_type="device.connected",
    )

    with ApiEventClient(
        "http://usb-analyzer.test",
        "/api/v1",
        transport=transport,
    ) as event_client:
        with pytest.raises(httpx.HTTPStatusError):
            event_client.add(event)
