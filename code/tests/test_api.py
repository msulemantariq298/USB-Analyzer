from fastapi.testclient import TestClient

from usb_analyzer.api.main import app


def test_health_endpoint() -> None:
    client = TestClient(app)

    response = client.get("/api/v1/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_clear_events_endpoint() -> None:
    client = TestClient(app)

    # Clear endpoint returns 200 with deleted count integer
    response = client.delete("/api/v1/events")
    assert response.status_code == 200
    assert "deleted" in response.json()
    assert isinstance(response.json()["deleted"], int)
