from fastapi.testclient import TestClient

from usb_analyzer.api.main import app


def test_health_endpoint() -> None:
    client = TestClient(app)

    response = client.get("/api/v1/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}
