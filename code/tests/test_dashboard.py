from fastapi.testclient import TestClient

from usb_analyzer.api.main import app


def test_dashboard_is_served() -> None:
    response = TestClient(app).get("/")

    assert response.status_code == 200
    assert "USB Analyzer Dashboard" in response.text
