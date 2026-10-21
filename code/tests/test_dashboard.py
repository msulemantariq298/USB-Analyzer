from fastapi.testclient import TestClient

from usb_analyzer.api.main import app


def test_dashboard_is_served() -> None:
    response = TestClient(app).get("/")

    assert response.status_code == 200
    assert "USB Analyzer Dashboard" in response.text
    assert 'id="simulate-event"' not in response.text
    assert 'id="theme-toggle"' in response.text
    assert 'id="active-scans"' in response.text
    assert 'id="flagged-files"' in response.text

    script = TestClient(app).get("/static/app.js")
    assert script.status_code == 200
    assert "scan.started" in script.text
    assert "filename-based indicators" in script.text
