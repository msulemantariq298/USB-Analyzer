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


def test_simulate_scenario_safe_usb() -> None:
    client = TestClient(app)
    response = client.post("/api/v1/simulate/scenario", json={"scenario": "safe_usb"})
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "simulated"
    assert data["scenario"] == "safe_usb"
    assert data["outcome"] == "allowed"
    assert "verified" in data["summary"].lower()


def test_simulate_scenario_badusb() -> None:
    client = TestClient(app)
    response = client.post("/api/v1/simulate/scenario", json={"scenario": "badusb"})
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "simulated"
    assert data["scenario"] == "badusb"
    assert data["outcome"] in ("blocked", "audit_warning")


def test_simulate_scenario_malware_drive() -> None:
    client = TestClient(app)
    response = client.post("/api/v1/simulate/scenario", json={"scenario": "malware_drive"})
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "simulated"
    assert data["scenario"] == "malware_drive"
    assert data["outcome"] in ("blocked", "audit_warning")


def test_simulate_scenario_unauthorized_device() -> None:
    client = TestClient(app)
    response = client.post("/api/v1/simulate/scenario", json={"scenario": "unauthorized_device"})
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "simulated"
    assert data["scenario"] == "unauthorized_device"
    assert data["outcome"] in ("blocked", "warning", "audit_warning")


def test_simulate_scenario_spoofed_identity() -> None:
    client = TestClient(app)
    response = client.post("/api/v1/simulate/scenario", json={"scenario": "spoofed_identity"})
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "simulated"
    assert data["scenario"] == "spoofed_identity"
    assert data["outcome"] in ("blocked", "audit_warning")


def test_simulate_scenario_invalid() -> None:
    client = TestClient(app)
    response = client.post("/api/v1/simulate/scenario", json={"scenario": "invalid_attack"})
    assert response.status_code == 400


def test_export_events_csv_endpoint() -> None:
    client = TestClient(app)
    response = client.get("/api/v1/reports/events.csv")
    assert response.status_code == 200
    assert "text/csv" in response.headers["content-type"]
    assert "Event ID" in response.text
    assert "Device ID" in response.text


def test_export_events_json_endpoint() -> None:
    client = TestClient(app)
    response = client.get("/api/v1/reports/events.json")
    assert response.status_code == 200
    assert "application/json" in response.headers["content-type"]
    assert isinstance(response.json(), list)


def test_manual_block_device_endpoint() -> None:
    client = TestClient(app)
    response = client.post(
        "/api/v1/devices/block",
        json={"device_id": "USB\\VID_9999&PID_8888\\TEST_MANUAL", "reason": "Untrusted accessory"},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "blocked"
    assert data["device_id"] == "USB\\VID_9999&PID_8888\\TEST_MANUAL"
    assert "isolated" in data["summary"].lower()


def test_manual_allow_device_endpoint() -> None:
    client = TestClient(app)
    device_id = "USB\\VID_9999&PID_8888\\TEST_ALLOW"
    response = client.post(
        "/api/v1/devices/allow",
        json={"device_id": device_id, "reason": "User clicked Let It Run"},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "allowed"
    assert data["device_id"] == device_id
    assert "permitted" in data["summary"].lower()

    events_resp = client.get("/api/v1/events")
    assert events_resp.status_code == 200
    matching = [
        ev for ev in events_resp.json()
        if ev["device_id"] == device_id and ev["event_type"] == "device.allowed"
    ]
    assert len(matching) >= 1
    assert matching[0]["details"]["decision"] == "let_run"
    assert matching[0]["details"]["action"] == "allowed_by_user"


