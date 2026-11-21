from fastapi.testclient import TestClient

from usb_analyzer.api.main import app


def test_health_endpoint() -> None:
    client = TestClient(app)

    response = client.get("/api/v1/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}

    fav = client.get("/favicon.ico")
    assert fav.status_code == 200
    assert "image/svg+xml" in fav.headers["content-type"]


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
    import csv as _csv
    import io as _io

    from usb_analyzer.api.main import event_store
    from usb_analyzer.core.events import DeviceEvent, EventSeverity

    event_store.add(
        DeviceEvent(
            device_id="USB\\VID_058F&PID_6387\\27DB4F8B",
            source="storage-scanner",
            severity=EventSeverity.CRITICAL,
            event_type="scan.completed",
            details={
                "name": "Flash Disk",
                "volume_path": "F:\\",
                "files_scanned": 2,
                "flagged_count": 2,
                "max_risk_score": 90,
                "file_analyses": [
                    {
                        "path": "invoice_scan.pdf",
                        "file_type": "PE32 Executable",
                        "entropy": 7.88,
                        "risk_score": 90,
                        "sha256": "aa" * 32,
                        "md5": "bb" * 16,
                        "flags": ["extension_signature_mismatch"],
                        "metadata": {"extension": ".pdf", "extension_mismatch": True},
                    }
                ],
            },
        )
    )
    event_store.add(
        DeviceEvent(
            device_id="=MALICIOUS_DEV",
            source="policy-engine",
            severity=EventSeverity.WARNING,
            event_type="policy.violation",
            details={"reason": "+cmd|'/C calc'!A0"},
        )
    )

    client = TestClient(app)
    response = client.get("/api/v1/reports/events.csv")
    assert response.status_code == 200
    assert "text/csv" in response.headers["content-type"]
    text = response.content.decode("utf-8-sig")
    assert "Event ID" in text
    assert "Device ID" in text
    assert "SHA-256" in text
    assert "Entropy (b/B)" in text
    rows = list(_csv.DictReader(_io.StringIO(text)))
    file_rows = [r for r in rows if r["Record Type"] == "FILE"]
    assert file_rows
    matched = file_rows[0]
    assert matched["Vendor ID"] == "0x058F"
    assert matched["Product ID"] == "0x6387"
    assert matched["Serial Number"] == "27DB4F8B"
    assert matched["SHA-256"] == "aa" * 32
    assert matched["MD5"] == "bb" * 16
    assert matched["Risk Score"] == "90/100"
    assert matched["Volume / File Path"] == "F:\\invoice_scan.pdf"

    inj_rows = [r for r in rows if "=MALICIOUS_DEV" in r["Device ID"]]
    assert inj_rows
    assert inj_rows[0]["Device ID"].startswith("'=")
    assert inj_rows[0]["Reason / Risk"].startswith("'+")


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


def test_open_endpoint_without_active_dashboard_tab_redirects() -> None:
    client = TestClient(app)
    # When no client heartbeat has been registered, /open redirects (307) to the dashboard /
    response = client.get("/open?inspect_device=USB%5CTEST&triage=1", follow_redirects=False)
    assert response.status_code == 307
    assert response.headers["Location"] == "/?inspect_device=USB%5CTEST&triage=1"


def test_open_endpoint_with_active_dashboard_tab_returns_self_closing_html() -> None:
    client = TestClient(app)
    # Register an active client heartbeat
    hb_resp = client.post("/api/v1/dashboard/heartbeat?client_id=test_tab_1")
    assert hb_resp.status_code == 200

    # /open now returns the self-closing HTML to prevent opening duplicate tabs
    response = client.get("/open?inspect_device=USB%5CTEST_ACTIVE", follow_redirects=False)
    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]
    assert "window.close()" in response.text

    # Heartbeat retrieves queued notification actions
    hb_resp2 = client.post("/api/v1/dashboard/heartbeat?client_id=test_tab_1")
    data = hb_resp2.json()
    assert data["status"] == "ok"
    assert any(a["device_id"] == "USB\\TEST_ACTIVE" for a in data.get("actions", []))


def test_websocket_telemetry_stream() -> None:
    client = TestClient(app)
    with client.websocket_connect("/api/v1/ws/telemetry") as ws:
        init_msg = ws.receive_json()
        assert init_msg["type"] == "connected"
        assert "USB Analyzer" in init_msg["message"]
        ws.send_text("ping")
        pong = ws.receive_text()
        assert pong == "pong"


def test_activity_analytics_endpoint() -> None:
    client = TestClient(app)
    client.delete("/api/v1/events")
    res = client.get("/api/v1/analytics/activity?range=1h")
    assert res.status_code == 200
    data = res.json()
    assert data["range"] == "1h"
    assert len(data["labels"]) == len(data["data"])
    assert data["total_events"] == 0
    assert data["suspicious_events"] == 0


def test_create_event_notification_honesty_and_suppression(monkeypatch) -> None:
    import usb_analyzer.api.main as api_main

    sent: list[tuple[str, str, str]] = []

    def fake_notify(title: str, message: str, *, severity: str = "info", **_kwargs) -> None:
        sent.append((title, message, severity))

    monkeypatch.setattr(api_main, "send_desktop_notification", fake_notify)
    client = TestClient(app)

    # 1. Suppressed preliminary event does not emit duplicate toast
    resp1 = client.post(
        "/api/v1/events",
        json={
            "device_id": "USB\\VID_1111&PID_2222\\SUPPRESS",
            "source": "device-monitor",
            "severity": "critical",
            "event_type": "device.spoofed_identity",
            "details": {"suppress_toast": True, "summary": "Spoofed"},
        },
    )
    assert resp1.status_code == 201
    assert len(sent) == 0

    # 2. Failed block (blocked=False) reports elevation needed instead of "Port disabled"
    resp2 = client.post(
        "/api/v1/events",
        json={
            "device_id": "USB\\VID_1111&PID_2222\\FAIL_BLK",
            "source": "policy-engine",
            "severity": "critical",
            "event_type": "device.blocked",
            "details": {"blocked": False, "summary": "Threat detected"},
        },
    )
    assert resp2.status_code == 201
    assert len(sent) == 1
    assert "Elevation Required" in sent[0][0]
    assert "Action taken: Port disabled" not in sent[0][1]


def test_connected_devices_endpoint() -> None:
    client = TestClient(app)
    res = client.get("/api/v1/devices/connected")
    assert res.status_code == 200
    assert isinstance(res.json(), list)


def test_scan_devices_endpoint() -> None:
    client = TestClient(app)
    res = client.post("/api/v1/devices/scan")
    assert res.status_code == 200
    data = res.json()
    assert "status" in data


def test_scanner_rules_and_storage_scan_endpoints(tmp_path) -> None:
    client = TestClient(app)

    rules_resp = client.get("/api/v1/scanner/rules")
    assert rules_resp.status_code == 200
    rules_data = rules_resp.json()
    assert len(rules_data["rules"]) >= 10
    assert rules_data["hash_ioc_count"] >= 1

    # Initial scan of clean file
    (tmp_path / "notes.txt").write_text("Clean engineering notes", encoding="utf-8")
    first_scan = client.post("/api/v1/storage/scan", json={"volume_path": str(tmp_path)})
    assert first_scan.status_code == 200
    d1 = first_scan.json()
    assert d1["volumes_scanned"] == 1
    assert d1["files_scanned"] == 1
    assert d1["max_risk_score"] < 20

    # Drop a new suspicious packed file and re-scan -> marked as NEW and scored >= 20
    (tmp_path / "packed.dat").write_bytes(bytes(range(256)) * 12)
    second_scan = client.post("/api/v1/storage/scan", json={"volume_path": str(tmp_path)})
    assert second_scan.status_code == 200
    d2 = second_scan.json()
    assert d2["files_scanned"] == 2
    assert d2["new_files_count"] == 1
    assert d2["max_risk_score"] >= 25
    by_name = {f["path"]: f for f in d2["results"][0]["file_analyses"]}
    assert by_name["packed.dat"]["change_status"] == "new"
    assert by_name["notes.txt"]["change_status"] == "existing"


