from pathlib import Path
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from usb_analyzer.api.main import app, whitelist_store
from usb_analyzer.core.events import EventSeverity
from usb_analyzer.policy.engine import PolicyEngine
from usb_analyzer.policy.enforcement import MockDeviceBlocker
from usb_analyzer.policy.models import PolicyMode, WhitelistEntry
from usb_analyzer.policy.store import WhitelistStore


def test_whitelist_entry_matches():
    entry = WhitelistEntry(
        name="Kingston DataTraveler",
        serial_number="0014D12345678",
        vendor_id="0951",
        product_id="1666",
        device_id="USB\\VID_0951&PID_1666\\0014D12345678",
    )

    # Match all identical
    assert entry.matches(
        serial_number="0014D12345678",
        vendor_id="0951",
        product_id="1666",
        device_id="USB\\VID_0951&PID_1666\\0014D12345678",
    )

    # Match case-insensitive
    assert entry.matches(
        serial_number="0014d12345678",
        vendor_id="0951",
        product_id="1666",
    )

    # Serial mismatch
    assert not entry.matches(
        serial_number="DIFFERENT_SERIAL",
        vendor_id="0951",
        product_id="1666",
    )

    # PID mismatch
    assert not entry.matches(
        serial_number="0014D12345678",
        vendor_id="0951",
        product_id="9999",
    )


def test_whitelist_store_crud(tmp_path: Path):
    db_path = tmp_path / "test_whitelist.db"
    store = WhitelistStore(db_path)

    entry1 = WhitelistEntry(
        name="Admin Flash Drive",
        serial_number="SN12345",
        vendor_id="1234",
        product_id="5678",
    )
    store.add(entry1)

    items = store.list()
    assert len(items) == 1
    assert items[0].name == "Admin Flash Drive"

    # Get by ID
    fetched = store.get(entry1.id)
    assert fetched is not None
    assert fetched.serial_number == "SN12345"

    # Find match
    matched = store.find_match(serial_number="SN12345", vendor_id="1234", product_id="5678")
    assert matched is not None
    assert matched.id == entry1.id

    no_match = store.find_match(serial_number="UNKNOWN_SN")
    assert no_match is None

    # Remove
    assert store.remove(entry1.id)
    assert len(store.list()) == 0
    assert not store.remove(entry1.id)


def test_policy_engine_allow_whitelisted(tmp_path: Path):
    store = WhitelistStore(tmp_path / "test.db")
    blocker = MockDeviceBlocker()
    engine = PolicyEngine(store=store, blocker=blocker, mode=PolicyMode.ENFORCE)

    entry = WhitelistEntry(name="Approved Keyboard", serial_number="KB-999")
    store.add(entry)

    decision, events = engine.evaluate_device(
        device_id="USB\\VID_046D&PID_C31C\\KB-999",
        serial_number="KB-999",
    )

    assert decision.allowed is True
    assert decision.action == "allow"
    assert len(blocker.blocked_devices) == 0
    assert len(events) == 1
    assert events[0].event_type == "device.allowed"
    assert events[0].severity == EventSeverity.INFO


def test_policy_engine_block_unauthorized_enforce_mode(tmp_path: Path):
    store = WhitelistStore(tmp_path / "test.db")
    blocker = MockDeviceBlocker(should_succeed=True)
    engine = PolicyEngine(store=store, blocker=blocker, mode=PolicyMode.ENFORCE)

    device_id = "USB\\VID_DEAD&PID_BEEF\\BADDEVICE1"
    decision, events = engine.evaluate_device(
        device_id=device_id,
        serial_number="BADDEVICE1",
    )

    assert decision.allowed is False
    assert decision.action == "block"
    assert decision.blocked_successfully is True
    assert device_id in blocker.blocked_devices

    event_types = [e.event_type for e in events]
    assert "device.blocked" in event_types
    assert "policy.violation" in event_types


def test_policy_engine_audit_only_mode(tmp_path: Path):
    store = WhitelistStore(tmp_path / "test.db")
    blocker = MockDeviceBlocker()
    engine = PolicyEngine(store=store, blocker=blocker, mode=PolicyMode.AUDIT_ONLY)

    device_id = "USB\\VID_1111&PID_2222\\UNKNOWN"
    decision, events = engine.evaluate_device(
        device_id=device_id,
        serial_number="UNKNOWN",
    )

    assert decision.allowed is True
    assert decision.action == "audit_violation"
    assert len(blocker.blocked_devices) == 0
    assert len(events) == 1
    assert events[0].event_type == "policy.violation"
    assert events[0].severity == EventSeverity.WARNING


def test_policy_engine_block_threat(tmp_path: Path):
    store = WhitelistStore(tmp_path / "test.db")
    blocker = MockDeviceBlocker(should_succeed=True)
    engine = PolicyEngine(store=store, blocker=blocker)

    device_id = "USB\\VID_0001&PID_0002\\MALWARE"
    decision, event = engine.block_threat(
        device_id=device_id,
        reason="Malicious autorun.inf with Trojan payload detected",
        threat_type="storage_malware",
    )

    assert decision.allowed is False
    assert decision.blocked_successfully is True
    assert device_id in blocker.blocked_devices
    assert event.event_type == "device.blocked"
    assert event.severity == EventSeverity.CRITICAL


def test_policy_api_endpoints():
    client = TestClient(app)

    # 1. Status check
    status_resp = client.get("/api/v1/policy/status")
    assert status_resp.status_code == 200
    assert "mode" in status_resp.json()

    # 2. Add whitelist entry
    new_entry = {
        "name": "Secure USB Test",
        "serial_number": "TEST_SERIAL_001",
        "vendor_id": "AAAA",
        "product_id": "BBBB",
        "notes": "Testing API",
    }
    create_resp = client.post("/api/v1/policy/whitelist", json=new_entry)
    assert create_resp.status_code == 201
    entry_id = create_resp.json()["id"]

    # 3. List whitelist
    list_resp = client.get("/api/v1/policy/whitelist")
    assert list_resp.status_code == 200
    entries = list_resp.json()
    assert any(e["id"] == entry_id for e in entries)

    # 4. Mode update
    mode_resp = client.post("/api/v1/policy/mode", json={"mode": "audit_only"})
    assert mode_resp.status_code == 200
    assert mode_resp.json()["mode"] == "audit_only"

    # 5. Delete entry
    del_resp = client.delete(f"/api/v1/policy/whitelist/{entry_id}")
    assert del_resp.status_code == 204

    # 6. Delete again -> 404
    del_again = client.delete(f"/api/v1/policy/whitelist/{entry_id}")
    assert del_again.status_code == 404

