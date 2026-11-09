import csv
import io
import json
from pathlib import Path
from typing import Any
from uuid import UUID

from fastapi import FastAPI, HTTPException, Query, Response
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from usb_analyzer.core.config import get_settings
from usb_analyzer.core.database import EventStore
from usb_analyzer.core.events import DeviceEvent, EventSeverity
from usb_analyzer.device_monitor.fingerprint import DeviceFingerprint, detect_spoofed_identity
from usb_analyzer.hid_detector.detector import BadUsbDetector
from usb_analyzer.policy.engine import PolicyEngine
from usb_analyzer.policy.enforcement import get_platform_blocker
from usb_analyzer.policy.models import PolicyMode, WhitelistEntry
from usb_analyzer.policy.store import WhitelistStore
from usb_analyzer.reports.incident_pdf import generate_incident_pdf

settings = get_settings()
event_store = EventStore(settings.database_path)
whitelist_store = WhitelistStore(settings.database_path)
current_policy_mode = PolicyMode(settings.policy_mode)
policy_engine = PolicyEngine(
    store=whitelist_store,
    blocker=get_platform_blocker(dry_run=True),
    mode=current_policy_mode,
)
hid_detector = BadUsbDetector(event_sink=event_store, policy_engine=policy_engine)

app = FastAPI(title=settings.app_name, version="0.1.0")


@app.middleware("http")
async def add_cache_control_headers(request, call_next):
    response = await call_next(request)
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response


static_directory = Path(__file__).parent / "static"
app.mount("/static", StaticFiles(directory=static_directory), name="static")


class PolicyModeUpdateRequest(BaseModel):
    mode: PolicyMode


@app.get("/", include_in_schema=False)
def dashboard() -> FileResponse:
    return FileResponse(static_directory / "index.html")


@app.get(f"{settings.api_prefix}/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get(f"{settings.api_prefix}/events", response_model=list[DeviceEvent])
def list_events(
    limit: int = Query(default=100, ge=1, le=1000),
) -> list[DeviceEvent]:
    return event_store.list(limit=limit)


@app.post(
    f"{settings.api_prefix}/events",
    response_model=DeviceEvent,
    status_code=201,
)
def create_event(event: DeviceEvent) -> DeviceEvent:
    return event_store.add(event)


@app.delete(f"{settings.api_prefix}/events", status_code=200)
def clear_all_events() -> dict[str, int]:
    count = event_store.clear()
    return {"deleted": count}


@app.get(
    f"{settings.api_prefix}/policy/whitelist",
    response_model=list[WhitelistEntry],
)
def list_whitelist() -> list[WhitelistEntry]:
    return whitelist_store.list()


@app.post(
    f"{settings.api_prefix}/policy/whitelist",
    response_model=WhitelistEntry,
    status_code=201,
)
def add_whitelist_entry(entry: WhitelistEntry) -> WhitelistEntry:
    return whitelist_store.add(entry)


@app.delete(
    f"{settings.api_prefix}/policy/whitelist/{{entry_id}}",
    status_code=204,
)
def delete_whitelist_entry(entry_id: UUID) -> None:
    if not whitelist_store.remove(entry_id):
        raise HTTPException(status_code=404, detail="Whitelist entry not found")


@app.get(f"{settings.api_prefix}/policy/status")
def get_policy_status() -> dict[str, object]:
    global current_policy_mode
    entries = whitelist_store.list()
    return {
        "mode": current_policy_mode.value,
        "whitelist_count": len(entries),
    }


@app.get(f"{settings.api_prefix}/reports/incident/pdf")
def export_incident_report_pdf() -> Response:
    events = event_store.list(limit=200)
    whitelist = whitelist_store.list()
    pdf_bytes = generate_incident_pdf(
        events=events,
        whitelist=whitelist,
        policy_mode=current_policy_mode.value,
    )
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": 'attachment; filename="usb_analyzer_incident_report.pdf"'},
    )


@app.get(f"{settings.api_prefix}/reports/events.csv")
def export_events_csv() -> Response:
    events = event_store.list(limit=500)
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "Event ID",
        "Timestamp (UTC)",
        "Device ID",
        "Subsystem Source",
        "Severity",
        "Event Type",
        "Reason / Risk",
        "Action Taken",
        "Details JSON",
    ])
    for ev in events:
        details = ev.details or {}
        reason = details.get("reason") or details.get("summary") or details.get("threat") or ""
        action = details.get("action") or ("blocked" if ev.event_type == "device.blocked" else "logged")
        writer.writerow([
            str(ev.id),
            ev.time.isoformat(),
            ev.device_id,
            ev.source,
            ev.severity.value,
            ev.event_type,
            reason,
            action,
            json.dumps(details),
        ])
    return Response(
        content=output.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": 'attachment; filename="usb_forensic_audit_events.csv"'},
    )


@app.get(f"{settings.api_prefix}/reports/events.json")
def export_events_json() -> Response:
    events = event_store.list(limit=500)
    data = [ev.model_dump(mode="json") for ev in events]
    return Response(
        content=json.dumps(data, indent=2),
        media_type="application/json",
        headers={"Content-Disposition": 'attachment; filename="usb_forensic_audit_events.json"'},
    )


@app.post(f"{settings.api_prefix}/policy/mode")
def update_policy_mode(req: PolicyModeUpdateRequest) -> dict[str, str]:
    global current_policy_mode
    current_policy_mode = req.mode
    policy_engine.mode = current_policy_mode
    return {"mode": current_policy_mode.value}


class BadUsbSimulationRequest(BaseModel):
    device_id: str = "USB\\VID_1B4F&PID_9206\\BADUSB_ATTACKER"
    device_name: str = "SparkFun Pro Micro (BadUSB Simulation)"
    char_count: int = 30
    delay_ms: float = 5.0


@app.post(f"{settings.api_prefix}/simulate/badusb")
def simulate_badusb(req: BadUsbSimulationRequest) -> dict[str, Any]:
    hid_detector.register_hid_device(req.device_id, req.device_name)
    alert = hid_detector.simulate_injection(
        char_count=req.char_count,
        delay_per_char_seconds=req.delay_ms / 1000.0,
    )
    return {
        "status": "simulated",
        "detected": alert is not None,
        "summary": alert.summary if alert else "Typing speed did not trigger threshold",
    }


class ScenarioSimulationRequest(BaseModel):
    scenario: str  # "safe_usb", "badusb", "malware_drive", "unauthorized_device", "spoofed_identity"


@app.post(f"{settings.api_prefix}/simulate/scenario")
def simulate_scenario(req: ScenarioSimulationRequest) -> dict[str, Any]:
    scenario = req.scenario.strip().lower()

    if scenario == "safe_usb":
        # 1. Trusted Drive -> Allowed & Logged
        serial = "CORP_DRIVE_001"
        vid = "0951"
        pid = "1666"
        device_id = f"USB\\VID_{vid}&PID_{pid}\\{serial}"

        if not whitelist_store.find_match(serial_number=serial):
            whitelist_store.add(
                WhitelistEntry(
                    name="Corporate Secure Flash Drive",
                    serial_number=serial,
                    vendor_id=vid,
                    product_id=pid,
                    notes="Pre-approved corporate USB storage",
                )
            )

        event_store.add(
            DeviceEvent(
                device_id=device_id,
                source="device-monitor",
                severity=EventSeverity.INFO,
                event_type="device.connected",
                details={
                    "name": "Kingston DataTraveler (Corporate Whitelisted)",
                    "vendor_id": vid,
                    "product_id": pid,
                    "serial_number": serial,
                    "device_type": "Mass Storage (Storage)",
                },
            )
        )

        decision, events = policy_engine.evaluate_device(
            device_id=device_id,
            serial_number=serial,
            vendor_id=vid,
            product_id=pid,
        )
        for ev in events:
            event_store.add(ev)

        event_store.add(
            DeviceEvent(
                device_id=device_id,
                source="storage-scanner",
                severity=EventSeverity.INFO,
                event_type="scan.completed",
                details={
                    "summary": "Storage integrity verified clean. 0 threats detected across 16 files.",
                    "clean_files": 16,
                    "threat_count": 0,
                    "status": "clean",
                },
            )
        )
        return {
            "status": "simulated",
            "scenario": "safe_usb",
            "outcome": "allowed",
            "summary": "Safe USB Drive connected and verified against corporate whitelist. Integrity clean — full access granted.",
        }

    elif scenario == "badusb":
        # 2. BadUSB Keystroke Injection (Rubber Ducky)
        device_id = "USB\\VID_16C0&PID_05DF\\DIGISPARK_ATTACKER_001"
        event_store.add(
            DeviceEvent(
                device_id=device_id,
                source="device-monitor",
                severity=EventSeverity.INFO,
                event_type="device.connected",
                details={
                    "name": "Digispark USB HID Keyboard (Disguised BadUSB)",
                    "vendor_id": "16C0",
                    "product_id": "05DF",
                    "device_type": "Human Interface Device (HID)",
                },
            )
        )
        hid_detector.register_hid_device(device_id, "Digispark BadUSB Attacker")
        alert = hid_detector.simulate_injection(char_count=35, delay_per_char_seconds=0.003)
        return {
            "status": "simulated",
            "scenario": "badusb",
            "outcome": "blocked" if current_policy_mode == PolicyMode.ENFORCE else "audit_warning",
            "summary": alert.summary if alert else "BadUSB keystroke injection simulated.",
        }

    elif scenario == "malware_drive":
        # 3. Infected Storage Drive (Trojan Dropper & autorun.inf) -> Blocked
        device_id = "USBSTOR\\DISK&VEN_EVIL&PROD_USB\\INFECTED_SN_001&0"
        event_store.add(
            DeviceEvent(
                device_id=device_id,
                source="device-monitor",
                severity=EventSeverity.INFO,
                event_type="device.connected",
                details={
                    "name": "SanDisk Cruzer (Malware Infected Media)",
                    "vendor_id": "0781",
                    "product_id": "5567",
                    "device_type": "Mass Storage (Storage)",
                },
            )
        )
        event_store.add(
            DeviceEvent(
                device_id=device_id,
                source="storage-scanner",
                severity=EventSeverity.INFO,
                event_type="scan.started",
                details={
                    "device_id": device_id,
                    "mount_point": "E:\\",
                    "summary": "Storage scan initiated for newly attached volume E:\\",
                },
            )
        )
        event_store.add(
            DeviceEvent(
                device_id=device_id,
                source="storage-scanner",
                severity=EventSeverity.CRITICAL,
                event_type="scan.threat_detected",
                details={
                    "device_id": device_id,
                    "mount_point": "E:\\",
                    "threat_type": "trojan_autorun",
                    "flagged_files": [
                        "E:\\autorun.inf (Suspicious Autorun.inf)",
                        "E:\\svchost_trojan.exe (Trojan_Dropper.exe)",
                    ],
                    "summary": "High-severity malware signature and malicious autorun detected on storage volume.",
                },
            )
        )
        _, block_ev = policy_engine.block_threat(
            device_id=device_id,
            reason="Malware infection: Trojan dropper & unauthorized autorun script present on storage volume",
            threat_type="malware_infection",
            details={"action": "quarantine_and_block", "volume": "E:\\"},
        )
        event_store.add(block_ev)
        return {
            "status": "simulated",
            "scenario": "malware_drive",
            "outcome": "blocked",
            "summary": "Infected drive detected! Trojan dropper and autorun.inf found. Hardware blocked & volume quarantined.",
        }

    elif scenario == "unauthorized_device":
        # 4. Unknown / Rogue USB Device (Suspicious Warning)
        device_id = "USB\\VID_9999&PID_8888\\UNAUTHORIZED_SN_999"
        event_store.add(
            DeviceEvent(
                device_id=device_id,
                source="device-monitor",
                severity=EventSeverity.INFO,
                event_type="device.connected",
                details={
                    "name": "Rogue USB Peripheral (Unknown Hardware)",
                    "vendor_id": "9999",
                    "product_id": "8888",
                    "serial_number": "UNAUTHORIZED_SN_999",
                    "device_type": "Unrecognized USB Peripheral",
                },
            )
        )
        event_store.add(
            DeviceEvent(
                device_id=device_id,
                source="policy-engine",
                severity=EventSeverity.WARNING,
                event_type="device.suspicious",
                details={
                    "action": "warn_user",
                    "reason": "Suspicious hardware connected: Device ID is not on the trusted whitelist.",
                    "violation": "unregistered_hardware_detected",
                    "summary": "Suspicious USB peripheral connected (unregistered hardware). User notified with warning.",
                },
            )
        )
        return {
            "status": "simulated",
            "scenario": "unauthorized_device",
            "outcome": "warning",
            "summary": "Suspicious device detected: Unregistered USB hardware flagged. User notified with a warning to verify the peripheral.",
        }

    elif scenario == "spoofed_identity":
        # 5. Spoofed Identity Attack (VID/PID Clone) -> Blocked
        if not whitelist_store.find_match(vendor_id="1050", product_id="0407"):
            whitelist_store.add(
                WhitelistEntry(
                    name="Security Admin YubiKey 5 NFC",
                    vendor_id="1050",
                    product_id="0407",
                    serial_number="AUTHENTIC_YUBI_7701",
                    notes="Registered IT Security Hardware Token",
                )
            )

        cloned_serial = "CLONED_MALICIOUS_SN_99"
        device_id = f"USB\\VID_1050&PID_0407\\{cloned_serial}"

        event_store.add(
            DeviceEvent(
                device_id=device_id,
                source="device-monitor",
                severity=EventSeverity.INFO,
                event_type="device.connected",
                details={
                    "name": "YubiKey 5 NFC (Cloned Attacker Hardware)",
                    "vendor_id": "1050",
                    "product_id": "0407",
                    "serial_number": cloned_serial,
                    "device_type": "Smart Card / Security Key",
                },
            )
        )

        spoofed_fp = DeviceFingerprint(
            vendor_id="1050",
            product_id="0407",
            serial_number=cloned_serial,
            friendly_name="YubiKey 5 NFC (Cloned Attacker Hardware)",
        )
        is_spoofed, reason, details = detect_spoofed_identity(spoofed_fp, whitelist_store.list())

        if is_spoofed:
            event_store.add(
                DeviceEvent(
                    device_id=device_id,
                    source="device-monitor",
                    severity=EventSeverity.CRITICAL,
                    event_type="device.spoofed_identity",
                    details=details,
                )
            )
            _, block_ev = policy_engine.block_threat(
                device_id=device_id,
                reason=reason or "Spoofed hardware identity",
                threat_type="spoofed_identity",
            )
            event_store.add(block_ev)
            summary = f"Identity Spoofing detected! Cloned VID 1050:PID 0407 with unauthorized serial '{cloned_serial}'. Hardware completely blocked."
        else:
            summary = "Spoof check did not trigger."

        return {
            "status": "simulated",
            "scenario": "spoofed_identity",
            "outcome": "blocked",
            "summary": summary,
        }

    else:
        raise HTTPException(
            status_code=400,
            detail=f"Unknown simulation scenario: {scenario}. Available: safe_usb, badusb, malware_drive, unauthorized_device, spoofed_identity",
        )


