from fastapi.testclient import TestClient

from usb_analyzer.api.main import app
from usb_analyzer.core.events import DeviceEvent, EventSeverity
from usb_analyzer.policy.models import WhitelistEntry
from usb_analyzer.reports.incident_pdf import SimplePdfWriter, generate_incident_pdf


def test_simple_pdf_writer():
    writer = SimplePdfWriter()
    writer.start_page()
    writer.add_text("USB Analyzer Test Page", 50, 700, font="F2", size=14)
    writer.add_line(50, 690, 550, 690)
    writer.add_rect(50, 600, 200, 50)
    pdf_bytes = writer.build()

    assert pdf_bytes.startswith(b"%PDF-1.4")
    assert b"%%EOF" in pdf_bytes


def test_generate_incident_pdf():
    events = [
        DeviceEvent(
            device_id="USB\\VID_0951&PID_1666\\SN12345678",
            source="device-monitor",
            event_type="device.connected",
            severity=EventSeverity.INFO,
            details={"name": "Kingston Drive"},
        ),
        DeviceEvent(
            device_id="USB\\VID_16C0&PID_05DF\\BADUSB_001",
            source="hid-detector",
            event_type="hid.injection_detected",
            severity=EventSeverity.CRITICAL,
            details={"threat": "BadUSB keystroke injection", "typing_speed_cps": 85.0},
        ),
        DeviceEvent(
            device_id="USB\\VID_16C0&PID_05DF\\BADUSB_001",
            source="policy-engine",
            event_type="device.blocked",
            severity=EventSeverity.CRITICAL,
            details={"action": "block", "reason": "BadUSB keystroke injection detected"},
        ),
        DeviceEvent(
            device_id="USBSTOR\\DISK&VEN_DEMO\\SN12345678",
            source="storage-scanner",
            event_type="scan.completed",
            severity=EventSeverity.WARNING,
            details={
                "volume_path": "F:\\",
                "file_analyses": [
                    {
                        "path": "payload.bin",
                        "file_type": "Binary Data",
                        "entropy": 7.98,
                        "risk_score": 45,
                        "sha256": "deadbeef" * 8,
                        "flags": ["high_entropy_packed"],
                    }
                ],
            },
        ),
    ]

    whitelist = [
        WhitelistEntry(
            name="Approved Admin Drive",
            serial_number="SN12345678",
            vendor_id="0951",
            product_id="1666",
        )
    ]

    pdf = generate_incident_pdf(events, whitelist, policy_mode="enforce")
    assert isinstance(pdf, bytes)
    assert pdf.startswith(b"%PDF-1.4")
    assert b"%%EOF" in pdf
    assert len(pdf) > 1500
    assert b"Activity & Health" in pdf
    assert b"File Analysis" in pdf
    assert b"deadbeef" in pdf
    assert b"Page 1 of " in pdf


def test_generate_incident_pdf_multipage_pagination():
    many_files = [
        {
            "path": f"folder/nested_artifact_{i:02d}_payload.bin",
            "file_type": "PE32+ Executable" if i % 2 == 0 else "Binary Data",
            "entropy": 7.92 if i < 6 else 4.15,
            "risk_score": 85 if i < 4 else (35 if i < 10 else 0),
            "sha256": f"{i:02x}" * 32,
            "md5": f"{i:02x}" * 16,
            "size_bytes": 4096 + i * 128,
            "flags": ["yara:Suspicious_Dropper", "high_entropy_packed"] if i < 6 else [],
            "metadata": {"extension": ".bin", "extension_mismatch": i == 0},
        }
        for i in range(18)
    ]
    events = [
        DeviceEvent(
            device_id="USBSTOR\\DISK&VEN_GENERIC&PROD_FLASH_DISK\\27DB4F8B&0",
            source="storage-scanner",
            event_type="scan.completed",
            severity=EventSeverity.CRITICAL,
            details={
                "name": "Generic Flash Disk",
                "volume_path": "F:\\",
                "files_scanned": len(many_files),
                "flagged_count": 10,
                "max_risk_score": 85,
                "file_analyses": many_files,
            },
        )
    ]
    pdf = generate_incident_pdf(events, whitelist=[], policy_mode="audit_only")
    assert pdf.startswith(b"%PDF-1.4")
    assert b"Page 1 of 2" in pdf or b"Page 1 of 3" in pdf
    assert b"Page 2 of " in pdf
    assert b"POLICY: AUDIT ONLY" in pdf


def test_api_export_incident_report_pdf():
    client = TestClient(app)
    response = client.get("/api/v1/reports/incident/pdf")
    assert response.status_code == 200
    assert response.headers["content-type"] == "application/pdf"
    assert "usb_analyzer_incident_report.pdf" in response.headers["content-disposition"]
    assert response.content.startswith(b"%PDF-1.4")

