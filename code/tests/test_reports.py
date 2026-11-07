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
    assert len(pdf) > 500


def test_api_export_incident_report_pdf():
    client = TestClient(app)
    response = client.get("/api/v1/reports/incident/pdf")
    assert response.status_code == 200
    assert response.headers["content-type"] == "application/pdf"
    assert "usb_analyzer_incident_report.pdf" in response.headers["content-disposition"]
    assert response.content.startswith(b"%PDF-1.4")

