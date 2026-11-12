import xml.etree.ElementTree as ET

from usb_analyzer.core.windows_notifier import (
    build_notification_urls,
    build_toast_xml,
)


def test_build_notification_urls_without_device_id() -> None:
    urls = build_notification_urls(device_id=None, severity="info")
    assert urls == {
        "inspect": "http://127.0.0.1:8000/",
        "block": "http://127.0.0.1:8000/",
        "allow": "http://127.0.0.1:8000/",
    }


def test_build_notification_urls_for_warning_device() -> None:
    dev_id = r"USB\VID_1234&PID_5678\SERIAL_01"
    urls = build_notification_urls(device_id=dev_id, severity="warning")
    assert "inspect_device=USB%5CVID_1234%26PID_5678%5CSERIAL_01" in urls["inspect"]
    assert "&triage=1" in urls["inspect"]
    assert "toast_action=block&device_id=USB%5CVID_1234%26PID_5678%5CSERIAL_01" in urls["block"]
    assert "toast_action=allow&device_id=USB%5CVID_1234%26PID_5678%5CSERIAL_01" in urls["allow"]


def test_build_toast_xml_warning_includes_block_and_allow_actions() -> None:
    xml_str = build_toast_xml(
        title="Suspicious USB Device Detected",
        message="Unrecognized & untrusted device attached",
        severity="warning",
        device_id=r"USB\VID_1234&PID_5678\SN&01",
    )
    root = ET.fromstring(xml_str)
    assert root.tag == "toast"
    assert root.attrib["activationType"] == "protocol"
    assert root.attrib["scenario"] == "reminder"
    assert "inspect_device=" in root.attrib["launch"]
    assert "triage=1" in root.attrib["launch"]

    actions = root.findall("./actions/action")
    assert [a.attrib["content"] for a in actions] == ["Block Device", "Let It Run"]
    assert "toast_action=block" in actions[0].attrib["arguments"]
    assert "toast_action=allow" in actions[1].attrib["arguments"]
    assert all(a.attrib["activationType"] == "protocol" for a in actions)


def test_build_toast_xml_non_interactive_warning_omits_block_allow_buttons() -> None:
    xml_str = build_toast_xml(
        title="USB Protection Paused",
        message="Background service stopped.",
        severity="warning",
        device_id=None,
        interactive=False,
    )
    root = ET.fromstring(xml_str)
    assert root.attrib.get("scenario") is None
    actions = root.findall("./actions/action")
    assert [a.attrib["content"] for a in actions] == ["Open Dashboard"]


def test_build_toast_xml_critical_shows_view_details() -> None:
    xml_str = build_toast_xml(
        title="Threat Blocked",
        message="Malware drive blocked",
        severity="critical",
        device_id=r"USBSTOR\DISK&VEN_TEST\001",
    )
    root = ET.fromstring(xml_str)
    assert root.attrib["duration"] == "long"
    assert "inspect_device=" in root.attrib["launch"]
    assert "triage=1" not in root.attrib["launch"]
    actions = root.findall("./actions/action")
    assert [a.attrib["content"] for a in actions] == ["View Details"]
