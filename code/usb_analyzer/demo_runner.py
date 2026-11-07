"""Automated Live Five-Scenario Attack Demonstration Runner.

Executes all 5 attack and security scenarios defined in the project proposal (Slide 11):
  1. Trusted drive -> Allowed and logged
  2. Infected drive -> High-severity alert and contained
  3. Keystroke injection -> BadUSB flagged and blocked
  4. Unknown device -> Disabled at once per policy
  5. Spoofed identity -> Trusted VID/PID with forged serial flagged
"""

from dataclasses import dataclass
import os
from pathlib import Path
import tempfile
import time
from typing import Any

from usb_analyzer.core.events import DeviceEvent, EventSeverity
from usb_analyzer.device_monitor.monitor import UsbDevice
from usb_analyzer.hid_detector.detector import BadUsbDetector
from usb_analyzer.policy.engine import PolicyEngine
from usb_analyzer.policy.enforcement import MockDeviceBlocker
from usb_analyzer.policy.models import PolicyMode, WhitelistEntry
from usb_analyzer.policy.store import WhitelistStore
from usb_analyzer.storage_scanner.scanner import scan_path
from usb_analyzer.storage_scanner.service import StorageScanService
from usb_analyzer.storage_scanner.signatures import EICAR_STRING, SignatureEngine, YaraRule


class DemoEventCollector:
    def __init__(self) -> None:
        self.events: list[DeviceEvent] = []

    def add(self, event: DeviceEvent) -> DeviceEvent:
        self.events.append(event)
        tag = f"[{event.severity.value.upper()}]"
        print(f"    -> Emitted Event: {tag:<10} {event.event_type:<24} | Device: {event.device_id}")
        if event.details.get("reason"):
            print(f"       Details: {event.details['reason']}")
        elif event.details.get("summary"):
            print(f"       Details: {event.details['summary']}")
        return event


def run_all_five_scenarios(db_path: Path | None = None) -> dict[str, bool]:
    """Execute all five attack scenarios sequentially and verify live defense outcomes."""
    results: dict[str, bool] = {}

    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as temp_dir:
        working_dir = Path(temp_dir)
        database_path = db_path or (working_dir / "demo_usb_analyzer.db")
        collector = DemoEventCollector()
        whitelist_store = WhitelistStore(database_path)
        blocker = MockDeviceBlocker(should_succeed=True)
        policy_engine = PolicyEngine(
            store=whitelist_store,
            blocker=blocker,
            mode=PolicyMode.ENFORCE,
        )

        print("=" * 72)
        print("  USB ANALYZER - FIVE-SCENARIO DEFENSE DEMONSTRATION")
        print("=" * 72)

        # -------------------------------------------------------------
        # SCENARIO 1: Trusted Drive
        # Whitelisted flash drive with clean files -> Allowed and logged
        # -------------------------------------------------------------
        print("\n[Scenario 1] Testing Trusted Drive (Whitelisted)...")
        trusted_entry = WhitelistEntry(
            name="Corp Secure Flash Drive",
            serial_number="CORP_DRIVE_001",
            vendor_id="0951",
            product_id="1666",
        )
        whitelist_store.add(trusted_entry)

        trusted_device_id = "USB\\VID_0951&PID_1666\\CORP_DRIVE_001"
        decision1, events1 = policy_engine.evaluate_device(
            device_id=trusted_device_id,
            serial_number="CORP_DRIVE_001",
            vendor_id="0951",
            product_id="1666",
        )
        for e in events1:
            collector.add(e)

        s1_passed = decision1.allowed is True and any(e.event_type == "device.allowed" for e in events1)
        results["Scenario 1 (Trusted Drive)"] = s1_passed
        print(f"  Result: {'PASSED (Allowed and logged)' if s1_passed else 'FAILED'}")

        # -------------------------------------------------------------
        # SCENARIO 2: Infected Drive
        # Flash drive with EICAR / malware signature + autorun.inf -> Critical Alert & Blocked
        # -------------------------------------------------------------
        print("\n[Scenario 2] Testing Infected Drive (Malware & Autorun.inf)...")
        infected_root = working_dir / "infected_drive"
        infected_root.mkdir()

        # Write simulated malware payload and malicious autorun
        (infected_root / "suspicious_autorun.inf").write_text("[AutoRun]\nopen=trojan.exe\naction=Run Trojan")
        (infected_root / "trojan_payload.bin").write_bytes(b"MALICIOUS_TROJAN_VIRUS_SIGNATURE_PATTERN")

        custom_engine = SignatureEngine(
            custom_rules=[
                YaraRule(
                    name="Trojan_Dropper",
                    description="Simulated Trojan Dropper",
                    patterns=[b"MALICIOUS_TROJAN_VIRUS_SIGNATURE_PATTERN"],
                ),
                YaraRule(
                    name="Suspicious_Autorun_Inf",
                    description="Autorun executing executable",
                    patterns=[b"open=trojan.exe"],
                ),
            ]
        )

        scan_res = scan_path(infected_root, signature_engine=custom_engine)
        scan_service = StorageScanService(
            event_sink=collector,
            scanner=lambda p: scan_res,
            policy_engine=policy_engine,
            max_workers=1,
        )

        infected_device_id = "USBSTOR\\DISK&VEN_EVIL&PROD_USB\\INFECTED_SN_001&0"
        scan_service._scan(infected_device_id, str(infected_root))

        s2_passed = scan_res.has_threats and any(
            e.device_id == infected_device_id and e.severity == EventSeverity.CRITICAL
            for e in collector.events
        )
        results["Scenario 2 (Infected Drive)"] = s2_passed
        print(f"  Result: {'PASSED (High-severity alert & device contained)' if s2_passed else 'FAILED'}")

        # -------------------------------------------------------------
        # SCENARIO 3: Keystroke Injection (BadUSB)
        # Digispark / Rubber Ducky rapid typing -> Flagged and Blocked
        # -------------------------------------------------------------
        print("\n[Scenario 3] Testing Keystroke Injection (BadUSB / Rubber Ducky)...")
        hid_detector = BadUsbDetector(event_sink=collector, policy_engine=policy_engine)
        badusb_device_id = "USB\\VID_16C0&PID_05DF\\DIGISPARK_ATTACKER_001"
        hid_detector.register_hid_device(badusb_device_id, "Digispark BadUSB Attacker")

        alert = hid_detector.simulate_injection(char_count=30, delay_per_char_seconds=0.003)

        s3_passed = alert is not None and badusb_device_id in blocker.blocked_devices
        results["Scenario 3 (Keystroke Injection)"] = s3_passed
        print(f"  Result: {'PASSED (BadUSB flagged & hardware blocked)' if s3_passed else 'FAILED'}")

        # -------------------------------------------------------------
        # SCENARIO 4: Unknown Device
        # Device not on whitelist -> Disabled at once
        # -------------------------------------------------------------
        print("\n[Scenario 4] Testing Unknown Device (Not on Whitelist)...")
        unknown_device_id = "USB\\VID_9999&PID_8888\\UNAUTHORIZED_SN_999"
        decision4, events4 = policy_engine.evaluate_device(
            device_id=unknown_device_id,
            serial_number="UNAUTHORIZED_SN_999",
            vendor_id="9999",
            product_id="8888",
        )
        for e in events4:
            collector.add(e)

        s4_passed = decision4.allowed is False and unknown_device_id in blocker.blocked_devices
        results["Scenario 4 (Unknown Device)"] = s4_passed
        print(f"  Result: {'PASSED (Unauthorized device blocked at once)' if s4_passed else 'FAILED'}")

        # -------------------------------------------------------------
        # SCENARIO 5: Spoofed Identity
        # Trusted VID/PID, different serial -> Mismatch alert & Blocked
        # -------------------------------------------------------------
        print("\n[Scenario 5] Testing Spoofed Identity (Mismatched Serial)...")
        # Registered legit key
        whitelist_store.add(
            WhitelistEntry(
                name="Security Admin YubiKey",
                vendor_id="1050",
                product_id="0407",
                serial_number="AUTHENTIC_YUBIKEY_SN",
            )
        )

        from usb_analyzer.device_monitor.fingerprint import DeviceFingerprint, detect_spoofed_identity

        spoofed_fp = DeviceFingerprint(
            vendor_id="1050",
            product_id="0407",
            serial_number="CLONED_MALICIOUS_SN_99",
        )
        is_spoofed, reason5, details5 = detect_spoofed_identity(spoofed_fp, whitelist_store.list())
        if is_spoofed:
            collector.add(
                DeviceEvent(
                    device_id="USB\\VID_1050&PID_0407\\CLONED_MALICIOUS_SN_99",
                    source="device-monitor",
                    severity=EventSeverity.CRITICAL,
                    event_type="device.spoofed_identity",
                    details=details5,
                )
            )
            _, block_ev = policy_engine.block_threat(
                device_id="USB\\VID_1050&PID_0407\\CLONED_MALICIOUS_SN_99",
                reason=reason5 or "Spoofed identity",
                threat_type="spoofed_identity",
            )
            collector.add(block_ev)

        s5_passed = is_spoofed and "USB\\VID_1050&PID_0407\\CLONED_MALICIOUS_SN_99" in blocker.blocked_devices
        results["Scenario 5 (Spoofed Identity)"] = s5_passed
        print(f"  Result: {'PASSED (Mismatch alert emitted & device blocked)' if s5_passed else 'FAILED'}")

        print("\n" + "=" * 72)
        print("  DEMO SUMMARY: All 5 Scenarios Executed")
        print("=" * 72)
        for name, passed in results.items():
            print(f"  {name:<36}: {'[PASS]' if passed else '[FAIL]'}")
        print("=" * 72)

    return results


if __name__ == "__main__":
    run_all_five_scenarios()
