import logging
import os
import subprocess
from typing import Protocol

logger = logging.getLogger(__name__)


class DeviceBlocker(Protocol):
    def disable_device(self, device_id: str) -> tuple[bool, str]:
        """Disable/block the device. Returns (success, status_message)."""


class WindowsPnpUtilBlocker:
    """Disables a Windows PnP device using pnputil."""

    def __init__(self, dry_run: bool = False) -> None:
        self.dry_run = dry_run

    def disable_device(self, device_id: str) -> tuple[bool, str]:
        if self.dry_run:
            msg = f"[DryRun] Would execute: pnputil /disable-device \"{device_id}\""
            logger.info(msg)
            return True, msg

        cmd = ["pnputil", "/disable-device", device_id]
        logger.info("Executing device block command: %s", " ".join(cmd))
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            output = (result.stdout + " " + result.stderr).strip()
            if result.returncode == 0:
                logger.info("Successfully disabled device %s: %s", device_id, output)
                return True, f"Disabled device: {output}"
            else:
                logger.warning(
                    "pnputil failed with code %d for %s: %s",
                    result.returncode,
                    device_id,
                    output,
                )
                return False, f"pnputil error ({result.returncode}): {output}"
        except Exception as error:
            logger.exception("Failed to disable device %s", device_id)
            return False, f"Execution error: {error}"


class LinuxSysfsBlocker:
    """De-authorizes a USB device on Linux via sysfs."""

    def __init__(self, sysfs_root: str = "/sys/bus/usb/devices", dry_run: bool = False) -> None:
        self.sysfs_root = sysfs_root
        self.dry_run = dry_run

    def disable_device(self, device_id: str) -> tuple[bool, str]:
        if self.dry_run:
            msg = f"[DryRun] Would write 0 to sysfs authorized for {device_id}"
            logger.info(msg)
            return True, msg

        # Normalize device ID to sysfs path component if needed
        clean_id = os.path.basename(device_id.replace("\\", "/"))
        authorized_path = os.path.join(self.sysfs_root, clean_id, "authorized")
        try:
            if not os.path.exists(authorized_path):
                # Search matching directory
                found = None
                if os.path.exists(self.sysfs_root):
                    for entry in os.listdir(self.sysfs_root):
                        if clean_id in entry or entry in clean_id:
                            candidate = os.path.join(self.sysfs_root, entry, "authorized")
                            if os.path.exists(candidate):
                                found = candidate
                                break
                if not found:
                    return False, f"Sysfs path not found for {device_id}"
                authorized_path = found

            with open(authorized_path, "w") as f:
                f.write("0\n")
            logger.info("De-authorized Linux USB device at %s", authorized_path)
            return True, f"Written 0 to {authorized_path}"
        except Exception as error:
            logger.exception("Failed to de-authorize device %s via sysfs", device_id)
            return False, f"Sysfs write error: {error}"


class MockDeviceBlocker:
    """Blocker for testing and simulated attack scenarios."""

    def __init__(self, should_succeed: bool = True) -> None:
        self.should_succeed = should_succeed
        self.blocked_devices: list[str] = []

    def disable_device(self, device_id: str) -> tuple[bool, str]:
        self.blocked_devices.append(device_id)
        if self.should_succeed:
            return True, f"Mock-blocked device {device_id}"
        return False, f"Mock failure to block {device_id}"


def get_platform_blocker(dry_run: bool = False) -> DeviceBlocker:
    """Return appropriate blocker for current OS."""
    if os.name == "nt":
        return WindowsPnpUtilBlocker(dry_run=dry_run)
    return LinuxSysfsBlocker(dry_run=dry_run)

