from pathlib import Path
from unittest.mock import MagicMock, patch

from usb_analyzer.device_monitor.linux import (
    LinuxUdevProvider,
    enumerate_sysfs_devices,
)
from usb_analyzer.policy.enforcement import LinuxSysfsBlocker


def test_linux_sysfs_enumeration(tmp_path: Path):
    sysfs_root = tmp_path / "sys_bus_usb_devices"
    sysfs_root.mkdir()

    # Create mock USB flash drive device folder: 1-1
    dev1 = sysfs_root / "1-1"
    dev1.mkdir()
    (dev1 / "idVendor").write_text("0951\n")
    (dev1 / "idProduct").write_text("1666\n")
    (dev1 / "serial").write_text("SN09511666TEST\n")
    (dev1 / "manufacturer").write_text("Kingston\n")
    (dev1 / "product").write_text("DataTraveler 3.0\n")
    (dev1 / "bDeviceClass").write_text("08\n")
    (dev1 / "authorized").write_text("1\n")

    # Create mock HID Keyboard: 1-2
    dev2 = sysfs_root / "1-2"
    dev2.mkdir()
    (dev2 / "idVendor").write_text("046D\n")
    (dev2 / "idProduct").write_text("C31C\n")
    (dev2 / "serial").write_text("LOGIKBD_99\n")
    (dev2 / "manufacturer").write_text("Logitech\n")
    (dev2 / "product").write_text("USB Keyboard\n")
    (dev2 / "bDeviceClass").write_text("03\n")
    (dev2 / "authorized").write_text("1\n")

    # Folder missing idVendor/idProduct (should be skipped)
    (sysfs_root / "usb_controller").mkdir()

    devices = enumerate_sysfs_devices(sysfs_root)
    assert len(devices) == 2

    # Check Kingston drive
    kingston_id = "USB/1-1/VID_0951&PID_1666/SN09511666TEST"
    assert kingston_id in devices
    k_dev = devices[kingston_id]
    assert k_dev.manufacturer == "Kingston"
    assert k_dev.name == "DataTraveler 3.0"
    assert k_dev.pnp_class == "Mass Storage"
    assert k_dev.serial_number == "SN09511666TEST"
    assert k_dev.status == "Authorized"

    # Check Logitech keyboard
    logi_id = "USB/1-2/VID_046D&PID_C31C/LOGIKBD_99"
    assert logi_id in devices
    l_dev = devices[logi_id]
    assert l_dev.name == "USB Keyboard"
    assert l_dev.pnp_class == "Human Interface Device (HID)"

    # Test LinuxUdevProvider with sysfs fallback
    provider = LinuxUdevProvider(sysfs_root=sysfs_root)
    provider._udev_context = None
    res = provider.list_devices()
    assert len(res) == 2


def test_linux_sysfs_blocker(tmp_path: Path):
    sysfs_root = tmp_path / "sysfs_blocker_test"
    sysfs_root.mkdir()

    dev_folder = sysfs_root / "1-1"
    dev_folder.mkdir()
    authorized_file = dev_folder / "authorized"
    authorized_file.write_text("1\n")

    blocker = LinuxSysfsBlocker(sysfs_root=str(sysfs_root), dry_run=False)

    success, msg = blocker.disable_device("1-1")
    assert success is True
    assert "Written 0" in msg
    assert authorized_file.read_text().strip() == "0"
