import argparse
import logging
import os
from pathlib import Path
from threading import Event
from typing import Any

from usb_analyzer.core.api_client import ApiEventClient
from usb_analyzer.core.config import get_settings
from usb_analyzer.device_monitor.monitor import DeviceProvider, UsbDevice, run_monitor
from usb_analyzer.hid_detector.detector import BadUsbDetector
from usb_analyzer.policy.engine import PolicyEngine
from usb_analyzer.policy.enforcement import LinuxSysfsBlocker
from usb_analyzer.policy.store import WhitelistStore
from usb_analyzer.storage_scanner.service import StorageScanService

logger = logging.getLogger(__name__)

LINUX_USB_SYSFS_ROOT = "/sys/bus/usb/devices"


def _read_sysfs_attr(device_path: Path, attr_name: str) -> str | None:
    target = device_path / attr_name
    try:
        if target.is_file():
            return target.read_text(encoding="utf-8", errors="replace").strip()
    except OSError:
        pass
    return None


def enumerate_sysfs_devices(sysfs_root: str | Path = LINUX_USB_SYSFS_ROOT) -> dict[str, UsbDevice]:
    """Enumerate connected USB devices by inspecting sysfs (/sys/bus/usb/devices)."""
    devices: dict[str, UsbDevice] = {}
    root = Path(sysfs_root)
    if not root.is_dir():
        return devices

    for entry in root.iterdir():
        # Valid USB device entries are formatted like 1-1, 1-1.2, 2-1, usb1, usb2
        # Interfaces have a colon like 1-1:1.0 (we skip interfaces to list primary devices)
        if ":" in entry.name:
            continue

        vid = _read_sysfs_attr(entry, "idVendor")
        pid = _read_sysfs_attr(entry, "idProduct")
        if not vid or not pid:
            continue

        serial = _read_sysfs_attr(entry, "serial")
        manufacturer = _read_sysfs_attr(entry, "manufacturer")
        product = _read_sysfs_attr(entry, "product")
        dev_class = _read_sysfs_attr(entry, "bDeviceClass")
        authorized = _read_sysfs_attr(entry, "authorized")

        device_id = f"USB/{entry.name}/VID_{vid.upper()}&PID_{pid.upper()}"
        if serial:
            device_id += f"/{serial}"

        # Resolve mounted volumes if available
        volume_paths = _find_mount_points_for_sysfs(entry)

        status = "Authorized" if authorized != "0" else "Blocked"
        pnp_class = "Mass Storage" if dev_class == "08" else ("Human Interface Device (HID)" if dev_class == "03" else dev_class)

        device = UsbDevice(
            device_id=device_id,
            name=product or f"USB Device {vid}:{pid}",
            manufacturer=manufacturer,
            pnp_class=pnp_class,
            service="usb",
            hardware_ids=(f"USB\\VID_{vid.upper()}&PID_{pid.upper()}",),
            status=status,
            volume_paths=tuple(sorted(volume_paths)),
            serial_number=serial,
        )
        devices[device_id] = device

    return devices


def _find_mount_points_for_sysfs(device_path: Path) -> set[str]:
    """Find mount points associated with this USB device from /proc/mounts."""
    mount_points: set[str] = set()
    proc_mounts = Path("/proc/mounts")
    if not proc_mounts.is_file():
        return mount_points

    # Search for block device symlinks in device hierarchy
    block_names: set[str] = set()
    for root_dir, dirs, _ in os.walk(device_path):
        if "block" in dirs:
            block_dir = Path(root_dir) / "block"
            try:
                for b in block_dir.iterdir():
                    block_names.add(b.name)
            except OSError:
                pass

    if not block_names:
        return mount_points

    try:
        for line in proc_mounts.read_text(encoding="utf-8", errors="replace").splitlines():
            parts = line.split()
            if len(parts) >= 2:
                dev_spec, mount_dir = parts[0], parts[1]
                for b_name in block_names:
                    if b_name in dev_spec:
                        mount_points.add(mount_dir)
    except OSError:
        pass

    return mount_points


class LinuxUdevProvider(DeviceProvider):
    """Enumerate USB devices on Linux via pyudev or sysfs."""

    def __init__(self, sysfs_root: str | Path = LINUX_USB_SYSFS_ROOT) -> None:
        self.sysfs_root = Path(sysfs_root)
        self._udev_context: Any = None
        try:
            import pyudev
            self._udev_context = pyudev.Context()
        except ImportError:
            pass

    def list_devices(self) -> dict[str, UsbDevice]:
        if self._udev_context is not None:
            try:
                return self._list_devices_pyudev()
            except Exception as exc:
                logger.debug("pyudev enumeration failed, falling back to sysfs: %s", exc)

        return enumerate_sysfs_devices(self.sysfs_root)

    def _list_devices_pyudev(self) -> dict[str, UsbDevice]:
        import pyudev
        devices: dict[str, UsbDevice] = {}
        for dev in self._udev_context.list_devices(subsystem="usb", DEVTYPE="usb_device"):
            vid = dev.get("ID_VENDOR_ID") or dev.attributes.get("idVendor")
            pid = dev.get("ID_MODEL_ID") or dev.attributes.get("idProduct")
            if not vid or not pid:
                continue

            vid_str = vid.decode() if isinstance(vid, bytes) else str(vid)
            pid_str = pid.decode() if isinstance(pid, bytes) else str(pid)

            serial = dev.get("ID_SERIAL_SHORT") or dev.attributes.get("serial")
            serial_str = serial.decode() if isinstance(serial, bytes) else (str(serial) if serial else None)

            manufacturer = dev.get("ID_VENDOR")
            product = dev.get("ID_MODEL")

            device_id = f"USB/{dev.sys_name}/VID_{vid_str.upper()}&PID_{pid_str.upper()}"
            if serial_str:
                device_id += f"/{serial_str}"

            # Check mount points
            volume_paths = _find_mount_points_for_sysfs(Path(dev.sys_path))

            device = UsbDevice(
                device_id=device_id,
                name=str(product) if product else f"USB Device {vid_str}:{pid_str}",
                manufacturer=str(manufacturer) if manufacturer else None,
                pnp_class="Mass Storage" if dev.get("DEVTYPE") == "usb_device" and volume_paths else "USB Device",
                service="usb",
                hardware_ids=(f"USB\\VID_{vid_str.upper()}&PID_{pid_str.upper()}",),
                status="Authorized",
                volume_paths=tuple(sorted(volume_paths)),
                serial_number=serial_str,
            )
            devices[device_id] = device

        return devices


def main() -> None:
    parser = argparse.ArgumentParser(description="Monitor Linux USB device changes")
    parser.add_argument(
        "--interval",
        type=float,
        default=1.0,
        help="seconds between sysfs / udev inventory checks (default: 1.0)",
    )
    args = parser.parse_args()
    settings = get_settings()
    logging.basicConfig(
        level=settings.log_level.upper(),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    stop_event = Event()
    provider = LinuxUdevProvider()
    policy_store = WhitelistStore(settings.database_path)
    policy_engine = PolicyEngine(
        store=policy_store,
        blocker=LinuxSysfsBlocker(),
        mode=settings.policy_mode,
    )
    logger.info(
        "Starting USB Analyzer Linux device monitor; API base URL: %s, Policy mode: %s",
        settings.api_base_url,
        settings.policy_mode,
    )
    try:
        with ApiEventClient(
            base_url=settings.api_base_url,
            api_prefix=settings.api_prefix,
            timeout_seconds=settings.api_timeout_seconds,
        ) as event_sink:
            hid_detector = BadUsbDetector(event_sink=event_sink, policy_engine=policy_engine)
            with StorageScanService(event_sink, policy_engine=policy_engine) as scan_service:
                run_monitor(
                    provider,
                    event_sink,
                    stop_event,
                    args.interval,
                    storage_scan_scheduler=scan_service,
                    policy_engine=policy_engine,
                    hid_detector=hid_detector,
                )
    except KeyboardInterrupt:
        logger.info("Stopping USB Analyzer Linux device monitor")
        stop_event.set()


if __name__ == "__main__":
    main()

