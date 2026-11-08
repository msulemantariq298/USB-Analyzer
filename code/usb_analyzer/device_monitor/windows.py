import argparse
import logging
import os
import re
from threading import Event
from typing import Any

from usb_analyzer.core.api_client import ApiEventClient
from usb_analyzer.core.config import get_settings
from usb_analyzer.device_monitor.fingerprint import (
    extract_serial_number,
    infer_device_category,
    infer_friendly_name,
)
from usb_analyzer.device_monitor.monitor import DeviceProvider, UsbDevice, run_monitor
from usb_analyzer.hid_detector.detector import BadUsbDetector
from usb_analyzer.policy.engine import PolicyEngine
from usb_analyzer.policy.store import WhitelistStore
from usb_analyzer.storage_scanner.service import StorageScanService

logger = logging.getLogger(__name__)


class WindowsWmiProvider(DeviceProvider):
    """Enumerate currently present USB PnP entities through Windows WMI."""

    def __init__(self) -> None:
        if os.name != "nt":
            raise OSError("The Windows WMI device monitor can only run on Windows")

        try:
            import wmi
        except ImportError as error:
            raise RuntimeError(
                "The WMI dependency is missing; install the project dependencies "
                "with `python -m pip install -e \".[dev]\"`"
            ) from error

        self._connection = wmi.WMI()

    def list_devices(self) -> dict[str, UsbDevice]:
        devices: dict[str, UsbDevice] = {}
        entities = self._connection.query(
            "SELECT * FROM Win32_PnPEntity WHERE Present = TRUE"
        )

        # Collect child HID and interface metadata for role and brand identification
        hid_info_by_vid_pid: dict[tuple[str, str], dict[str, set[str]]] = {}
        for entity in entities:
            pnp_id = _string_value(entity, "PNPDeviceID") or ""
            name = _string_value(entity, "Name")
            pnp_class = _string_value(entity, "PNPClass")
            vid_match = re.search(r"VID_([0-9A-F]{4})", pnp_id, re.IGNORECASE)
            pid_match = re.search(r"PID_([0-9A-F]{4})", pnp_id, re.IGNORECASE)
            if vid_match and pid_match:
                key = (vid_match.group(1).upper(), pid_match.group(1).upper())
                entry = hid_info_by_vid_pid.setdefault(key, {"names": set(), "classes": set()})
                if name:
                    entry["names"].add(name)
                if pnp_class:
                    entry["classes"].add(pnp_class)

        device_entities = []
        for entity in entities:
            device_id = _string_value(entity, "PNPDeviceID") or _string_value(
                entity, "DeviceID"
            )
            if not device_id or not device_id.upper().startswith(("USB\\", "USBSTOR\\")):
                continue
            # Filter out internal motherboard USB root hubs
            if "ROOT_HUB" in device_id.upper():
                continue
            device_entities.append((entity, device_id))

        volume_paths_by_device = _usb_volume_paths_by_device(
            self._connection,
            {device_id.casefold() for _, device_id in device_entities},
        )

        parents: dict[tuple[str, str], tuple[Any, str]] = {}
        children_by_vid_pid: dict[tuple[str, str], list[tuple[Any, str]]] = {}
        standalone: list[tuple[Any, str]] = []

        for entity, device_id in device_entities:
            vid_match = re.search(r"VID_([0-9A-F]{4})", device_id, re.IGNORECASE)
            pid_match = re.search(r"PID_([0-9A-F]{4})", device_id, re.IGNORECASE)
            if vid_match and pid_match:
                key = (vid_match.group(1).upper(), pid_match.group(1).upper())
                if "&MI_" in device_id.upper():
                    children_by_vid_pid.setdefault(key, []).append((entity, device_id))
                else:
                    parents[key] = (entity, device_id)
            else:
                standalone.append((entity, device_id))

        # 1. Consolidate composite devices under their physical parent
        for key, (entity, device_id) in parents.items():
            extra_info = hid_info_by_vid_pid.get(key, {"names": set(), "classes": set()})
            sub_children = children_by_vid_pid.get(key, [])

            vol_set = set(volume_paths_by_device.get(device_id.casefold(), ()))
            hw_ids = set(_string_sequence(entity, "HardwareID"))
            for c_entity, c_dev_id in sub_children:
                vol_set.update(volume_paths_by_device.get(c_dev_id.casefold(), ()))
                hw_ids.update(_string_sequence(c_entity, "HardwareID"))
                c_name = _string_value(c_entity, "Name")
                if c_name:
                    extra_info["names"].add(c_name)
                c_class = _string_value(c_entity, "PNPClass")
                if c_class:
                    extra_info["classes"].add(c_class)

            category = infer_device_category(
                device_id=device_id,
                name=_string_value(entity, "Name"),
                pnp_class=_string_value(entity, "PNPClass"),
                service=_string_value(entity, "Service"),
                hardware_ids=tuple(sorted(hw_ids)),
                sub_names=extra_info["names"],
                sub_classes=extra_info["classes"],
            )
            friendly = infer_friendly_name(
                device_id=device_id,
                name=_string_value(entity, "Name"),
                manufacturer=_string_value(entity, "Manufacturer"),
                device_category=category,
                sub_names=extra_info["names"],
            )

            device = UsbDevice(
                device_id=device_id,
                name=friendly,
                manufacturer=_string_value(entity, "Manufacturer"),
                pnp_class=_string_value(entity, "PNPClass") or category,
                service=_string_value(entity, "Service"),
                hardware_ids=tuple(sorted(hw_ids)),
                status=_string_value(entity, "Status"),
                volume_paths=tuple(sorted(vol_set)),
                serial_number=extract_serial_number(device_id),
                device_type=category,
            )
            devices[device_id] = device

        # 2. Child interfaces whose parent was not enumerated (e.g. mock test units)
        for key, child_list in children_by_vid_pid.items():
            if key not in parents:
                for entity, device_id in child_list:
                    vol = volume_paths_by_device.get(device_id.casefold(), ())
                    category = infer_device_category(
                        device_id=device_id,
                        name=_string_value(entity, "Name"),
                        pnp_class=_string_value(entity, "PNPClass"),
                        service=_string_value(entity, "Service"),
                        hardware_ids=_string_sequence(entity, "HardwareID"),
                    )
                    friendly = infer_friendly_name(
                        device_id=device_id,
                        name=_string_value(entity, "Name"),
                        manufacturer=_string_value(entity, "Manufacturer"),
                        device_category=category,
                    )
                    device = UsbDevice(
                        device_id=device_id,
                        name=friendly,
                        manufacturer=_string_value(entity, "Manufacturer"),
                        pnp_class=_string_value(entity, "PNPClass"),
                        service=_string_value(entity, "Service"),
                        hardware_ids=_string_sequence(entity, "HardwareID"),
                        status=_string_value(entity, "Status"),
                        volume_paths=vol,
                        serial_number=extract_serial_number(device_id),
                        device_type=category,
                    )
                    devices[device_id] = device

        # 3. Standalone non-composite devices (e.g. USBSTOR mass storage drives)
        for entity, device_id in standalone:
            vol = volume_paths_by_device.get(device_id.casefold(), ())
            category = infer_device_category(
                device_id=device_id,
                name=_string_value(entity, "Name"),
                pnp_class=_string_value(entity, "PNPClass"),
                service=_string_value(entity, "Service"),
                hardware_ids=_string_sequence(entity, "HardwareID"),
            )
            friendly = infer_friendly_name(
                device_id=device_id,
                name=_string_value(entity, "Name"),
                manufacturer=_string_value(entity, "Manufacturer"),
                device_category=category,
            )
            device = UsbDevice(
                device_id=device_id,
                name=friendly,
                manufacturer=_string_value(entity, "Manufacturer"),
                pnp_class=_string_value(entity, "PNPClass"),
                service=_string_value(entity, "Service"),
                hardware_ids=_string_sequence(entity, "HardwareID"),
                status=_string_value(entity, "Status"),
                volume_paths=vol,
                serial_number=extract_serial_number(device_id),
                device_type=category,
            )
            devices[device_id] = device

        return devices


def _usb_volume_paths_by_device(
    connection: Any,
    device_ids: set[str],
) -> dict[str, tuple[str, ...]]:
    requested_ids = {device_id.casefold() for device_id in device_ids}
    paths_by_device: dict[str, set[str]] = {}
    for disk in connection.Win32_DiskDrive():
        device_id = _string_value(disk, "PNPDeviceID")
        if device_id is None or device_id.casefold() not in requested_ids:
            continue

        volume_paths = paths_by_device.setdefault(device_id.casefold(), set())
        for partition in disk.associators("Win32_DiskDriveToDiskPartition"):
            for logical_disk in partition.associators("Win32_LogicalDiskToPartition"):
                drive_id = _string_value(logical_disk, "DeviceID")
                if drive_id and len(drive_id) == 2 and drive_id[1] == ":":
                    volume_paths.add(f"{drive_id}\\")

    return {
        device_id: tuple(sorted(paths))
        for device_id, paths in paths_by_device.items()
    }


def _string_value(entity: Any, property_name: str) -> str | None:
    value = getattr(entity, property_name, None)
    if value is None:
        return None
    return str(value)


def _string_sequence(entity: Any, property_name: str) -> tuple[str, ...]:
    value = getattr(entity, property_name, None)
    if value is None:
        return ()
    if isinstance(value, str):
        return (value,)
    return tuple(str(item) for item in value if item is not None)


def main() -> None:
    parser = argparse.ArgumentParser(description="Monitor Windows USB device changes")
    parser.add_argument(
        "--interval",
        type=float,
        default=1.0,
        help="seconds between WMI inventory checks (default: 1.0)",
    )
    args = parser.parse_args()
    settings = get_settings()
    logging.basicConfig(
        level=settings.log_level.upper(),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    stop_event = Event()
    provider = WindowsWmiProvider()
    policy_store = WhitelistStore(settings.database_path)
    policy_engine = PolicyEngine(store=policy_store, mode=settings.policy_mode)
    logger.info(
        "Starting USB Analyzer Windows device monitor; API base URL: %s, Policy mode: %s",
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
            hid_detector.start_listener()
            try:
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
            finally:
                hid_detector.stop_listener()
    except KeyboardInterrupt:
        logger.info("Stopping USB Analyzer Windows device monitor")
        stop_event.set()


if __name__ == "__main__":
    main()
