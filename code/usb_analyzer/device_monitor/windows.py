import argparse
import logging
import os
from threading import Event
from typing import Any

from usb_analyzer.core.api_client import ApiEventClient
from usb_analyzer.core.config import get_settings
from usb_analyzer.device_monitor.monitor import DeviceProvider, UsbDevice, run_monitor

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
        for entity in self._connection.query(
            "SELECT * FROM Win32_PnPEntity WHERE Present = TRUE"
        ):
            device_id = _string_value(entity, "PNPDeviceID") or _string_value(
                entity, "DeviceID"
            )
            if not device_id or not device_id.upper().startswith(("USB\\", "USBSTOR\\")):
                continue

            device = UsbDevice(
                device_id=device_id,
                name=_string_value(entity, "Name"),
                manufacturer=_string_value(entity, "Manufacturer"),
                pnp_class=_string_value(entity, "PNPClass"),
                service=_string_value(entity, "Service"),
                hardware_ids=_string_sequence(entity, "HardwareID"),
                status=_string_value(entity, "Status"),
            )
            devices[device_id] = device
        return devices


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
    logger.info(
        "Starting USB Analyzer Windows device monitor; API base URL: %s",
        settings.api_base_url,
    )
    try:
        with ApiEventClient(
            base_url=settings.api_base_url,
            api_prefix=settings.api_prefix,
            timeout_seconds=settings.api_timeout_seconds,
        ) as event_sink:
            run_monitor(provider, event_sink, stop_event, args.interval)
    except KeyboardInterrupt:
        logger.info("Stopping USB Analyzer Windows device monitor")
        stop_event.set()


if __name__ == "__main__":
    main()
