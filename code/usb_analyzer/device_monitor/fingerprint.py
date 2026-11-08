import re
from dataclasses import dataclass, field
from typing import Any, Iterable

from usb_analyzer.policy.models import WhitelistEntry

_USB_ID_PATTERN = re.compile(r"\b(VID|PID)_([0-9A-F]{4})\b", re.IGNORECASE)
_REV_PATTERN = re.compile(r"\bREV_([0-9A-F]{4})\b", re.IGNORECASE)
_MI_PATTERN = re.compile(r"\bMI_([0-9A-F]{2})\b", re.IGNORECASE)

# Standard USB device class codes and names
USB_DEVICE_CLASSES = {
    "01": "Audio",
    "02": "Communications and CDC Control",
    "03": "Human Interface Device (HID)",
    "05": "Physical Interface Device (PID)",
    "06": "Image",
    "07": "Printer",
    "08": "Mass Storage (Storage)",
    "09": "Hub",
    "0A": "CDC-Data",
    "0B": "Smart Card",
    "0D": "Content Security",
    "0E": "Video",
    "0F": "Personal Healthcare",
    "E0": "Wireless Controller (Bluetooth)",
    "EF": "Miscellaneous",
    "FE": "Application Specific",
    "FF": "Vendor Specific",
}


@dataclass(frozen=True)
class DeviceFingerprint:
    """Normalized hardware fingerprint extracted from USB device descriptors."""

    vendor_id: str | None = None
    product_id: str | None = None
    serial_number: str | None = None
    revision: str | None = None
    device_class: str | None = None
    device_type: str = "Unrecognized USB Peripheral"
    friendly_name: str | None = None
    interfaces: tuple[str, ...] = ()
    is_composite: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "vendor_id": self.vendor_id,
            "product_id": self.product_id,
            "serial_number": self.serial_number,
            "revision": self.revision,
            "device_class": self.device_class,
            "device_type": self.device_type,
            "friendly_name": self.friendly_name,
            "interfaces": list(self.interfaces),
            "is_composite": self.is_composite,
        }


def extract_serial_number(device_id: str) -> str | None:
    """Extract serial number from USB / USBSTOR device instance ID.
    
    Windows instance IDs:
      USB\\VID_0951&PID_1666\\0014D12345678 -> 0014D12345678
      USBSTOR\\DISK&VEN_...\\0014D12345678&0 -> 0014D12345678
      USB\\VID_046D&PID_C52B\\6&1234567&0 (location-synthesized ID, no true serial)
    """
    parts = device_id.strip().split("\\")
    if len(parts) >= 3:
        raw_serial = parts[2].strip()
        # If it has trailing volume index like &0
        if "&" in raw_serial:
            sub = raw_serial.split("&")[0]
            # If the original raw serial contained only one & followed by a number (e.g. SN&0)
            if len(raw_serial.split("&")) == 2 and raw_serial.split("&")[1].isdigit():
                return sub
            # Otherwise if it has multiple & like 6&1234567&0, it is a synthesized ID
            return raw_serial
        return raw_serial
    return None


def infer_device_category(
    device_id: str = "",
    name: str | None = None,
    pnp_class: str | None = None,
    service: str | None = None,
    hardware_ids: tuple[str, ...] = (),
    sub_names: Iterable[str] = (),
    sub_classes: Iterable[str] = (),
) -> str:
    """Infer human-readable USB device category (Keyboard, Mouse, Storage, etc.)."""
    pool = [
        device_id,
        name or "",
        pnp_class or "",
        service or "",
        *hardware_ids,
        *sub_names,
        *sub_classes,
    ]
    text = " ".join(pool).lower()

    has_kbd = "keyboard" in text or "kbd" in text
    has_mouse = "mouse" in text or "mouhid" in text or "touchpad" in text
    if has_kbd and has_mouse:
        return "Keyboard & Mouse"
    if has_kbd:
        return "Keyboard"
    if has_mouse:
        return "Mouse"

    if any(k in text for k in ("disk", "storage", "usbstor", "flash", "thumbdrive", "cruzer", "datatraveler")):
        return "USB Storage Drive"
    if any(k in text for k in ("audio", "sound", "headset", "speaker", "microphone", "usbaudio")):
        return "Audio Device"
    if any(k in text for k in ("camera", "webcam", "video", "usbvideo", "uvc")):
        return "Webcam"
    if any(k in text for k in ("bluetooth", "bthusb")):
        return "Bluetooth Adapter"
    if any(k in text for k in ("yubikey", "smartcard", "smart card", "token", "nitrokey")):
        return "Security Token"
    if any(k in text for k in ("wireless", "wifi", "802.11", "ethernet", "lan")):
        return "Network Adapter"
    if "hid" in text or "human interface" in text:
        return "Human Interface Device (HID)"

    return "Unrecognized USB Peripheral"


def infer_friendly_name(
    device_id: str,
    name: str | None = None,
    manufacturer: str | None = None,
    device_category: str = "Unrecognized USB Peripheral",
    sub_names: Iterable[str] = (),
) -> str:
    """Generate a clean human-readable name for a USB device."""
    generic_names = {
        "usb composite device",
        "usb input device",
        "generic usb hub",
        "usb root hub",
        "usb device",
        "composite device",
        "app mode",
        "hid-compliant vendor-defined device",
        "hid-compliant system controller",
        "hid-compliant consumer control device",
        "unnamed device",
    }

    # 1. Look for a brand/model name in sub-names or name
    candidates = [name, *sub_names]
    # Filter out generic names
    meaningful = [
        c.strip() for c in candidates
        if c and c.strip().lower() not in generic_names and not c.strip().lower().startswith("hid-compliant")
    ]

    # Prioritize specific model names (e.g. "HP True Vision FHD Camera", "Kingston DataTraveler")
    for cand in meaningful:
        if not cand.lower().startswith("hid keyboard") and not cand.lower().startswith("hid-compliant"):
            return cand

    # 2. Check manufacturer + category
    mfg = (manufacturer or "").strip()
    if mfg and not mfg.startswith("(") and mfg.lower() not in ("generic", "microsoft", "standard", "standard usb host controller"):
        return f"{mfg} {device_category}"

    # 3. If there's a specific peripheral type
    if meaningful:
        return meaningful[0]

    if device_category != "Unrecognized USB Peripheral":
        return f"USB {device_category}"

    return "Unrecognized USB Peripheral"


def extract_fingerprint(
    device_id: str,
    hardware_ids: tuple[str, ...] = (),
    pnp_class: str | None = None,
    service: str | None = None,
    name: str | None = None,
    manufacturer: str | None = None,
    sub_names: Iterable[str] = (),
    sub_classes: Iterable[str] = (),
) -> DeviceFingerprint:
    """Extract complete USB fingerprint including VID, PID, serial, class, and interfaces."""
    identifiers: dict[str, str] = {}
    interfaces: list[str] = []
    is_composite = False

    search_pool = [device_id, *hardware_ids]
    for value in search_pool:
        for match in _USB_ID_PATTERN.finditer(value):
            identifiers.setdefault(match.group(1).lower(), match.group(2).upper())
        rev_match = _REV_PATTERN.search(value)
        if rev_match:
            identifiers.setdefault("rev", rev_match.group(1).upper())
        for mi_match in _MI_PATTERN.finditer(value):
            if mi_match.group(1) not in interfaces:
                interfaces.append(f"Interface_{mi_match.group(1)}")
                is_composite = True

    serial = extract_serial_number(device_id)

    # Class classification
    normalized_class = None
    if pnp_class:
        if pnp_class.upper() in ("DISKDRIVE", "STORAGE"):
            normalized_class = "Mass Storage"
        elif pnp_class.upper() in ("KEYBOARD", "MOUSE", "HIDCLASS"):
            normalized_class = "Human Interface Device (HID)"
        elif pnp_class.upper() in ("NET", "NETTRANS"):
            normalized_class = "Network Adapter"
        else:
            normalized_class = pnp_class
    elif service:
        if "USBSTOR" in service.upper() or "DISK" in service.upper():
            normalized_class = "Mass Storage"
        elif "KBD" in service.upper() or "HID" in service.upper():
            normalized_class = "Human Interface Device (HID)"
        else:
            normalized_class = service

    category = infer_device_category(
        device_id=device_id,
        name=name,
        pnp_class=pnp_class,
        service=service,
        hardware_ids=hardware_ids,
        sub_names=sub_names,
        sub_classes=sub_classes,
    )
    friendly = infer_friendly_name(
        device_id=device_id,
        name=name,
        manufacturer=manufacturer,
        device_category=category,
        sub_names=sub_names,
    )

    return DeviceFingerprint(
        vendor_id=identifiers.get("vid"),
        product_id=identifiers.get("pid"),
        serial_number=serial,
        revision=identifiers.get("rev"),
        device_class=normalized_class,
        device_type=category,
        friendly_name=friendly,
        interfaces=tuple(sorted(interfaces)),
        is_composite=is_composite,
    )


def detect_spoofed_identity(
    fingerprint: DeviceFingerprint,
    trusted_entries: Iterable[WhitelistEntry],
) -> tuple[bool, str | None, dict[str, Any]]:
    """Detect if a connected device has a trusted VID/PID but a mismatched serial number.
    
    This implements Attack Scenario 5 from the proposal:
    'Trusted VID/PID, different serial -> Mismatch alert'.
    """
    if not fingerprint.vendor_id or not fingerprint.product_id:
        return False, None, {}

    for entry in trusted_entries:
        # Check if entry has same VID and PID and a registered legitimate serial
        if (
            entry.vendor_id
            and entry.product_id
            and entry.serial_number
            and entry.vendor_id.strip().upper() == fingerprint.vendor_id.upper()
            and entry.product_id.strip().upper() == fingerprint.product_id.upper()
        ):
            # Same VID/PID! Now check serial number
            if fingerprint.serial_number and fingerprint.serial_number.strip().casefold() != entry.serial_number.strip().casefold():
                reason = (
                    f"Identity spoofing detected: device claims trusted VID {fingerprint.vendor_id}:"
                    f"PID {fingerprint.product_id} ({entry.name}), but presents unauthorized serial "
                    f"'{fingerprint.serial_number}' instead of registered serial '{entry.serial_number}'."
                )
                details = {
                    "trusted_entry_id": str(entry.id),
                    "trusted_name": entry.name,
                    "claimed_vid": fingerprint.vendor_id,
                    "claimed_pid": fingerprint.product_id,
                    "expected_serial": entry.serial_number,
                    "observed_serial": fingerprint.serial_number,
                }
                return True, reason, details

    return False, None, {}

