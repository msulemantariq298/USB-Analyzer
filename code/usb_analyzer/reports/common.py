"""Shared telemetry summarization and formatting helpers for CSV and PDF reports."""

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import re
from typing import Any

from usb_analyzer.core.events import DeviceEvent, EventSeverity

_VID_RE = re.compile(r"VID_([0-9A-Fa-f]+)")
_PID_RE = re.compile(r"PID_([0-9A-Fa-f]+)")
_NUMERIC_RE = re.compile(r"^-\d+(?:\.\d+)?$")


@dataclass(slots=True)
class DeviceReportState:
    """Normalized per-device summary aligned with dashboard verdict rules."""

    device_id: str
    name: str
    device_type: str
    vendor_id: str
    product_id: str
    serial_number: str
    verdict: str  # "SAFE", "CONTAINED", "BLOCKED"
    severity: str  # "info", "warning", "critical"
    reason: str
    action: str
    is_disconnected: bool
    latest_time: datetime


@dataclass(slots=True)
class ReportSummary:
    """Top-level metrics and grouped telemetry snapshot for forensic reporting."""

    total_events: int
    connected_devices: int
    critical_alerts: int
    warning_alerts: int
    blocked_devices: int
    warning_devices: int
    safe_devices: int
    storage_scans: int
    active_scans: int
    flagged_files: int
    health_score_pct: int
    devices: list[DeviceReportState]
    activity_labels: list[str]
    activity_counts: list[int]
    window_events: int
    window_alerts: int


def format_hex_id(val: Any) -> str:
    """Format a hex hardware identifier as `0xXXXX`, or `N/A` when missing."""
    if not val:
        return "N/A"
    text = str(val).strip()
    if not text or text.upper() == "N/A":
        return "N/A"
    if text.lower().startswith("0x"):
        return "0x" + text[2:].upper()
    return f"0x{text.upper()}"


def extract_usb_ids(device_id: str, details: dict[str, Any] | None = None) -> tuple[str, str, str]:
    """Extract normalized (VID, PID, Serial) tuple from event details and device ID."""
    det = details or {}
    vid = det.get("vendor_id")
    pid = det.get("product_id")
    serial = det.get("serial_number")

    if not vid and device_id:
        m = _VID_RE.search(device_id)
        if m:
            vid = m.group(1)
    if not pid and device_id:
        m = _PID_RE.search(device_id)
        if m:
            pid = m.group(1)
    if not serial and device_id and "\\" in device_id:
        serial = device_id.split("\\")[-1]

    return (
        format_hex_id(vid),
        format_hex_id(pid),
        str(serial).strip() if serial else "N/A",
    )


def build_device_identity_lookup(events: list[DeviceEvent]) -> dict[str, tuple[str, str, str, str]]:
    """Build lookup mapping device_id / normalized serial to (name, vid, pid, serial)."""
    by_key: dict[str, tuple[str, str, str, str]] = {}
    for ev in events:
        det = ev.details or {}
        vid, pid, serial = extract_usb_ids(ev.device_id, det)
        name = extract_device_name(ev.device_id, det)
        if vid != "N/A" or pid != "N/A" or (det.get("name") or det.get("friendly_name")):
            entry = (name, vid, pid, serial)
            by_key.setdefault(ev.device_id.lower(), entry)
            if serial != "N/A":
                base_sn = serial.split("&")[0].lower()
                if base_sn:
                    by_key.setdefault(f"sn:{base_sn}", entry)
    return by_key


def extract_device_name(device_id: str, details: dict[str, Any] | None = None) -> str:
    """Resolve human-friendly hardware name for an event or device."""
    det = details or {}
    for key in ("name", "device_name", "friendly_name"):
        val = det.get(key)
        if val and str(val).strip():
            return str(val).strip()
    if device_id.upper().startswith("USBSTOR"):
        return "USB Mass Storage Drive"
    if "HID" in device_id.upper():
        return "USB HID Peripheral"
    return "USB Peripheral"


def classify_event_verdict(ev: DeviceEvent) -> tuple[str, str, str]:
    """Return normalized (verdict, reason, action) for a single telemetry event."""
    det = ev.details or {}
    verdict = str(det.get("verdict") or "").upper().strip()
    action = str(det.get("action_taken") or det.get("action") or "").strip()

    if not verdict:
        if ev.event_type in ("device.allowed", "policy.allowed") or action == "Allowed & Active":
            verdict = "SAFE"
        elif ev.event_type in (
            "device.blocked",
            "device.spoofed_identity",
            "device.attack_hardware",
            "hid.injection_detected",
        ):
            verdict = "BLOCKED"
        elif ev.event_type == "scan.completed":
            if ev.severity == EventSeverity.CRITICAL or det.get("has_threats"):
                verdict = "BLOCKED"
            elif ev.severity == EventSeverity.WARNING:
                verdict = "CONTAINED"
            else:
                verdict = "SAFE"
        elif ev.severity == EventSeverity.CRITICAL:
            verdict = "BLOCKED"
        elif ev.severity == EventSeverity.WARNING or ev.event_type in (
            "policy.violation",
            "device.suspicious",
        ):
            verdict = "CONTAINED"
        else:
            verdict = "SAFE"

    reason = str(
        det.get("reason")
        or det.get("summary")
        or det.get("threat")
        or det.get("threat_type")
        or ""
    ).strip()
    if not reason:
        if ev.event_type == "device.connected":
            reason = "Peripheral connected"
        elif ev.event_type == "device.disconnected":
            reason = "Peripheral detached"
        else:
            reason = ev.event_type

    if not action:
        if verdict == "BLOCKED":
            action = "Blocked (Elevate for PnP Disable)" if det.get("blocked") is False else "Isolated & Blocked"
        elif verdict == "CONTAINED":
            action = "Contained / Review"
        elif ev.event_type == "device.disconnected":
            action = "Detached"
        else:
            action = "Logged"

    return verdict, reason, action


def _ensure_utc(dt: datetime) -> datetime:
    return dt if dt.tzinfo is not None else dt.replace(tzinfo=timezone.utc)


def _summarize_single_device(device_id: str, ev_list: list[DeviceEvent]) -> DeviceReportState:
    """Compute consolidated status matching dashboard `summarizeDeviceStatus`."""
    ev_sorted = sorted(ev_list, key=lambda e: _ensure_utc(e.time), reverse=True)
    latest = ev_sorted[0]

    connect_ev = next(
        (e for e in ev_sorted if e.event_type == "device.connected" and e.details and (e.details.get("vendor_id") or e.details.get("name"))),
        None,
    ) or next(
        (e for e in ev_sorted if e.details and (e.details.get("vendor_id") or e.details.get("name"))),
        latest,
    )
    reason_ev = next(
        (e for e in ev_sorted if e.details and (e.details.get("reason") or e.details.get("threat_type") or e.details.get("summary"))),
        latest,
    )
    latest_scan_ev = next((e for e in ev_sorted if e.event_type == "scan.completed"), None)

    decision_types = {
        "device.allowed",
        "policy.allowed",
        "device.blocked",
        "device.spoofed_identity",
        "device.attack_hardware",
        "hid.injection_detected",
        "policy.violation",
        "device.suspicious",
        "scan.completed",
    }
    latest_decision = next((e for e in ev_sorted if e.event_type in decision_types), None)

    is_allowed = bool(
        latest_decision and latest_decision.event_type in ("device.allowed", "policy.allowed")
    )
    is_latest_scan_clean = bool(
        latest_scan_ev
        and latest_scan_ev.severity == EventSeverity.INFO
        and not (latest_scan_ev.details or {}).get("has_threats")
    )
    last_block_ev = next((e for e in ev_sorted if e.event_type == "device.blocked"), None)
    is_port_disabled = bool(last_block_ev and (last_block_ev.details or {}).get("blocked") is not False)
    has_hw_attack = any(
        e.event_type in ("device.spoofed_identity", "device.attack_hardware", "hid.injection_detected")
        for e in ev_sorted
    )
    storage_cleared = bool(
        is_latest_scan_clean
        and not is_port_disabled
        and not has_hw_attack
        and latest_scan_ev
        and (not last_block_ev or _ensure_utc(latest_scan_ev.time) >= _ensure_utc(last_block_ev.time))
    )

    has_critical = (not is_allowed) and (not storage_cleared) and (
        has_hw_attack
        or any(
            (e.severity == EventSeverity.CRITICAL and e.event_type not in ("scan.completed", "device.blocked"))
            or (e.event_type == "device.blocked" and (e.details or {}).get("threat_type") != "storage_malware")
            for e in ev_sorted
        )
        or bool(latest_scan_ev and (latest_scan_ev.severity == EventSeverity.CRITICAL or (latest_scan_ev.details or {}).get("has_threats")))
    )
    is_blocked = (not is_allowed) and (not storage_cleared) and (
        has_critical
        or bool(
            latest_decision
            and latest_decision.event_type == "device.blocked"
            and (latest_decision.details or {}).get("blocked") is not False
        )
    )
    is_warning = (not is_allowed) and (not is_blocked) and (not storage_cleared) and (
        any(
            (e.severity == EventSeverity.WARNING and e.event_type != "scan.completed")
            or e.event_type in ("policy.violation", "device.suspicious")
            for e in ev_sorted
        )
        or bool(latest_scan_ev and latest_scan_ev.severity == EventSeverity.WARNING)
    )
    is_disconnected = latest.event_type == "device.disconnected"

    if is_blocked:
        verdict = "BLOCKED"
        severity = "critical"
    elif is_warning:
        verdict = "CONTAINED"
        severity = "warning"
    else:
        verdict = "SAFE"
        severity = "info"

    merged_details = dict(connect_ev.details or {})
    vid, pid, serial = extract_usb_ids(device_id, merged_details)
    name = extract_device_name(device_id, merged_details)
    dev_type = str(merged_details.get("device_type") or "USB Peripheral")

    reason_det = reason_ev.details or {}
    if is_allowed:
        reason = str((latest_decision.details or {}).get("reason") or "Approved by operator")
    elif is_blocked or is_warning:
        reason = str(
            reason_det.get("reason")
            or reason_det.get("threat_type")
            or reason_det.get("summary")
            or "Policy review required"
        )
    elif is_disconnected:
        reason = "Device detached from USB bus"
    elif latest.event_type == "scan.completed" and (latest.details or {}).get("summary"):
        reason = str((latest.details or {})["summary"])
    else:
        reason = "Standard peripheral verified"

    if is_allowed:
        action = str((latest_decision.details or {}).get("action_taken") or "Allowed & Active")
    elif is_blocked:
        if last_block_ev and (last_block_ev.details or {}).get("blocked") is False:
            action = str((last_block_ev.details or {}).get("action_taken") or "Block Failed (Elevate)")
        else:
            action = str(((last_block_ev.details or {}) if last_block_ev else {}).get("action_taken") or "Isolated & Disabled")
    elif is_warning:
        action = "Held for Review"
    elif is_disconnected:
        action = "Detached"
    else:
        action = str((latest.details or {}).get("action_taken") or (latest.details or {}).get("action") or "Active")

    return DeviceReportState(
        device_id=device_id,
        name=name,
        device_type=dev_type,
        vendor_id=vid,
        product_id=pid,
        serial_number=serial,
        verdict=verdict,
        severity=severity,
        reason=reason,
        action=action,
        is_disconnected=is_disconnected,
        latest_time=_ensure_utc(latest.time),
    )


def summarize_telemetry(events: list[DeviceEvent]) -> ReportSummary:
    """Compute full KPIs, per-device state rows, health ratio, and activity bars."""
    grouped: dict[str, list[DeviceEvent]] = {}
    for ev in events:
        grouped.setdefault(ev.device_id, []).append(ev)

    device_states = [_summarize_single_device(did, evs) for did, evs in grouped.items()]
    verdict_rank = {"BLOCKED": 0, "CONTAINED": 1, "SAFE": 2}
    device_states.sort(
        key=lambda d: (verdict_rank.get(d.verdict, 3), -d.latest_time.timestamp()),
    )

    connected_devices = sum(1 for d in device_states if not d.is_disconnected)
    blocked_devices = sum(1 for d in device_states if d.verdict == "BLOCKED")
    warning_devices = sum(1 for d in device_states if d.verdict == "CONTAINED")
    safe_devices = sum(1 for d in device_states if d.verdict == "SAFE")
    total_dev = safe_devices + warning_devices + blocked_devices
    health_pct = round((safe_devices / total_dev) * 100) if total_dev > 0 else 100

    critical_alerts = sum(1 for e in events if e.severity == EventSeverity.CRITICAL)
    warning_alerts = sum(1 for e in events if e.severity == EventSeverity.WARNING)
    started_scans = sum(1 for e in events if e.event_type == "scan.started")
    finished_scans = sum(1 for e in events if e.event_type in ("scan.completed", "scan.failed"))
    active_scans = max(0, started_scans - finished_scans)

    flagged_files = 0
    for ev in events:
        det = ev.details or {}
        if ev.event_type == "scan.completed":
            if isinstance(det.get("flagged"), list):
                flagged_files += len(det["flagged"])
            elif isinstance(det.get("flagged_count"), int):
                flagged_files += det["flagged_count"]
        elif ev.event_type == "scan.threat_detected":
            if isinstance(det.get("flagged_files"), list):
                flagged_files += len(det["flagged_files"])
            else:
                flagged_files += 1

    # 6-bucket 1h recent activity chart aligned with analytics endpoint
    now = datetime.now(timezone.utc)
    step = timedelta(minutes=10)
    window_start = now - timedelta(hours=1)
    activity_labels = [
        (window_start + step * (i + 1)).astimezone().strftime("%H:%M")
        for i in range(6)
    ]
    activity_counts = [0] * 6
    window_events = 0
    window_alerts = 0
    step_sec = step.total_seconds()
    for ev in events:
        ev_t = _ensure_utc(ev.time)
        if ev_t < window_start:
            continue
        window_events += 1
        if ev.severity in (EventSeverity.WARNING, EventSeverity.CRITICAL):
            window_alerts += 1
        elapsed = max(0.0, (ev_t - window_start).total_seconds())
        idx = min(5, int(elapsed // step_sec))
        activity_counts[idx] += 1

    return ReportSummary(
        total_events=len(events),
        connected_devices=connected_devices,
        critical_alerts=critical_alerts,
        warning_alerts=warning_alerts,
        blocked_devices=blocked_devices,
        warning_devices=warning_devices,
        safe_devices=safe_devices,
        storage_scans=finished_scans,
        active_scans=active_scans,
        flagged_files=flagged_files,
        health_score_pct=health_pct,
        devices=device_states,
        activity_labels=activity_labels,
        activity_counts=activity_counts,
        window_events=window_events,
        window_alerts=window_alerts,
    )


def collect_file_analyses(events: list[DeviceEvent]) -> list[dict[str, Any]]:
    """Collect deduplicated storage file analysis records ordered highest-risk first."""
    seen: set[tuple[str, str]] = set()
    rows: list[dict[str, Any]] = []

    events_desc = sorted(events, key=lambda e: _ensure_utc(e.time), reverse=True)
    for ev in events_desc:
        if ev.event_type != "scan.completed":
            continue
        det = ev.details or {}
        volume = str(det.get("volume_path") or det.get("mount_point") or "")
        analyses = det.get("file_analyses") or det.get("flagged") or []
        if not isinstance(analyses, list):
            continue
        for item in analyses:
            if not isinstance(item, dict):
                continue
            fpath = str(item.get("path") or "")
            fsha = str(item.get("sha256") or "")
            if not fpath or (fpath, fsha) in seen:
                continue
            seen.add((fpath, fsha))
            score = int(item.get("risk_score", 0))
            verdict = (
                "CRITICAL" if score >= 80
                else ("HIGH" if score >= 50 else ("SUSPICIOUS" if score >= 20 else "CLEAN"))
            )
            entry = dict(item)
            entry.setdefault("volume_path", volume)
            entry["verdict"] = verdict
            entry["device_id"] = ev.device_id
            entry["event_id"] = str(ev.id)
            entry["scanned_at"] = _ensure_utc(ev.time).isoformat()
            rows.append(entry)

    rows.sort(key=lambda r: (-int(r.get("risk_score", 0)), str(r.get("path", ""))))
    return rows


def csv_safe_cell(value: Any) -> str:
    """Format a scalar cell cleanly and neutralize spreadsheet formula injection."""
    if value is None:
        return ""
    text = str(value)
    if not text:
        return ""
    first = text[0]
    if first in ("=", "+", "@", "\t", "\r"):
        return f"'{text}"
    if first == "-" and not _NUMERIC_RE.match(text):
        return f"'{text}"
    return text
