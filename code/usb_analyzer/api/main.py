import csv
import io
import json
import logging
import os
import time
import urllib.parse
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from uuid import UUID

from fastapi import FastAPI, HTTPException, Query, Response, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from usb_analyzer.core.config import get_settings
from usb_analyzer.core.database import EventStore
from usb_analyzer.core.events import DeviceEvent, EventSeverity
from usb_analyzer.core.windows_notifier import send_desktop_notification
from usb_analyzer.device_monitor.fingerprint import DeviceFingerprint, detect_spoofed_identity
from usb_analyzer.hid_detector.detector import BadUsbDetector
from usb_analyzer.policy.engine import PolicyEngine
from usb_analyzer.policy.enforcement import get_platform_blocker
from usb_analyzer.policy.models import PolicyMode, WhitelistEntry
from usb_analyzer.policy.store import WhitelistStore
from usb_analyzer.reports.common import (
    build_device_identity_lookup,
    classify_event_verdict,
    csv_safe_cell,
    extract_device_name,
    extract_usb_ids,
)
from usb_analyzer.reports.incident_pdf import generate_incident_pdf
from usb_analyzer.storage_scanner.service import StorageScanService
from usb_analyzer.storage_scanner.signatures import DEFAULT_RULES_DIR, SignatureEngine

logger = logging.getLogger(__name__)

settings = get_settings()
event_store = EventStore(settings.database_path)
whitelist_store = WhitelistStore(settings.database_path)
current_policy_mode = whitelist_store.get_policy_mode() or PolicyMode(settings.policy_mode)
policy_engine = PolicyEngine(
    store=whitelist_store,
    blocker=get_platform_blocker(dry_run=bool(os.environ.get("PYTEST_CURRENT_TEST"))),
    mode=current_policy_mode,
)
hid_detector = BadUsbDetector(event_sink=event_store, policy_engine=policy_engine)


class _ApiScanEventSink:
    """Persist scan events emitted inside API handlers and retain recent events for WS broadcast."""

    def __init__(self) -> None:
        self.pending_broadcasts: list[DeviceEvent] = []

    def add(self, event: DeviceEvent) -> DeviceEvent:
        added = event_store.add(event)
        self.pending_broadcasts.append(added)
        return added


_api_scan_sink = _ApiScanEventSink()
storage_scan_service = StorageScanService(
    event_sink=_api_scan_sink,
    policy_engine=policy_engine,
    max_workers=2,
)

app = FastAPI(title=settings.app_name, version="0.1.0")


class ConnectionManager:
    """Manages active WebSocket telemetry streaming clients."""

    def __init__(self) -> None:
        self.active_connections: list[WebSocket] = []

    async def connect(self, websocket: WebSocket) -> None:
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket) -> None:
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast(self, message: dict[str, Any]) -> None:
        for connection in list(self.active_connections):
            try:
                await connection.send_json(message)
            except Exception:
                self.disconnect(connection)


ws_manager = ConnectionManager()


async def broadcast_telemetry(msg_type: str = "telemetry_update", payload: Any = None) -> None:
    await ws_manager.broadcast({
        "type": msg_type,
        "payload": payload,
        "timestamp": time.time(),
    })


@app.middleware("http")
async def add_cache_control_headers(request, call_next):
    response = await call_next(request)
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response


static_directory = Path(__file__).parent / "static"
app.mount("/static", StaticFiles(directory=static_directory), name="static")


class PolicyModeUpdateRequest(BaseModel):
    mode: PolicyMode


class NotificationActionPayload(BaseModel):
    action: str | None = None
    device_id: str | None = None
    triage: bool = False


# In-memory queue / broadcast for notification actions consumed by active dashboard tab(s)
_pending_notification_actions: list[dict[str, Any]] = []


@app.get("/", include_in_schema=False)
def dashboard() -> FileResponse:
    return FileResponse(static_directory / "index.html")


@app.get("/favicon.ico", include_in_schema=False)
def favicon() -> Response:
    svg = (
        '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" '
        'stroke="#1D4ED8" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">'
        '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>'
    )
    return Response(content=svg, media_type="image/svg+xml")


@app.get("/open", include_in_schema=False)
def open_dashboard_redirect(
    toast_action: str | None = None,
    inspect_device: str | None = None,
    device_id: str | None = None,
    triage: str | None = None,
) -> Response:
    """Entrypoint launched by Windows desktop notifications.
    
    If the dashboard is already open in a browser tab, signals that tab
    via SSE/polling and returns a self-closing response to prevent duplicate tabs.
    If no tab is currently open, redirects to the dashboard root with query parameters.
    """
    target_device = device_id or inspect_device
    is_triage = triage in ("1", "true", "yes")

    if toast_action or target_device or is_triage:
        _pending_notification_actions.append({
            "action": toast_action,
            "device_id": target_device,
            "triage": is_triage,
            "timestamp": time.time(),
        })
        # Keep queue bounded
        del _pending_notification_actions[:-20]

    # Check if a client dashboard tab is currently connected (heartbeat within 8s)
    has_active_client = bool(
        _active_dashboard_clients
        and any(time.time() - t < 8.0 for t in _active_dashboard_clients.values())
    )

    if has_active_client:
        # Client tab is already open: serve minimal self-closing HTML
        html_content = """<!doctype html>
<html>
<head><title>USB Analyzer</title></head>
<body>
<script>
window.focus();
try { window.close(); } catch(e) {}
setTimeout(function() { window.close(); }, 350);
</script>
</body>
</html>"""
        return Response(content=html_content, media_type="text/html")

    # No dashboard tab currently open: redirect to open dashboard with parameters
    params = []
    if toast_action:
        params.append(f"toast_action={urllib.parse.quote(toast_action)}")
    if target_device:
        params.append(f"inspect_device={urllib.parse.quote(target_device)}")
    if is_triage:
        params.append("triage=1")

    query_str = f"?{'&'.join(params)}" if params else ""
    return Response(
        status_code=307,
        headers={"Location": f"/{query_str}"},
    )


_active_dashboard_clients: dict[str, float] = {}


@app.post(f"{settings.api_prefix}/dashboard/heartbeat")
def dashboard_heartbeat(client_id: str = Query(...)) -> dict[str, Any]:
    """Track active dashboard browser tabs to prevent opening duplicate tabs."""
    now = time.time()
    _active_dashboard_clients[client_id] = now
    # Clean stale clients (> 30s)
    stale = [cid for cid, last in _active_dashboard_clients.items() if now - last > 30.0]
    for cid in stale:
        _active_dashboard_clients.pop(cid, None)

    # Return any pending notification actions
    actions = list(_pending_notification_actions)
    _pending_notification_actions.clear()
    return {"status": "ok", "actions": actions}


@app.get(f"{settings.api_prefix}/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.websocket(f"{settings.api_prefix}/ws/telemetry")
async def websocket_telemetry_endpoint(websocket: WebSocket) -> None:
    await ws_manager.connect(websocket)
    try:
        await websocket.send_json({
            "type": "connected",
            "message": "USB Analyzer Real-Time Telemetry Stream Connected",
            "timestamp": time.time(),
        })
        while True:
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text("pong")
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)
    except Exception:
        ws_manager.disconnect(websocket)


@app.get(f"{settings.api_prefix}/events", response_model=list[DeviceEvent])
def list_events(
    limit: int = Query(default=100, ge=1, le=1000),
) -> list[DeviceEvent]:
    return event_store.list(limit=limit)


@app.post(
    f"{settings.api_prefix}/events",
    response_model=DeviceEvent,
    status_code=201,
)
async def create_event(event: DeviceEvent) -> DeviceEvent:
    added = event_store.add(event)
    await broadcast_telemetry("event_added", added.model_dump(mode="json"))

    details = event.details or {}
    if details.get("suppress_toast"):
        return added

    # Unrecognized hardware emits both device.blocked and policy.violation; let the warning toast handle it once.
    if (
        event.event_type == "device.blocked"
        and details.get("reason") == "Unauthorized device: not found on the whitelist"
    ):
        return added

    if event.severity == EventSeverity.CRITICAL:
        summary = details.get("summary") or details.get("reason") or "Critical hardware threat intercepted"
        if event.event_type == "device.blocked" and details.get("blocked") is False:
            msg_body = (
                summary
                if "administrator" in summary.lower()
                else f"Could not disable port automatically (run as Administrator). {summary}"
            )
            send_desktop_notification(
                "USB Analyzer — Threat Detected (Elevation Required)",
                msg_body,
                severity="critical",
                device_id=event.device_id,
            )
        else:
            send_desktop_notification(
                "USB Analyzer — Threat Neutralized",
                f"Action taken: Port disabled. {summary}",
                severity="critical",
                device_id=event.device_id,
            )
    elif event.severity == EventSeverity.WARNING:
        summary = details.get("summary") or details.get("reason") or "Unregistered device connected"
        send_desktop_notification(
            "USB Analyzer — Suspicious Device Alert",
            f"Problem: {summary}",
            severity="warning",
            device_id=event.device_id,
        )
    return added


class DeviceBlockRequest(BaseModel):
    device_id: str
    reason: str = "Blocked by user decision following suspicious hardware alert"


class DeviceAllowRequest(BaseModel):
    device_id: str
    reason: str = "User chose to let device run following suspicious hardware alert"


@app.post(f"{settings.api_prefix}/devices/block")
async def block_device_manually(req: DeviceBlockRequest) -> dict[str, Any]:
    decision, block_event = policy_engine.block_threat(
        device_id=req.device_id,
        reason=req.reason,
        threat_type="user_containment_action",
        details={"action": "blocked_by_user"},
    )
    if not decision.blocked_successfully:
        block_event.details["action_taken"] = "Block Failed (Administrator Privileges Required)"
    else:
        block_event.details["action_taken"] = "Isolated & Disabled"
    event_store.add(block_event)
    await broadcast_telemetry("device_blocked", {"device_id": req.device_id, "reason": req.reason, "blocked": decision.blocked_successfully})
    if decision.blocked_successfully:
        send_desktop_notification(
            "USB Analyzer — Device Blocked",
            f"Action taken: Port disabled for {req.device_id}.",
            severity="critical",
            device_id=req.device_id,
        )
        summary = f"Device {req.device_id} has been disabled and isolated at the hardware port."
    else:
        send_desktop_notification(
            "USB Analyzer — Block Failed (Admin Required)",
            f"Could not disable {req.device_id}: Administrator privileges required.",
            severity="warning",
            device_id=req.device_id,
        )
        summary = f"Device {req.device_id} could not be isolated at the port: Administrator privileges required."
    return {
        "status": "blocked",
        "device_id": req.device_id,
        "blocked": decision.blocked_successfully,
        "summary": summary,
    }


@app.post(f"{settings.api_prefix}/devices/allow")
async def allow_device_manually(req: DeviceAllowRequest) -> dict[str, Any]:
    whitelist_store.allow_device_session(req.device_id)
    port_enabled, enable_msg = policy_engine.unblock_device(req.device_id, reason=req.reason)
    allow_event = DeviceEvent(
        device_id=req.device_id,
        source="user-decision",
        severity=EventSeverity.INFO,
        event_type="device.allowed",
        details={
            "action": "allowed_by_user",
            "decision": "let_run",
            "reason": req.reason,
            "verdict": "SAFE",
            "risk": "None (Authorized by User)",
            "action_taken": "Allowed & Active" if port_enabled else "Allowed in Policy (Admin Required to Re-enable Port)",
            "port_enabled": port_enabled,
            "enforcement_message": enable_msg,
            "summary": f"Device {req.device_id} was permitted to run by user.",
        },
    )
    event_store.add(allow_event)
    await broadcast_telemetry("device_allowed", {"device_id": req.device_id, "reason": req.reason})
    return {
        "status": "allowed",
        "device_id": req.device_id,
        "port_enabled": port_enabled,
        "summary": f"Device {req.device_id} was permitted to run by user.",
    }


@app.get(f"{settings.api_prefix}/devices/connected")
def list_connected_devices() -> list[dict[str, Any]]:
    """Return live inventory of physically connected USB devices."""
    if os.name == "nt":
        try:
            try:
                import pythoncom
                pythoncom.CoInitialize()
            except Exception:
                pass
            from usb_analyzer.device_monitor.windows import WindowsWmiProvider
            from usb_analyzer.device_monitor.monitor import _event_for

            provider = WindowsWmiProvider()
            devs = provider.list_devices()
            return [_event_for(d, connected=True).model_dump(mode="json") for d in devs.values()]
        except Exception as e:
            logger.warning("Could not list connected devices: %s", e)
    return []


class StorageScanRequest(BaseModel):
    volume_path: str | None = None
    device_id: str | None = None


@app.get(f"{settings.api_prefix}/scanner/rules")
def list_scanner_rules() -> dict[str, Any]:
    """Return active YARA rules and hash IOC database metadata."""
    engine = SignatureEngine()
    return {
        "engine_mode": "yara-python + builtin" if engine._has_native_yara else "yara-dsl (.yar parser) + heuristics",
        "rules_dir": str(DEFAULT_RULES_DIR),
        "hash_ioc_count": len(engine.known_hashes),
        "rules": engine.get_rule_inventory(),
    }


@app.post(f"{settings.api_prefix}/storage/scan")
async def scan_usb_storage_volumes(req: StorageScanRequest | None = None) -> dict[str, Any]:
    """Scan specified or all connected USB mass storage volumes with hashes, entropy, magic types & YARA."""
    targets: list[tuple[str, str]] = []

    if req and req.volume_path:
        target_path = Path(req.volume_path)
        if not target_path.exists() or not target_path.is_dir():
            raise HTTPException(status_code=400, detail=f"Storage volume path not accessible: {req.volume_path}")
        dev_id = req.device_id or f"USBSTOR\\VOLUME\\{target_path.drive or target_path.name}"
        targets.append((dev_id, str(target_path)))
    elif os.name == "nt":
        try:
            try:
                import pythoncom
                pythoncom.CoInitialize()
            except Exception:
                pass
            from usb_analyzer.device_monitor.windows import WindowsWmiProvider

            devs = WindowsWmiProvider().list_devices()
            for dev in devs.values():
                for vol in dev.volume_paths:
                    if req and req.device_id and dev.device_id != req.device_id:
                        continue
                    targets.append((dev.device_id, vol))
        except Exception as exc:
            logger.warning("Failed to enumerate Windows USB volumes for scan: %s", exc)
            raise HTTPException(status_code=500, detail=f"Volume enumeration failed: {exc}") from exc

    results: list[dict[str, Any]] = []
    _api_scan_sink.pending_broadcasts.clear()

    for dev_id, vol_path in targets:
        details = storage_scan_service.scan_volume_now(dev_id, vol_path)
        if details:
            results.append({"device_id": dev_id, "volume_path": vol_path, **details})

    for ev in list(_api_scan_sink.pending_broadcasts):
        await broadcast_telemetry("event_added", ev.model_dump(mode="json"))
        ev_details = ev.details or {}
        if ev_details.get("suppress_toast"):
            continue
        if ev.event_type == "device.blocked":
            summary = str(ev_details.get("summary") or ev_details.get("reason") or "Malicious USB threat blocked")
            if ev_details.get("blocked") is False:
                send_desktop_notification(
                    "USB Analyzer — Threat Detected (Elevation Required)",
                    summary,
                    severity="critical",
                    device_id=ev.device_id,
                )
            else:
                send_desktop_notification(
                    "USB Analyzer — Threat Neutralized",
                    summary,
                    severity="critical",
                    device_id=ev.device_id,
                )
        elif ev.event_type == "scan.completed":
            if ev.severity == EventSeverity.CRITICAL:
                send_desktop_notification(
                    "USB Analyzer — Malware Detected",
                    str(ev_details.get("summary") or "Malware signature detected on USB storage"),
                    severity="critical",
                    device_id=ev.device_id,
                )
            elif ev.severity == EventSeverity.WARNING:
                send_desktop_notification(
                    "USB Analyzer — Suspicious USB Files",
                    str(ev_details.get("summary") or "Suspicious files detected on USB storage"),
                    severity="warning",
                    device_id=ev.device_id,
                )
    _api_scan_sink.pending_broadcasts.clear()

    return {
        "status": "ok",
        "volumes_scanned": len(results),
        "files_scanned": sum(int(r.get("files_scanned", 0)) for r in results),
        "new_files_count": sum(int(r.get("new_files_count", 0)) + int(r.get("modified_files_count", 0)) for r in results),
        "flagged_count": sum(int(r.get("flagged_count", 0)) for r in results),
        "max_risk_score": max((int(r.get("max_risk_score", 0)) for r in results), default=0),
        "results": results,
    }


@app.post(f"{settings.api_prefix}/devices/scan")
def scan_and_sync_connected_devices() -> dict[str, Any]:
    """Scan and synchronize all currently connected physical devices into event history."""
    if os.name == "nt":
        try:
            try:
                import pythoncom
                pythoncom.CoInitialize()
            except Exception:
                pass
            from usb_analyzer.device_monitor.windows import WindowsWmiProvider
            from usb_analyzer.device_monitor.monitor import _event_for

            provider = WindowsWmiProvider()
            devs = provider.list_devices()
            existing_events = event_store.list(limit=500)
            existing_ids = {
                e.device_id for e in existing_events if e.event_type == "device.connected"
            }
            added = 0
            for d in devs.values():
                if d.device_id not in existing_ids:
                    ev = _event_for(d, connected=True)
                    event_store.add(ev)
                    added += 1
            return {
                "status": "ok",
                "connected_count": len(devs),
                "added_count": added,
                "devices": [
                    {
                        "device_id": d.device_id,
                        "name": d.name,
                        "device_type": d.device_type,
                        "serial_number": d.serial_number,
                        "volume_paths": list(d.volume_paths),
                    }
                    for d in devs.values()
                ],
            }
        except Exception as e:
            logger.warning("Hardware device scan error: %s", e)
            return {"status": "error", "detail": str(e)}
    return {"status": "unsupported", "detail": "Hardware device scan only supported on Windows host"}


@app.delete(f"{settings.api_prefix}/events", status_code=200)
async def clear_all_events() -> dict[str, int]:
    count = event_store.clear()
    await broadcast_telemetry("events_cleared", {"deleted": count})
    return {"deleted": count}


@app.get(
    f"{settings.api_prefix}/policy/whitelist",
    response_model=list[WhitelistEntry],
)
def list_whitelist() -> list[WhitelistEntry]:
    return whitelist_store.list()


@app.post(
    f"{settings.api_prefix}/policy/whitelist",
    response_model=WhitelistEntry,
    status_code=201,
)
async def add_whitelist_entry(entry: WhitelistEntry) -> WhitelistEntry:
    added = whitelist_store.add(entry)
    await broadcast_telemetry("whitelist_updated")
    return added


@app.delete(
    f"{settings.api_prefix}/policy/whitelist/{{entry_id}}",
    status_code=204,
)
async def delete_whitelist_entry(entry_id: UUID) -> None:
    if not whitelist_store.remove(entry_id):
        raise HTTPException(status_code=404, detail="Whitelist entry not found")
    await broadcast_telemetry("whitelist_updated")


@app.get(f"{settings.api_prefix}/policy/status")
def get_policy_status() -> dict[str, object]:
    global current_policy_mode
    persisted = whitelist_store.get_policy_mode()
    if persisted is not None:
        current_policy_mode = persisted
        policy_engine.mode = persisted
    entries = whitelist_store.list()
    return {
        "mode": current_policy_mode.value,
        "whitelist_count": len(entries),
    }


@app.get(f"{settings.api_prefix}/reports/incident/pdf")
def export_incident_report_pdf() -> Response:
    events = event_store.list(limit=500)
    whitelist = whitelist_store.list()
    pdf_bytes = generate_incident_pdf(
        events=events,
        whitelist=whitelist,
        policy_mode=current_policy_mode.value,
    )
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": 'attachment; filename="usb_analyzer_incident_report.pdf"'},
    )


@app.get(f"{settings.api_prefix}/reports/events.csv")
def export_events_csv() -> Response:
    events = event_store.list(limit=500)
    output = io.StringIO()
    output.write("\ufeff")  # UTF-8 BOM for direct Microsoft Excel compatibility
    writer = csv.writer(output)
    writer.writerow([
        "Event ID",
        "Record Type",
        "Timestamp (UTC)",
        "Severity",
        "Verdict",
        "Event Type",
        "Subsystem Source",
        "Device Name",
        "Device ID",
        "Vendor ID",
        "Product ID",
        "Serial Number",
        "Volume / File Path",
        "File Type",
        "Entropy (b/B)",
        "Risk Score",
        "SHA-256",
        "MD5",
        "Indicators / YARA Rules",
        "Reason / Risk",
        "Action Taken",
        "Details JSON",
    ])
    identity_lookup = build_device_identity_lookup(events)
    for ev in events:
        details = ev.details or {}
        verdict, reason, action = classify_event_verdict(ev)
        vid, pid, serial = extract_usb_ids(ev.device_id, details)
        dev_name = extract_device_name(ev.device_id, details)
        if vid == "N/A" or pid == "N/A":
            base_sn = serial.split("&")[0].lower() if serial != "N/A" else ""
            fallback = identity_lookup.get(ev.device_id.lower()) or (identity_lookup.get(f"sn:{base_sn}") if base_sn else None)
            if fallback:
                fb_name, fb_vid, fb_pid, fb_serial = fallback
                if dev_name in ("USB Mass Storage Drive", "USB Peripheral", "USB HID Peripheral"):
                    dev_name = fb_name
                if vid == "N/A":
                    vid = fb_vid
                if pid == "N/A":
                    pid = fb_pid
                if fb_serial != "N/A" and "&" in serial:
                    serial = fb_serial
        vol_or_path = str(details.get("volume_path") or details.get("mount_point") or details.get("path") or "")

        ev_file_type = str(details.get("file_type") or "")
        ev_entropy = f"{float(details['entropy']):.2f}" if "entropy" in details else ""
        ev_risk = ""
        if "risk_score" in details:
            ev_risk = f"{int(details['risk_score'])}/100"
        elif ev.event_type == "scan.completed" and "max_risk_score" in details:
            ev_risk = f"{int(details['max_risk_score'])}/100"

        ev_sha256 = str(details.get("sha256") or "")
        ev_md5 = str(details.get("md5") or "")
        if ev.event_type == "scan.completed":
            ev_indicators = f"Scanned {int(details.get('files_scanned', 0))}, Flagged {int(details.get('flagged_count', 0))}"
        elif isinstance(details.get("flags"), list):
            ev_indicators = ", ".join(str(x) for x in details["flags"])
        elif isinstance(details.get("flagged_files"), list):
            ev_indicators = "; ".join(str(x) for x in details["flagged_files"])
        else:
            ev_indicators = ""

        writer.writerow([
            csv_safe_cell(ev.id),
            "EVENT",
            csv_safe_cell(ev.time.isoformat()),
            csv_safe_cell(ev.severity.value.upper()),
            csv_safe_cell(verdict),
            csv_safe_cell(ev.event_type),
            csv_safe_cell(ev.source),
            csv_safe_cell(dev_name),
            csv_safe_cell(ev.device_id),
            csv_safe_cell(vid),
            csv_safe_cell(pid),
            csv_safe_cell(serial),
            csv_safe_cell(vol_or_path),
            csv_safe_cell(ev_file_type),
            csv_safe_cell(ev_entropy),
            csv_safe_cell(ev_risk),
            csv_safe_cell(ev_sha256),
            csv_safe_cell(ev_md5),
            csv_safe_cell(ev_indicators),
            csv_safe_cell(reason),
            csv_safe_cell(action),
            csv_safe_cell(json.dumps(details, sort_keys=True)),
        ])

        if ev.event_type == "scan.completed":
            analyses = details.get("file_analyses") or details.get("flagged") or []
            if isinstance(analyses, list):
                sorted_files = sorted(
                    (f for f in analyses if isinstance(f, dict)),
                    key=lambda item: (-int(item.get("risk_score", 0)), str(item.get("path", ""))),
                )
                for item in sorted_files:
                    score = int(item.get("risk_score", 0))
                    fverdict = (
                        "CRITICAL" if score >= 80
                        else ("HIGH" if score >= 50 else ("SUSPICIOUS" if score >= 20 else "CLEAN"))
                    )
                    fsev = "CRITICAL" if score >= 50 else ("WARNING" if score >= 20 else "INFO")
                    meta = item.get("metadata") or {}
                    ftype = str(item.get("file_type") or "Unknown")
                    if meta.get("extension_mismatch"):
                        ftype = f"{ftype} [Mismatch: {meta.get('extension', '')}]"
                    fpath = str(item.get("path") or "")
                    full_loc = f"{vol_or_path.rstrip('\\/')}\\{fpath}" if vol_or_path and fpath else (fpath or vol_or_path)
                    flags = [str(x) for x in (item.get("flags") or [])]
                    freason = "; ".join(flags) if flags else "Clean storage file"
                    writer.writerow([
                        csv_safe_cell(ev.id),
                        "FILE",
                        csv_safe_cell(ev.time.isoformat()),
                        csv_safe_cell(fsev),
                        csv_safe_cell(fverdict),
                        "storage.file_analysis",
                        "storage-scanner",
                        csv_safe_cell(dev_name),
                        csv_safe_cell(ev.device_id),
                        csv_safe_cell(vid),
                        csv_safe_cell(pid),
                        csv_safe_cell(serial),
                        csv_safe_cell(full_loc),
                        csv_safe_cell(ftype),
                        csv_safe_cell(f"{float(item.get('entropy', 0.0)):.2f}"),
                        csv_safe_cell(f"{score}/100"),
                        csv_safe_cell(item.get("sha256") or ""),
                        csv_safe_cell(item.get("md5") or ""),
                        csv_safe_cell(", ".join(flags)),
                        csv_safe_cell(freason),
                        "FLAGGED" if score >= 20 else "CLEAN",
                        csv_safe_cell(json.dumps(meta, sort_keys=True)),
                    ])

    return Response(
        content=output.getvalue(),
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": 'attachment; filename="usb_forensic_audit_events.csv"'},
    )


@app.get(f"{settings.api_prefix}/reports/events.json")
def export_events_json() -> Response:
    events = event_store.list(limit=500)
    data = [ev.model_dump(mode="json") for ev in events]
    return Response(
        content=json.dumps(data, indent=2),
        media_type="application/json",
        headers={"Content-Disposition": 'attachment; filename="usb_forensic_audit_events.json"'},
    )


@app.post(f"{settings.api_prefix}/policy/mode")
async def update_policy_mode(req: PolicyModeUpdateRequest) -> dict[str, str]:
    global current_policy_mode
    current_policy_mode = whitelist_store.set_policy_mode(req.mode)
    policy_engine.mode = current_policy_mode
    await broadcast_telemetry("policy_updated", {"mode": current_policy_mode.value})
    return {"mode": current_policy_mode.value}


@app.get(f"{settings.api_prefix}/analytics/activity")
def get_activity_analytics(
    time_range: str = Query("1h", alias="range", pattern="^(1h|24h|7d|30d)$"),
) -> dict[str, Any]:
    events = event_store.list(limit=1000)
    now = datetime.now(timezone.utc)

    if time_range == "1h":
        bucket_count = 6
        step = timedelta(minutes=10)
        window_start = now - timedelta(hours=1)
        labels = [
            (window_start + step * (i + 1)).astimezone().strftime("%H:%M")
            for i in range(bucket_count)
        ]
    elif time_range == "24h":
        bucket_count = 8
        step = timedelta(hours=3)
        window_start = now - timedelta(hours=24)
        labels = [
            (window_start + step * (i + 1)).astimezone().strftime("%H:%M")
            for i in range(bucket_count)
        ]
    elif time_range == "7d":
        bucket_count = 7
        step = timedelta(days=1)
        window_start = now - timedelta(days=7)
        labels = [
            (window_start + step * (i + 1)).astimezone().strftime("%a")
            for i in range(bucket_count)
        ]
    else:  # 30d
        bucket_count = 4
        step = timedelta(days=7.5)
        window_start = now - timedelta(days=30)
        labels = [f"Week {i + 1}" for i in range(bucket_count)]

    buckets = [0] * bucket_count
    total_events = 0
    suspicious_events = 0
    step_seconds = step.total_seconds()

    for ev in events:
        ev_time = ev.time if ev.time.tzinfo else ev.time.replace(tzinfo=timezone.utc)
        if ev_time < window_start:
            continue
        total_events += 1
        if ev.severity in (EventSeverity.WARNING, EventSeverity.CRITICAL):
            suspicious_events += 1
        elapsed = max(0.0, (ev_time - window_start).total_seconds())
        idx = min(bucket_count - 1, int(elapsed // step_seconds))
        buckets[idx] += 1

    return {
        "range": time_range,
        "labels": labels,
        "data": buckets,
        "total_events": total_events,
        "suspicious_events": suspicious_events,
    }


class BadUsbSimulationRequest(BaseModel):
    device_id: str = "USB\\VID_1B4F&PID_9206\\BADUSB_ATTACKER"
    device_name: str = "SparkFun Pro Micro (BadUSB Simulation)"
    char_count: int = 30
    delay_ms: float = 5.0


@app.post(f"{settings.api_prefix}/simulate/badusb")
async def simulate_badusb(req: BadUsbSimulationRequest) -> dict[str, Any]:
    hid_detector.register_hid_device(req.device_id, req.device_name)
    alert = hid_detector.simulate_injection(
        char_count=req.char_count,
        delay_per_char_seconds=req.delay_ms / 1000.0,
    )
    await broadcast_telemetry("badusb_simulated", {"detected": alert is not None})
    return {
        "status": "simulated",
        "detected": alert is not None,
        "summary": alert.summary if alert else "Typing speed did not trigger threshold",
    }


class ScenarioSimulationRequest(BaseModel):
    scenario: str  # "safe_usb", "badusb", "malware_drive", "unauthorized_device", "spoofed_identity"


@app.post(f"{settings.api_prefix}/simulate/scenario")
async def simulate_scenario(req: ScenarioSimulationRequest) -> dict[str, Any]:
    scenario = req.scenario.strip().lower()

    if scenario == "safe_usb":
        # 1. Trusted Drive -> Allowed & Logged
        serial = "CORP_DRIVE_001"
        vid = "0951"
        pid = "1666"
        device_id = f"USB\\VID_{vid}&PID_{pid}\\{serial}"

        if not whitelist_store.find_match(serial_number=serial):
            whitelist_store.add(
                WhitelistEntry(
                    name="Corporate Secure Flash Drive",
                    serial_number=serial,
                    vendor_id=vid,
                    product_id=pid,
                    notes="Pre-approved corporate USB storage",
                )
            )

        event_store.add(
            DeviceEvent(
                device_id=device_id,
                source="device-monitor",
                severity=EventSeverity.INFO,
                event_type="device.connected",
                details={
                    "name": "Kingston DataTraveler (Corporate Whitelisted)",
                    "vendor_id": vid,
                    "product_id": pid,
                    "serial_number": serial,
                    "device_type": "Mass Storage (Storage)",
                },
            )
        )

        decision, events = policy_engine.evaluate_device(
            device_id=device_id,
            serial_number=serial,
            vendor_id=vid,
            product_id=pid,
        )
        for ev in events:
            event_store.add(ev)

        event_store.add(
            DeviceEvent(
                device_id=device_id,
                source="storage-scanner",
                severity=EventSeverity.INFO,
                event_type="scan.completed",
                details={
                    "summary": "Storage integrity verified clean. 0 threats detected across 16 files.",
                    "clean_files": 16,
                    "threat_count": 0,
                    "status": "clean",
                },
            )
        )
        await broadcast_telemetry("scenario_simulated", {"scenario": "safe_usb"})
        return {
            "status": "simulated",
            "scenario": "safe_usb",
            "outcome": "allowed",
            "summary": "Safe USB Drive connected and verified against corporate whitelist. Integrity clean — full access granted.",
        }

    elif scenario == "badusb":
        # 2. BadUSB Keystroke Injection (Rubber Ducky)
        device_id = "USB\\VID_16C0&PID_05DF\\DIGISPARK_ATTACKER_001"
        event_store.add(
            DeviceEvent(
                device_id=device_id,
                source="device-monitor",
                severity=EventSeverity.INFO,
                event_type="device.connected",
                details={
                    "name": "Digispark USB HID Keyboard (Disguised BadUSB)",
                    "vendor_id": "16C0",
                    "product_id": "05DF",
                    "device_type": "Human Interface Device (HID)",
                },
            )
        )
        hid_detector.register_hid_device(device_id, "Digispark BadUSB Attacker")
        alert = hid_detector.simulate_injection(char_count=35, delay_per_char_seconds=0.003)
        send_desktop_notification(
            "USB Analyzer — Threat Neutralized",
            "BadUSB keystroke injection intercepted. Action taken: Hardware port disabled.",
            severity="critical",
            device_id=device_id,
        )
        await broadcast_telemetry("threat_alert", {"scenario": "badusb", "device_id": device_id})
        return {
            "status": "simulated",
            "scenario": "badusb",
            "outcome": "blocked" if current_policy_mode == PolicyMode.ENFORCE else "audit_warning",
            "summary": alert.summary if alert else "BadUSB keystroke injection simulated.",
        }

    elif scenario == "malware_drive":
        # 3. Infected Storage Drive (Trojan Dropper & autorun.inf) -> Blocked
        device_id = "USBSTOR\\DISK&VEN_EVIL&PROD_USB\\INFECTED_SN_001&0"
        event_store.add(
            DeviceEvent(
                device_id=device_id,
                source="device-monitor",
                severity=EventSeverity.INFO,
                event_type="device.connected",
                details={
                    "name": "SanDisk Cruzer (Malware Infected Media)",
                    "vendor_id": "0781",
                    "product_id": "5567",
                    "device_type": "Mass Storage (Storage)",
                },
            )
        )
        event_store.add(
            DeviceEvent(
                device_id=device_id,
                source="storage-scanner",
                severity=EventSeverity.INFO,
                event_type="scan.started",
                details={
                    "device_id": device_id,
                    "mount_point": "E:\\",
                    "summary": "Storage scan initiated for newly attached volume E:\\",
                },
            )
        )
        event_store.add(
            DeviceEvent(
                device_id=device_id,
                source="storage-scanner",
                severity=EventSeverity.CRITICAL,
                event_type="scan.threat_detected",
                details={
                    "device_id": device_id,
                    "mount_point": "E:\\",
                    "threat_type": "trojan_autorun",
                    "flagged_files": [
                        "E:\\autorun.inf (Suspicious Autorun.inf)",
                        "E:\\svchost_trojan.exe (Trojan_Dropper.exe)",
                    ],
                    "summary": "High-severity malware signature and malicious autorun detected on storage volume.",
                },
            )
        )
        _, block_ev = policy_engine.block_threat(
            device_id=device_id,
            reason="Malware infection: Trojan dropper & unauthorized autorun script present on storage volume",
            threat_type="malware_infection",
            details={"action": "quarantine_and_block", "volume": "E:\\"},
        )
        event_store.add(block_ev)
        send_desktop_notification(
            "USB Analyzer — Threat Neutralized",
            "Malware trojan dropper intercepted. Action taken: Storage volume quarantined & blocked.",
            severity="critical",
            device_id=device_id,
        )
        await broadcast_telemetry("threat_alert", {"scenario": "malware_drive", "device_id": device_id})
        return {
            "status": "simulated",
            "scenario": "malware_drive",
            "outcome": "blocked",
            "summary": "Infected drive detected! Trojan dropper and autorun.inf found. Hardware blocked & volume quarantined.",
        }

    elif scenario == "unauthorized_device":
        # 4. Unknown / Rogue USB Device (Suspicious -> Default Blocked in Containment until user allows)
        device_id = "USB\\VID_9999&PID_8888\\UNAUTHORIZED_SN_999"
        event_store.add(
            DeviceEvent(
                device_id=device_id,
                source="device-monitor",
                severity=EventSeverity.INFO,
                event_type="device.connected",
                details={
                    "name": "Rogue USB Peripheral (Unknown Hardware)",
                    "vendor_id": "9999",
                    "product_id": "8888",
                    "serial_number": "UNAUTHORIZED_SN_999",
                    "device_type": "Unrecognized USB Peripheral",
                    "verdict": "WARNING",
                    "risk": "Unrecognized Peripheral (Contained)",
                    "action_taken": "Contained (Blocked until Allowed)",
                    "summary": "Unrecognized USB peripheral connected. Held in zero-trust containment until user authorization.",
                },
            )
        )
        event_store.add(
            DeviceEvent(
                device_id=device_id,
                source="policy-engine",
                severity=EventSeverity.WARNING,
                event_type="device.suspicious",
                details={
                    "action": "containment_block",
                    "verdict": "WARNING",
                    "risk": "Unrecognized Peripheral (Contained)",
                    "action_taken": "Contained (Blocked until Allowed)",
                    "reason": "Suspicious unregistered hardware detected. Held in zero-trust containment (blocked) until explicitly authorized by operator.",
                    "violation": "unregistered_hardware_detected",
                    "summary": "Suspicious USB peripheral held in zero-trust containment (blocked) until user explicitly authorizes it to run.",
                },
            )
        )
        send_desktop_notification(
            "USB Analyzer — Suspicious Device Contained",
            "Unrecognized hardware held in zero-trust containment (blocked). Review in dashboard to authorize.",
            severity="warning",
            device_id=device_id,
        )
        await broadcast_telemetry("device_contained", {"scenario": "unauthorized_device", "device_id": device_id})
        return {
            "status": "simulated",
            "scenario": "unauthorized_device",
            "outcome": "warning",
            "summary": "Suspicious device detected: Unregistered USB hardware placed in zero-trust containment (blocked) until user authorizes.",
        }

    elif scenario == "spoofed_identity":
        # 5. Spoofed Identity Attack (VID/PID Clone) -> Blocked
        if not whitelist_store.find_match(vendor_id="1050", product_id="0407"):
            whitelist_store.add(
                WhitelistEntry(
                    name="Security Admin YubiKey 5 NFC",
                    vendor_id="1050",
                    product_id="0407",
                    serial_number="AUTHENTIC_YUBI_7701",
                    notes="Registered IT Security Hardware Token",
                )
            )

        cloned_serial = "CLONED_MALICIOUS_SN_99"
        device_id = f"USB\\VID_1050&PID_0407\\{cloned_serial}"

        event_store.add(
            DeviceEvent(
                device_id=device_id,
                source="device-monitor",
                severity=EventSeverity.INFO,
                event_type="device.connected",
                details={
                    "name": "YubiKey 5 NFC (Cloned Attacker Hardware)",
                    "vendor_id": "1050",
                    "product_id": "0407",
                    "serial_number": cloned_serial,
                    "device_type": "Smart Card / Security Key",
                },
            )
        )

        spoofed_fp = DeviceFingerprint(
            vendor_id="1050",
            product_id="0407",
            serial_number=cloned_serial,
            friendly_name="YubiKey 5 NFC (Cloned Attacker Hardware)",
        )
        is_spoofed, reason, details = detect_spoofed_identity(spoofed_fp, whitelist_store.list())

        if is_spoofed:
            event_store.add(
                DeviceEvent(
                    device_id=device_id,
                    source="device-monitor",
                    severity=EventSeverity.CRITICAL,
                    event_type="device.spoofed_identity",
                    details=details,
                )
            )
            _, block_ev = policy_engine.block_threat(
                device_id=device_id,
                reason=reason or "Spoofed hardware identity",
                threat_type="spoofed_identity",
            )
            event_store.add(block_ev)
            send_desktop_notification(
                "USB Analyzer — Threat Neutralized",
                "Hardware identity spoofing detected. Action taken: Hardware port isolated.",
                severity="critical",
                device_id=device_id,
            )
            summary = f"Identity Spoofing detected! Cloned VID 1050:PID 0407 with unauthorized serial '{cloned_serial}'. Hardware completely blocked."
        else:
            summary = "Spoof check did not trigger."

        await broadcast_telemetry("threat_alert", {"scenario": "spoofed_identity", "device_id": device_id})
        return {
            "status": "simulated",
            "scenario": "spoofed_identity",
            "outcome": "blocked",
            "summary": summary,
        }

    else:
        raise HTTPException(
            status_code=400,
            detail=f"Unknown simulation scenario: {scenario}. Available: safe_usb, badusb, malware_drive, unauthorized_device, spoofed_identity",
        )


