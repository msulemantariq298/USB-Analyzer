from pathlib import Path
from typing import Any
from uuid import UUID

from fastapi import FastAPI, HTTPException, Query, Response
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from usb_analyzer.core.config import get_settings
from usb_analyzer.core.database import EventStore
from usb_analyzer.core.events import DeviceEvent, EventSeverity
from usb_analyzer.hid_detector.detector import BadUsbDetector
from usb_analyzer.policy.engine import PolicyEngine
from usb_analyzer.policy.enforcement import get_platform_blocker
from usb_analyzer.policy.models import PolicyMode, WhitelistEntry
from usb_analyzer.policy.store import WhitelistStore
from usb_analyzer.reports.incident_pdf import generate_incident_pdf

settings = get_settings()
event_store = EventStore(settings.database_path)
whitelist_store = WhitelistStore(settings.database_path)
current_policy_mode = PolicyMode(settings.policy_mode)
policy_engine = PolicyEngine(
    store=whitelist_store,
    blocker=get_platform_blocker(dry_run=True),
    mode=current_policy_mode,
)
hid_detector = BadUsbDetector(event_sink=event_store, policy_engine=policy_engine)

app = FastAPI(title=settings.app_name, version="0.1.0")


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


@app.get("/", include_in_schema=False)
def dashboard() -> FileResponse:
    return FileResponse(static_directory / "index.html")


@app.get(f"{settings.api_prefix}/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


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
def create_event(event: DeviceEvent) -> DeviceEvent:
    return event_store.add(event)


@app.delete(f"{settings.api_prefix}/events", status_code=200)
def clear_all_events() -> dict[str, int]:
    count = event_store.clear()
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
def add_whitelist_entry(entry: WhitelistEntry) -> WhitelistEntry:
    return whitelist_store.add(entry)


@app.delete(
    f"{settings.api_prefix}/policy/whitelist/{{entry_id}}",
    status_code=204,
)
def delete_whitelist_entry(entry_id: UUID) -> None:
    if not whitelist_store.remove(entry_id):
        raise HTTPException(status_code=404, detail="Whitelist entry not found")


@app.get(f"{settings.api_prefix}/policy/status")
def get_policy_status() -> dict[str, object]:
    global current_policy_mode
    entries = whitelist_store.list()
    return {
        "mode": current_policy_mode.value,
        "whitelist_count": len(entries),
    }


@app.get(f"{settings.api_prefix}/reports/incident/pdf")
def export_incident_report_pdf() -> Response:
    events = event_store.list(limit=200)
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


@app.post(f"{settings.api_prefix}/policy/mode")
def update_policy_mode(req: PolicyModeUpdateRequest) -> dict[str, str]:
    global current_policy_mode
    current_policy_mode = req.mode
    policy_engine.mode = current_policy_mode
    return {"mode": current_policy_mode.value}


class BadUsbSimulationRequest(BaseModel):
    device_id: str = "USB\\VID_1B4F&PID_9206\\BADUSB_ATTACKER"
    device_name: str = "SparkFun Pro Micro (BadUSB Simulation)"
    char_count: int = 30
    delay_ms: float = 5.0


@app.post(f"{settings.api_prefix}/simulate/badusb")
def simulate_badusb(req: BadUsbSimulationRequest) -> dict[str, Any]:
    hid_detector.register_hid_device(req.device_id, req.device_name)
    alert = hid_detector.simulate_injection(
        char_count=req.char_count,
        delay_per_char_seconds=req.delay_ms / 1000.0,
    )
    return {
        "status": "simulated",
        "detected": alert is not None,
        "summary": alert.summary if alert else "Typing speed did not trigger threshold",
    }


