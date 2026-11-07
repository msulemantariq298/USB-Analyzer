from pathlib import Path
from uuid import UUID

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from usb_analyzer.core.config import get_settings
from usb_analyzer.core.database import EventStore
from usb_analyzer.core.events import DeviceEvent
from usb_analyzer.policy.models import PolicyMode, WhitelistEntry
from usb_analyzer.policy.store import WhitelistStore

settings = get_settings()
event_store = EventStore(settings.database_path)
whitelist_store = WhitelistStore(settings.database_path)
current_policy_mode = PolicyMode(settings.policy_mode)

app = FastAPI(title=settings.app_name, version="0.1.0")
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


@app.post(f"{settings.api_prefix}/policy/mode")
def update_policy_mode(req: PolicyModeUpdateRequest) -> dict[str, str]:
    global current_policy_mode
    current_policy_mode = req.mode
    return {"mode": current_policy_mode.value}

