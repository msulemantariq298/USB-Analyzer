from pathlib import Path

from fastapi import FastAPI, Query
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from usb_analyzer.core.config import get_settings
from usb_analyzer.core.database import EventStore
from usb_analyzer.core.events import DeviceEvent

settings = get_settings()
event_store = EventStore(settings.database_path)

app = FastAPI(title=settings.app_name, version="0.1.0")
static_directory = Path(__file__).parent / "static"
app.mount("/static", StaticFiles(directory=static_directory), name="static")


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
