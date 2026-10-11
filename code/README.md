# USB Analyzer

Shared project foundation and Week 1 dashboard for the cross-platform USB security analyzer described in the proposal.

## Current setup

- FastAPI application with health and event endpoints
- Browser dashboard with event summary, audit table, and demo event button
- SQLite event store
- Shared JSON event contract for all modules
- Configuration through environment variables or `.env`
- Pytest starter tests
- OS-specific integrations intentionally kept outside the core

## Requirements

- Python 3.11 or newer
- Windows 10/11 or Ubuntu Linux

## Setup

The recommended layout keeps the virtual environment in the project root and the Python package in `code`:

```terminal
cd "D:\3rd Semester\Information Secuirity\USB Analyzer"
py -m venv venv
venv\Scripts\Activate
cd code
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
Copy-Item .env.example .env
```

On Linux, create `.venv` in the project root with `python3.11 -m venv .venv`, activate it, then run the installation commands from `code`.

## Run the API

```terminal
python -m uvicorn usb_analyzer.api.main:app --reload
```

The API will be available at `http://127.0.0.1:8000`.

- `GET /` — dashboard
- `GET /api/v1/health`
- `GET /api/v1/events`
- `POST /api/v1/events`
- `GET /docs`

Open `http://127.0.0.1:8000/` for the dashboard. The **Simulate USB event** button creates a warning event using the frozen Week 1 contract, so the UI can be developed before the platform monitors are implemented.

## Run tests

```terminal
python -m pytest
```

## Shared event contract

Every module should emit a `DeviceEvent` with:

- `time`: UTC timestamp
- `device_id`: stable device identifier where available
- `source`: module that produced the event
- `severity`: `info`, `warning`, or `critical`
- `event_type`: event name such as `device.connected`
- `details`: structured event-specific data

The contract is defined in `usb_analyzer/core/events.py`. Keep module-specific data inside `details` rather than adding incompatible top-level fields.

## Week 1 status

- Project structure and local setup: complete
- Shared event interface and JSON format: complete
- Basic web UI and API wiring: complete
- Library spike: complete for FastAPI, Pydantic Settings, SQLite, and Pytest
- GitHub repository initialized by the project owner
