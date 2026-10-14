# USB Analyzer — Project Guide

## Intended product and final outcome

USB Analyzer is intended to be a background Python application for Windows and Linux, with a local web dashboard as the interface. The monitoring agent should start automatically with the computer, detect USB connections, collect device identity/details, check for supported security risks, and send device and scan results to the web application through its API. Users should be able to review device history, findings, alerts, and incident reports in the dashboard.

The intended threat workflow is: detect a possible threat, notify the user, and safely contain or remediate confirmed threats. Prefer quarantine and an auditable action over silent deletion. Detection is limited to the scanners, signatures, and rules implemented by this project; do not describe it as guaranteed virus detection or a replacement for a full antivirus product.

```text
USB connection
    -> background agent detects and fingerprints device
    -> supported storage/HID/security checks
    -> agent sends events and results to the API
    -> API stores the audit history
    -> dashboard presents history, findings, alerts, and reports
    -> user reviews and authorizes safe remediation when needed
```

## Current implementation status

This is an early prototype. The final workflow above is **not yet implemented end to end**.

Implemented:

- FastAPI API, SQLite event store, shared `DeviceEvent` contract, and browser dashboard.
- Windows WMI inventory monitor for USB and USB-storage Plug and Play devices.
- Inventory comparison that can create connection/disconnection events.
- Dashboard event history, severity counts, and simulated event control.

Not yet implemented or fully validated:

- The monitor currently writes directly to SQLite; it does not send events through the API.
- The monitor/API are started manually; background service and automatic startup are not implemented.
- File scanning, malware/YARA signatures, HID/BadUSB behavior analysis, notifications, incident reports, quarantine/remediation, and device blocking.
- Linux USB monitoring.
- Hands-on confirmation of connect/disconnect detection with representative devices. A successful WMI inventory query only verifies device enumeration.

**Contributor/agent instruction:** Whenever code changes affect behavior, setup, run commands, dependencies, or project status, update this guide and the repository-root `README.md` in the same change. Clearly label planned behavior versus behavior that is implemented and tested.

## Current setup

- FastAPI application with health and event endpoints
- Initial Windows WMI USB inventory monitor (currently persists directly to SQLite)
- Browser dashboard with event summary, audit table, and demo event button
- SQLite event store
- Shared JSON event contract for all modules
- Configuration through environment variables or `.env`
- Pytest starter tests
- OS-specific monitoring code is separated from the shared event/API core

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

## Windows USB device monitor (initial prototype)

The Windows monitor uses WMI to inventory present USB Plug and Play devices. It compares inventories and writes `device.connected` and `device.disconnected` events to the same SQLite database used by the API. It starts with a baseline, so devices already plugged in when monitoring begins are not reported as new connections.

Run the monitor in a separate terminal from the API. In each terminal, start from the repository root, activate the environment, and change into `code`:

```powershell
.\venv\Scripts\Activate.ps1
Set-Location code
python -m usb_analyzer.device_monitor.windows
```

In the other terminal, use the same activation and directory commands, then start the API:

```powershell
.\venv\Scripts\Activate.ps1
Set-Location code
python -m uvicorn usb_analyzer.api.main:app --reload
```

Open `http://127.0.0.1:8000/` to view events. Start the monitor before plugging in the device you want to test: its first inventory establishes a baseline and is not reported as a set of new connections. Subsequent USB device changes are stored in SQLite. Run both processes with `code` as the working directory so they load the same `.env` and default database, `code/data/usb_analyzer.db`. Set `USB_ANALYZER_DATABASE_PATH` in `code/.env` to use a different database path. The monitor accepts `--interval 0.5` to check more frequently; detection latency also depends on WMI query time.

This initial backend reports USB and USB storage PnP instances only. It does not yet inspect file contents, detect keystroke injection, send events over HTTP to the API, or block devices. Linux monitoring and automated Windows startup are future work.

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

## Project status

- Project structure and local setup: implemented
- Shared event interface and JSON format: implemented
- Basic web UI and API: implemented
- SQLite event persistence: implemented
- Windows WMI USB inventory monitor: implemented; representative plug/unplug testing still required
- Background service and automatic startup: not implemented
- Agent-to-API event delivery: not implemented
- Storage scanning and threat detection: not implemented
- HID/BadUSB detection: not implemented
- User notifications, reports, and threat quarantine/remediation: not implemented
- Linux monitor: not implemented
- GitHub repository initialized by the project owner
