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
- The Windows monitor posts detected events to the FastAPI API; the API persists them for the dashboard.
- Dashboard event history, severity counts, and simulated event control.

Not yet implemented or fully validated:

- Durable offline event queuing and automatic retries if the API is unavailable.
- The monitor/API are started manually; background service and automatic startup are not implemented.
- File scanning, malware/YARA signatures, HID/BadUSB behavior analysis, notifications, incident reports, quarantine/remediation, and device blocking.
- Linux USB monitoring.
- Hands-on confirmation of connect/disconnect detection with representative devices. A successful WMI inventory query only verifies device enumeration.

**Contributor/agent instruction:** Whenever code changes affect behavior, setup, run commands, dependencies, or project status, update this guide and the repository-root `README.md` in the same change. Clearly label planned behavior versus behavior that is implemented and tested.

## Current setup

- FastAPI application with health and event endpoints
- Initial Windows WMI USB inventory monitor (sends events through the API)
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

The recommended layout keeps the virtual environment in the repository root and the Python package in `code`. From the repository root in PowerShell (skip venv creation if it already exists):

```powershell
cd "D:\3rd Semester\Information Secuirity\USB Analyzer"
py -m venv venv
.\venv\Scripts\Activate.ps1
Set-Location code
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
if (-not (Test-Path .env)) { Copy-Item .env.example .env }
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

The API currently has no authentication and is intended for local use only. Keep Uvicorn bound to its default loopback address; do not expose it to an untrusted network.

## Windows USB device monitor (initial prototype)

The Windows monitor uses WMI to inventory present USB Plug and Play devices. It compares inventories and posts `device.connected` and `device.disconnected` events to the FastAPI API; the API writes accepted events to SQLite. It starts with a baseline, so devices already plugged in when monitoring begins are not reported as new connections.

Run the API and monitor in separate terminals. Start the API first. In each terminal, start from the repository root, activate the environment, and change into `code`.

**Terminal 1 — API and dashboard:**

```powershell
.\venv\Scripts\Activate.ps1
Set-Location code
python -m uvicorn usb_analyzer.api.main:app --reload
```

**Terminal 2 — Windows USB monitor:**

```powershell
.\venv\Scripts\Activate.ps1
Set-Location code
python -m usb_analyzer.device_monitor.windows
```

Open `http://127.0.0.1:8000/` to view events. Start the monitor before plugging in the device you want to test: its first inventory establishes a baseline and is not reported as a set of new connections. Detected changes are sent to the API and stored in the API's SQLite database. Both processes should run from `code` so they read the same `.env` file. Configure the API origin with `USB_ANALYZER_API_BASE_URL` (default `http://127.0.0.1:8000`) and the request timeout with `USB_ANALYZER_API_TIMEOUT_SECONDS` (default 5 seconds). The monitor accepts `--interval 0.5` to check more frequently; detection latency also depends on WMI query time.

If the API is unreachable, times out, or returns an error, the monitor logs the failed request and exits instead of silently discarding the event. Restart the API and then restart the monitor. Local offline queuing and automatic retry are not implemented.

This initial backend reports USB and USB storage PnP instances only. It does not yet inspect file contents, detect keystroke injection, or block devices. Linux monitoring and automated Windows startup are future work.

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
- Windows monitor-to-API event delivery: implemented; offline queue/retry not implemented
- Background service and automatic startup: not implemented
- Storage scanning and threat detection: not implemented
- HID/BadUSB detection: not implemented
- User notifications, reports, and threat quarantine/remediation: not implemented
- Linux monitor: not implemented
- GitHub repository initialized by the project owner
