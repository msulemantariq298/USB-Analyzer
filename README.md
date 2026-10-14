# USB Analyzer

USB Analyzer is intended to be a background USB security application for Windows and Linux, with a local web dashboard as its user interface.

## Product goal

The finished application should run a Python monitoring agent in the background and start it automatically with the computer. When a USB device is connected, the agent should detect it, collect its identity and device details, inspect it for supported security risks, and send the results to the web application through its API. The dashboard should let a user review what connected and when, see scan results and alerts, and access incident reports.

For detected threats, the intended workflow is to notify the user and safely contain or remediate confirmed threats. Prefer quarantine and an auditable action over silently deleting files. Detection depends on the scanners, signatures, and rules available; this project must not claim to detect every virus or replace a full antivirus product.

Target flow:

```text
USB device connected
        -> background agent detects and fingerprints device
        -> storage/HID/security checks run
        -> agent sends device and scan events to the local API
        -> API stores the audit history
        -> dashboard shows device details, findings, alerts, and reports
        -> user reviews and authorizes safe remediation when needed
```

## Current implementation status

This is an early prototype, not yet the finished always-on protection system:

- The FastAPI API, SQLite event store, shared `DeviceEvent` model, and browser dashboard exist.
- The Windows monitor uses WMI polling to inventory USB and USB-storage Plug and Play devices. It can compare inventories and generate connect/disconnect events.
- The monitor currently writes directly to SQLite; it does **not** yet send events to the API.
- The monitor and web server must be started manually in separate terminals. Automatic startup/background service support is not implemented.
- The dashboard can show stored events and create a simulated event for UI testing.
- File scanning, malware signatures/YARA rules, HID/BadUSB behavior detection, user notifications, incident reports, quarantine/remediation, USB blocking, and Linux monitoring are not implemented.
- Real plug/unplug event handling still needs hands-on validation. WMI inventory access has been tested on Windows, but that alone does not verify the full detection workflow.

Contributors and coding agents: keep the distinction between the product goal and implemented behavior explicit. **Update this README and `code/README.md` in the same change whenever implementation, setup, run commands, or project status changes.**

## Setup (Windows)

From the repository root in PowerShell:

```powershell
py -m venv venv  # Skip if the environment already exists
.\venv\Scripts\Activate.ps1
Set-Location code
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
if (-not (Test-Path .env)) { Copy-Item .env.example .env }
```

## Run the current prototype on Windows

Run the API and USB monitor in **separate terminals**. In each terminal, start at the repository root, activate the same environment, and change into `code`. Running both from the same directory makes them share the relative SQLite database path (`code/data/usb_analyzer.db`).

**Terminal 1 — dashboard and API**, from the repository root:

```powershell
.\venv\Scripts\Activate.ps1
Set-Location code
python -m uvicorn usb_analyzer.api.main:app --reload
```

**Terminal 2 — USB device monitor**, also from the repository root:

```powershell
.\venv\Scripts\Activate.ps1
Set-Location code
python -m usb_analyzer.device_monitor.windows
```

The monitor's first inventory is a baseline: devices already connected when it starts are not reported as new connections. Plug in or remove a USB device after startup to test inventory changes. Currently, events are written directly to the shared SQLite database, not sent through the API. Keep both terminals running, then open the dashboard at <http://127.0.0.1:8000/> or the API docs at <http://127.0.0.1:8000/docs>. Press `Ctrl+C` in a terminal to stop that process.

To change the monitor polling interval, pass (for example) `--interval 0.5` to its command. The interval is the time between WMI inventory checks; actual detection latency also depends on the WMI query.

Run tests from `code` with the project environment active:

```powershell
python -m pytest
```

The Windows WMI monitor is not available on Linux yet. See [code/README.md](code/README.md) for the detailed setup, event contract, API endpoints, and module status.
