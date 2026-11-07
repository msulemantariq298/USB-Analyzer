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

## Implementation status

All core modules specified in the project proposal are implemented and verified:

- **Foundation & Core Engine (FR-7)**: FastAPI REST API, SQLite persistence (`DeviceEvent` and `whitelist`), configuration loader, and structured JSON event audit trail.
- **Device Fingerprinting & Spoofed-ID Detection (FR-1, FR-2)**: Extracts vendor ID, product ID, serial number, device class, and interfaces; detects spoofed identities (trusted VID/PID claiming unauthorized serial) and emits critical alerts.
- **Storage Scanner & Threat Engine (FR-3, FR-4)**: Chunked SHA-256 calculation, known malware hash verification (including EICAR), and YARA signature rule evaluation (autorun.inf auto-execution, PowerShell download cradles, macro execution), generating critical alerts and triggering automated device blocking.
- **HID / BadUSB Detector (FR-5)**: Sliding-window keystroke dynamics tracker calculating characters-per-second (CPS) and inter-keystroke intervals (IKIs) to detect inhuman typing cadences from BadUSB devices (e.g. Digispark/Rubber Ducky) and trigger immediate hardware blocking.
- **Policy Engine & Whitelist Enforcement (FR-6)**: Whitelist management supporting enforce and audit-only modes, automated blocking of unauthorized or threat-flagged devices via `pnputil` (Windows) and `sysfs authorized = 0` (Linux).
- **Dashboard & Incident Reports (FR-8)**: Web interface with theme toggle, Chart.js metrics (severity breakdown and activity volume), real-time threat alert banners, interactive whitelist management, BadUSB attack simulator, and one-click PDF incident report generation (`/api/v1/reports/incident/pdf`).
- **Cross-Platform Device Monitoring**:
  - Windows: WMI Plug and Play polling and volume association.
  - Linux: sysfs (`/sys/bus/usb/devices`) and `pyudev` monitoring with sysfs de-authorization.
- **Five Attack Scenarios Verification**: Automated demonstration runner (`python -m usb_analyzer.demo_runner`) verifying all five scenarios from the proposal:
  1. Trusted Drive -> Allowed and logged
  2. Infected Drive -> High-severity alert and device contained
  3. Keystroke Injection -> BadUSB flagged and blocked
  4. Unknown Device -> Blocked immediately by whitelist policy
  5. Spoofed Identity -> Mismatch alert emitted and blocked

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

## Running the Five-Scenario Demo

To run the live automated demonstration verifying all 5 attack scenarios from the proposal in one uninterrupted pass:

```powershell
.\venv\Scripts\Activate.ps1
$env:PYTHONPATH="code"
python -m usb_analyzer.demo_runner
```

## Quick Start (One-Click Launchers on Windows)

From the repository root, you can quickly launch the system using the bundled batch scripts:

- **Launch Full System (Web Dashboard + Device Monitor)**:
  Double-click `run_usb_analyzer.bat` or run:
  ```powershell
  .\run_usb_analyzer.bat
  ```
  This starts the API server, opens `http://127.0.0.1:8000/` in your browser, and starts the live USB monitor.

- **Run 5-Scenario Attack Defense Demo**:
  Double-click `run_demo.bat` or run:
  ```powershell
  .\run_demo.bat
  ```

## Running the Application Manually on Windows

If you prefer running the API and USB monitor in **separate terminals**:

**Terminal 1 — Dashboard and API**:

```powershell
.\venv\Scripts\Activate.ps1
Set-Location code
python -m uvicorn usb_analyzer.api.main:app --host 127.0.0.1 --port 8000
```

**Terminal 2 — USB Device Monitor**:

```powershell
.\venv\Scripts\Activate.ps1
Set-Location code
python -m usb_analyzer.device_monitor.windows
```

Open the dashboard in your browser at <http://127.0.0.1:8000/> or review API documentation at <http://127.0.0.1:8000/docs>.

The monitor's first inventory is a baseline: devices already connected when it starts are not reported as new connections. Plug in or remove a USB device after startup to test inventory changes. Each detected event is sent by HTTP POST to the API, which stores it in SQLite for the dashboard. Keep both terminals running. Press `Ctrl+C` in a terminal to stop that process.

## Running on Linux

On Linux (e.g. Ubuntu):

```bash
python3 -m venv .venv
source .venv/bin/activate
cd code
pip install -e ".[dev]"
python -m usb_analyzer.device_monitor.linux
```

## Running Tests

Run the full pytest suite with the project environment active:

```powershell
.\venv\Scripts\python.exe -m pytest code/tests
```

The API defaults to `http://127.0.0.1:8000` and the monitor uses a 5-second HTTP timeout. Set `USB_ANALYZER_API_BASE_URL` or `USB_ANALYZER_API_TIMEOUT_SECONDS` in `code/.env` to change those settings. To change the monitor polling interval, pass (for example) `--interval 0.5` to its command. The interval is the time between WMI inventory checks; actual detection latency also depends on the WMI query.

See [code/README.md](code/README.md) and [docs/USER_GUIDE.md](docs/USER_GUIDE.md) for detailed setup, event contracts, API endpoints, and full operations manual.
