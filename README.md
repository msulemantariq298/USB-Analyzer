# USB Analyzer

Real-time endpoint USB security monitoring, storage malware inspection, and policy enforcement system for **Windows** and **Linux**, powered by a FastAPI backend, SQLite audit store, and an architectural local web console.

---

## Architecture Overview

```text
USB Attach / Storage Mount / HID Activity
        │
        ▼
Background Monitor Agent (Windows WMI / Linux sysfs & pyudev)
        ├─► Hardware Fingerprinting (VID, PID, Serial, Spoofed-ID checks)
        ├─► BadUSB / HID Cadence Detector (keystroke rate & timing intervals)
        └─► Storage Malware Analyzer (SHA-256/MD5, Magic Signatures, PE headers,
                                      Shannon Entropy, Metadata, YARA & Hash IOCs)
        │
        ▼
Policy Engine & Enforcement (`Enforce` via pnputil / sysfs, or `Audit Only`)
        │
        ▼
FastAPI Server + SQLite Store + WebSocket Stream (http://127.0.0.1:8000/)
        ├─► Real-time Web Dashboard (Overview, Audit Log, Activity & Health, Whitelist)
        └─► Forensic Exports (UTF-8 CSV + Dashboard-Matched Vector PDF Reports)
```

---

## Key Security Capabilities

- **Device Fingerprinting & Spoof Detection**: Extracts USB Vendor ID (`VID`), Product ID (`PID`), serial number, PNP device class, and interfaces; triggers critical alerts when a whitelisted `VID:PID` pair appears with an unauthorized serial number.
- **USB Storage Malware Analysis (`0–100` Risk Scoring)**:
  - **Cryptographic Digests & IOC Feeds**: Computes single-pass `SHA-256` and `MD5` hashes and checks mounted files against known-bad hashes in [`code/usb_analyzer/storage_scanner/rules/malware_hashes.txt`](code/usb_analyzer/storage_scanner/rules/malware_hashes.txt).
  - **File Type Signatures & Masquerading Checks**: Inspects magic bytes and PE COFF headers to flag spoofed extensions (such as a PE executable renamed to `.pdf`), RTLO filename spoofing, and double extensions.
  - **Shannon Entropy (`0.00–8.00` b/B)**: Detects packed, obfuscated, or encrypted payloads while differentiating expected compressed formats.
  - **YARA & Heuristic Rules**: Evaluates custom detection rules in [`code/usb_analyzer/storage_scanner/rules/usb_malware.yar`](code/usb_analyzer/storage_scanner/rules/usb_malware.yar) covering `autorun.inf` abuse, PowerShell download cradles, disguised executables, and suspicious script payloads, plus metadata inspection (hidden/system attributes and incremental new/modified file tracking).
- **BadUSB / HID Keystroke Injection Defense**: Evaluates typing cadence across sliding time windows to intercept automated keystroke-injection hardware and isolate offending ports.
- **Zero-Trust Policy & Whitelisting**:
  - Switch between **Enforce** (active hardware disabling via Windows `pnputil` when running as Administrator, or Linux `sysfs` de-authorization) and **Audit Only**.
  - Authorize trusted hardware interactively from connected USB devices or by manual `VID`/`PID`/serial entry.
- **Web Console & Forensic Exports**:
  - Light/dark architectural dashboard with live WebSocket telemetry, **Overview** KPIs, **Audit Log** (`Devices`, `Event Log`, `Files`), **Activity & Health** analytics charts, **Whitelist**, MITRE ATT&CK **Threat Matrix**, and **Settings**.
  - **CSV Export** (`/api/v1/reports/events.csv`): Excel-ready UTF-8 CSV with extracted hardware IDs, flattened `EVENT` and `FILE` analysis rows (`SHA-256`, `MD5`, entropy, risk score, YARA indicators), and formula-injection neutralization.
  - **PDF Report** (`/api/v1/reports/incident/pdf`): Zero-dependency vector PDF matching the dashboard design with KPI summary, activity timeline chart, health ratio donut, device policy verdicts, file forensic tables, whitelist rules, and recent events.

---

## Repository Structure

```text
USB-Analyzer/
├── code/
│   ├── usb_analyzer/
│   │   ├── api/                 # FastAPI app, WebSocket hub, static Web UI (index.html, styles.css, app.js)
│   │   ├── core/                # Config loader, SQLite EventStore, event models, Windows notifications
│   │   ├── device_monitor/      # Cross-platform USB monitors (Windows WMI & Linux sysfs/pyudev) + fingerprinting
│   │   ├── hid_detector/        # BadUSB keystroke-dynamics detector
│   │   ├── policy/              # Whitelist store, policy evaluation engine & OS port blocking
│   │   ├── reports/             # Shared report summarizers (common.py) & vector PDF generator (incident_pdf.py)
│   │   └── storage_scanner/     # Static/entropy/PE analyzer, YARA rules, IOC hash feed & volume scan service
│   ├── tests/                   # Automated pytest suite
│   ├── .env.example             # Environment variable template
│   └── pyproject.toml           # Python package metadata & dependencies
├── docs/                        # Technical report and user guide
├── start_usb_analyzer.bat       # Windows one-click background defense launcher
├── open_dashboard.bat           # Windows one-click dashboard opener (auto-starts service if stopped)
├── stop_usb_analyzer.bat        # Windows one-click background service shutdown
└── README.md
```

---

## Prerequisites & Installation

- **Python**: `3.11+` (`requires-python = ">=3.11"`)
- **Operating Systems**: Windows 10/11 (WMI + optional `pnputil` port isolation) or Linux (sysfs / `pyudev`)

From the repository root in PowerShell (Windows):

```powershell
py -m venv venv               # Skip if .\venv already exists
.\venv\Scripts\Activate.ps1
Set-Location code
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
if (-not (Test-Path .env)) { Copy-Item .env.example .env }
Set-Location ..
```

---

## How to Start the App

### Option 1: One-Click Background Launchers (Windows — Recommended)

Run from the repository root (double-click in File Explorer or execute from PowerShell):

1. **Start background protection & API server (`http://127.0.0.1:8000`)**:
   ```powershell
   .\start_usb_analyzer.bat
   ```
   Starts both the FastAPI server and Windows WMI device monitor in the background (`usb_analyzer.service start`) and displays a Windows status notification.

2. **Open the web dashboard**:
   ```powershell
   .\open_dashboard.bat
   ```
   Opens `http://127.0.0.1:8000/` in your default browser (and automatically starts the background service first if it is not yet running).

3. **Stop background protection**:
   ```powershell
   .\stop_usb_analyzer.bat
   ```
   Terminates the background API and monitor processes cleanly and frees port `8000`.

> **Administrator Elevation Note (Windows):** Standard user mode monitors USB connections, scans storage volumes, raises alerts, and generates reports cleanly. To allow `Enforce` mode to disable malicious USB ports automatically via `pnputil`, start from an elevated Administrator PowerShell prompt.

---

### Option 2: Run Manually in Two Terminals (Development / Live Output)

**Terminal 1 — FastAPI Server & Web Console**:
```powershell
.\venv\Scripts\Activate.ps1
Set-Location code
python -m uvicorn usb_analyzer.api.main:app --host 127.0.0.1 --port 8000
```

**Terminal 2 — Hardware Device Monitor**:
```powershell
.\venv\Scripts\Activate.ps1
Set-Location code
python -m usb_analyzer.device_monitor.windows
```
*(Optional: append `--interval 0.5` to adjust WMI polling frequency.)*

Once both are running:
- **Web Dashboard**: <http://127.0.0.1:8000/>
- **Swagger / OpenAPI Docs**: <http://127.0.0.1:8000/docs>

---

### Option 3: Linux Setup & Manual Launch

```bash
python3 -m venv .venv
source .venv/bin/activate
cd code
pip install -e ".[dev]"
if [ ! -f .env ]; then cp .env.example .env; fi

# Terminal 1: API & Dashboard
python -m uvicorn usb_analyzer.api.main:app --host 127.0.0.1 --port 8000

# Terminal 2: Linux USB Monitor
python -m usb_analyzer.device_monitor.linux
```

---

### Option 4: Automated 5-Scenario Verification Demo

Verify trusted drive allowance, infected storage flagging, BadUSB keystroke injection detection, unauthorized hardware containment, and spoofed-identity blocking in one scripted pass:

```powershell
.\venv\Scripts\Activate.ps1
$env:PYTHONPATH="code"
python -m usb_analyzer.demo_runner
```

---

## Configuration

Copy [`code/.env.example`](code/.env.example) to `code/.env` to customize runtime behavior:

| Variable | Default | Description |
| :--- | :--- | :--- |
| `USB_ANALYZER_APP_NAME` | `USB Analyzer` | Application title used in API metadata |
| `USB_ANALYZER_DATABASE_PATH` | `data/usb_analyzer.db` | SQLite database path for events & whitelist rules |
| `USB_ANALYZER_API_PREFIX` | `/api/v1` | REST & WebSocket API route prefix |
| `USB_ANALYZER_API_BASE_URL` | `http://127.0.0.1:8000` | Base URL targeted by background monitors |
| `USB_ANALYZER_API_TIMEOUT_SECONDS` | `5` | HTTP request timeout for monitor telemetry |
| `USB_ANALYZER_LOG_LEVEL` | `INFO` | Logging verbosity |

---

## Key API & Export Endpoints

- `GET /api/v1/health` — API liveness check
- `GET /api/v1/events` — Query recorded hardware, HID, policy, and scan events
- `POST /api/v1/devices/scan` — Synchronize currently connected USB devices
- `POST /api/v1/storage/scan` — Run static, hash, entropy, metadata & YARA scan across mounted USB drives
- `GET /api/v1/policy/whitelist` — List authorized USB devices
- `GET /api/v1/reports/events.csv` — Download enriched UTF-8 forensic CSV (`EVENT` + `FILE` rows)
- `GET /api/v1/reports/incident/pdf` — Download visual multi-page PDF incident report
- `GET /api/v1/reports/events.json` — Download raw JSON audit export

---

## Running Tests

Run the pytest suite from the repository root:

```powershell
.\venv\Scripts\python.exe -m pytest code/tests
```

*(On Windows without Developer Mode / symlink creation privileges, 2 directory-symlink safety tests in [`code/tests/test_storage_scanner.py`](code/tests/test_storage_scanner.py) are skipped automatically.)*

---

## Limitations & Scope

USB Analyzer focuses on host-side USB enumeration, HID keystroke cadence anomalies, static file inspection (hashes, magic types, PE headers, entropy, metadata, and YARA-style rules), and policy enforcement. Signature coverage depends on [`usb_malware.yar`](code/usb_analyzer/storage_scanner/rules/usb_malware.yar) and [`malware_hashes.txt`](code/usb_analyzer/storage_scanner/rules/malware_hashes.txt); it does not perform kernel-driver sandboxing or replace a full endpoint antivirus suite.

For operational workflows and architecture details, see [`code/README.md`](code/README.md), [`docs/USER_GUIDE.md`](docs/USER_GUIDE.md), and [`docs/TECHNICAL_REPORT.md`](docs/TECHNICAL_REPORT.md).
