# USB Analyzer

A cross-platform USB security analyzer project for Windows and Linux. The Week 1 foundation includes a FastAPI backend, SQLite event store, shared device-event contract, and a browser dashboard.

## Current features

- View recent device events and severity counts in the dashboard.
- Create a demo event to exercise the API and UI before hardware monitoring is implemented.
- Store events locally in SQLite.
- Browse the API documentation at `/docs`.

> USB monitoring, scanning, HID detection, and device blocking are planned project modules and are not implemented yet. The dashboard currently uses simulated events.

## Quick start

From the repository root in PowerShell:

```powershell
py -m venv venv
.\venv\Scripts\Activate.ps1
Set-Location code
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
Copy-Item .env.example .env
python -m uvicorn usb_analyzer.api.main:app --reload
```

Open the dashboard at <http://127.0.0.1:8000/> and API docs at <http://127.0.0.1:8000/docs>.

Run the tests from the `code` directory:

```powershell
python -m pytest
```

See [code/README.md](code/README.md) for the full setup notes, event contract, API endpoints, and Week 1 status.
