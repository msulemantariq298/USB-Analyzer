# USB Analyzer — User Guide & Operations Manual

Welcome to **USB Analyzer**, a hardware security tool for Windows and Linux designed to inspect, monitor, and defend against malicious USB peripherals.

---

## Table of Contents

1. [System Requirements](#1-system-requirements)
2. [Installation & Setup](#2-installation--setup)
3. [Running the Application](#3-running-the-application)
   - [Starting the API & Dashboard](#starting-the-api--dashboard)
   - [Starting the Windows Device Monitor](#starting-the-windows-device-monitor)
   - [Starting the Linux Device Monitor](#starting-the-linux-device-monitor)
4. [Using the Web Dashboard](#4-using-the-web-dashboard)
   - [Overview & Security Metrics](#overview--security-metrics)
   - [Live Threat Alert Banner](#live-threat-alert-banner)
   - [Interactive Whitelist Management](#interactive-whitelist-management)
   - [Activity Log & File Inspection](#activity-log--file-inspection)
   - [One-Click PDF Forensic Report](#one-click-pdf-forensic-report)
5. [Testing & Demonstrating Attack Scenarios](#5-testing--demonstrating-attack-scenarios)
   - [Running the 5-Scenario Automated Demo](#running-the-5-scenario-automated-demo)
   - [Simulating BadUSB Keystroke Injection](#simulating-badusb-keystroke-injection)
6. [Troubleshooting & FAQ](#6-troubleshooting--faq)

---

## 1. System Requirements

- **Operating System**:
  - Windows 10 or 11 (64-bit)
  - Ubuntu Linux 20.04+ / Debian 11+
- **Python**: Version 3.11, 3.12, 3.13, or 3.14
- **Privileges**:
  - Windows: Standard user permissions for monitoring; Administrator privileges recommended for active hardware blocking via `pnputil`.
  - Linux: Root / `sudo` privileges for writing to `/sys/bus/usb/devices/*/authorized`.

---

## 2. Installation & Setup

### Windows (PowerShell)

From the repository root:

```powershell
# 1. Create and activate Python virtual environment
py -m venv venv
.\venv\Scripts\Activate.ps1

# 2. Navigate to code directory and install dependencies
Set-Location code
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"

# 3. Create local configuration file if not already present
if (-not (Test-Path .env)) { Copy-Item .env.example .env }
```

### Linux (Bash)

```bash
# 1. Create and activate virtual environment
python3 -m venv .venv
source .venv/bin/activate

# 2. Install dependencies
cd code
pip install --upgrade pip
pip install -e ".[dev]"

# 3. Setup configuration
cp .env.example .env
```

---

## 3. Running the Application

### Starting the API & Dashboard

In your first terminal, start the local web application:

```powershell
.\venv\Scripts\Activate.ps1
Set-Location code
python -m uvicorn usb_analyzer.api.main:app --reload
```

The web dashboard is now accessible at **<http://127.0.0.1:8000/>**, and the interactive Swagger API documentation is at **<http://127.0.0.1:8000/docs>**.

### Starting the Windows Device Monitor

In a **separate terminal**, start the background Windows USB monitor:

```powershell
.\venv\Scripts\Activate.ps1
Set-Location code
python -m usb_analyzer.device_monitor.windows
```

*Note: The monitor establishes an initial baseline of connected devices upon startup. Connect or disconnect a USB device after startup to observe real-time detection.*

### Starting the Linux Device Monitor

On Linux:

```bash
source .venv/bin/activate
cd code
sudo python -m usb_analyzer.device_monitor.linux
```

---

## 4. Using the Web Dashboard

Open `http://127.0.0.1:8000/` in any modern web browser.

### Overview & Security Metrics
- **Severity Breakdown Chart**: Doughnut chart illustrating the ratio of safe events, policy warnings, and critical security incidents.
- **Activity by Event Type Chart**: Bar chart summarizing connections, scans, and blocking actions.
- **Summary Cards**: Quick count of total events, warnings, critical threats, blocked devices, active storage scans, and flagged files.
- **Theme Toggle**: Switch between Dark and Light mode (top right).

### Live Threat Alert Banner
Whenever a critical event occurs (such as a BadUSB injection burst, malware detection on a flash drive, or a spoofed hardware identity), a prominent red alert banner automatically appears across the top with incident details and containment status.

### Interactive Whitelist Management
- **Policy Mode**: Toggle between **ENFORCE** (unauthorized devices are blocked from communicating with the OS) and **AUDIT ONLY** (unauthorized devices are allowed but logged with warnings).
- **Authorize Device**: Click `+ Authorize Device` to register a trusted peripheral by entering its Name, Serial Number, and Vendor/Product ID.
- **Quick-Authorize**: In the activity log table, click `+ Whitelist` on any device row to auto-populate the authorization form with its hardware identifiers.

### Activity Log & File Inspection
- Click on any event row's activity title to expand detailed telemetry:
  - For storage scans: lists scanned files, SHA-256 digests, file sizes, and specific YARA rule matches (`yara:Suspicious_Autorun_Inf`, `yara:PowerShell_Download_Cradle`, etc.).
  - For HID events: displays burst characters-per-second (CPS), inter-keystroke intervals (IKIs), and cadence variance.

### One-Click PDF Forensic Report
Click the **Export PDF Report** button in the top navigation bar to download a generated PDF incident report (`usb_analyzer_incident_report.pdf`). The report includes:
- Executive summary & incident metrics
- Detailed log of critical security threats & policy violations
- Active authorized device inventory
- Chronological forensic audit log with timestamps and device identifiers

---

## 5. Testing & Demonstrating Attack Scenarios

### Running the 5-Scenario Automated Demo

To demonstrate all 5 attack scenarios from the project proposal in an uninterrupted, automated run:

```powershell
.\venv\Scripts\Activate.ps1
$env:PYTHONPATH="code"
python -m usb_analyzer.demo_runner
```

Output:
```text
========================================================================
  DEMO SUMMARY: All 5 Scenarios Executed
========================================================================
  Scenario 1 (Trusted Drive)          : [PASS]
  Scenario 2 (Infected Drive)         : [PASS]
  Scenario 3 (Keystroke Injection)    : [PASS]
  Scenario 4 (Unknown Device)         : [PASS]
  Scenario 5 (Spoofed Identity)       : [PASS]
========================================================================
```

### Simulating BadUSB Keystroke Injection

You can simulate a live BadUSB attack directly from the Web Dashboard without special hardware:
1. Ensure the API is running and open `http://127.0.0.1:8000/`.
2. Click the **Simulate BadUSB** button in the dashboard header.
3. Observe the immediate response:
   - A `hid.injection_detected` critical event is recorded.
   - The device is blocked and hardware containment is logged (`device.blocked`).
   - The live critical alert banner pulses at the top of the screen.

Alternatively, send a POST request using `curl` or PowerShell:

```powershell
Invoke-RestMethod -Method Post -Uri "http://127.0.0.1:8000/api/v1/simulate/badusb" -ContentType "application/json" -Body '{"device_id":"USB\\VID_16C0&PID_05DF\\TEST_BADUSB","char_count":30,"delay_ms":3.0}'
```

---

## 6. Troubleshooting & FAQ

**Q: Why was my USB drive not blocked when a warning occurred?**  
A: Ensure the Policy Mode is set to **ENFORCE** (the red badge). In **AUDIT ONLY** mode (the yellow badge), events are recorded for security reviews but hardware is not disabled.

**Q: Can I run this without Administrator privileges on Windows?**  
A: Yes. In standard user mode, device detection, storage scanning, signature matching, BadUSB analysis, and event logging operate normally. Actual device disabling via `pnputil` requires Administrator privileges; without elevation, the system logs the containment command.

**Q: How do I run the full automated test suite?**  
A: Activate the virtual environment, navigate to the project directory, and run:
```powershell
python -m pytest code/tests
```
All 63 test cases will execute and verify all subsystems.

