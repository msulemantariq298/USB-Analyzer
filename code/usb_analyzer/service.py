"""Background service lifecycle manager for USB Analyzer.

Provides commands to start, stop, check status, and open dashboard
for the detached background API and device monitor processes.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request
import webbrowser
from pathlib import Path

from usb_analyzer.core.windows_notifier import send_desktop_notification

PID_FILE = Path(__file__).resolve().parents[2] / "data" / "service_pids.json"
REPO_ROOT = Path(__file__).resolve().parents[2]
PYTHON_EXE = sys.executable
HEALTH_URL = "http://127.0.0.1:8000/api/v1/health"
DASHBOARD_URL = "http://127.0.0.1:8000/"


def is_api_running() -> bool:
    try:
        with urllib.request.urlopen(HEALTH_URL, timeout=1.0) as resp:
            return resp.status == 200
    except Exception:
        return False


def get_stored_pids() -> dict[str, int]:
    if not PID_FILE.exists():
        return {}
    try:
        data = json.loads(PID_FILE.read_text(encoding="utf-8"))
        if isinstance(data, dict):
            return {k: int(v) for k, v in data.items() if str(v).isdigit()}
    except Exception:
        pass
    return {}


def is_pid_running(pid: int) -> bool:
    if pid <= 0:
        return False
    try:
        res = subprocess.run(
            ["tasklist", "/FI", f"PID eq {pid}", "/FO", "CSV", "/NH"],
            capture_output=True,
            text=True,
            check=False,
        )
        return str(pid) in res.stdout
    except Exception:
        return False


def start_service() -> None:
    print("=" * 72)
    print("  USB ANALYZER - STARTING BACKGROUND DEFENSE SERVICE")
    print("=" * 72)

    api_active = is_api_running()
    stored = get_stored_pids()

    if api_active and any(is_pid_running(p) for p in stored.values()):
        print("[!] USB Analyzer is ALREADY active and running in the background.")
        print(f"    - Web Dashboard: {DASHBOARD_URL}")
        print(f"    - Stored PIDs:   {stored}")
        send_desktop_notification(
            "USB Analyzer Active",
            "Background protection is already running.",
            severity="info",
        )
        time.sleep(2)
        return

    # Prepare env
    env = os.environ.copy()
    env["PYTHONPATH"] = str(REPO_ROOT / "code")

    creationflags = 0
    if os.name == "nt":
        creationflags = (
            getattr(subprocess, "DETACHED_PROCESS", 0x00000008)
            | getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0x00000200)
        )

    log_dir = REPO_ROOT / "data" / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    api_log = open(log_dir / "api.log", "a", encoding="utf-8")
    monitor_log = open(log_dir / "monitor.log", "a", encoding="utf-8")

    # 1. Start Web API Server (Uvicorn)
    print("[*] Launching API Server on http://127.0.0.1:8000 (detached)...")
    api_proc = subprocess.Popen(
        [
            PYTHON_EXE,
            "-m",
            "uvicorn",
            "usb_analyzer.api.main:app",
            "--host",
            "127.0.0.1",
            "--port",
            "8000",
        ],
        cwd=str(REPO_ROOT),
        env=env,
        stdout=api_log,
        stderr=subprocess.STDOUT,
        creationflags=creationflags,
        close_fds=(os.name != "nt"),
    )

    # Wait for API to become ready
    ready = False
    for _ in range(15):
        time.sleep(0.5)
        if is_api_running():
            ready = True
            break

    if not ready:
        print("[X] Warning: API server took longer than expected to report healthy.")
    else:
        print("    [+] API Server is online and healthy.")

    # 2. Start Windows Device Monitor
    print("[*] Launching Hardware Device Monitor (detached)...")
    monitor_proc = subprocess.Popen(
        [PYTHON_EXE, "-m", "usb_analyzer.device_monitor.windows"],
        cwd=str(REPO_ROOT),
        env=env,
        stdout=monitor_log,
        stderr=subprocess.STDOUT,
        creationflags=creationflags,
        close_fds=(os.name != "nt"),
    )
    print(f"    [+] Device Monitor started (PID: {monitor_proc.pid}).")

    # Save PIDs
    pids = {"api_pid": api_proc.pid, "monitor_pid": monitor_proc.pid}
    PID_FILE.parent.mkdir(parents=True, exist_ok=True)
    PID_FILE.write_text(json.dumps(pids, indent=2), encoding="utf-8")

    # Send native Windows notification
    send_desktop_notification(
        "USB Analyzer Active",
        "Real-time endpoint defense is running silently in the background.",
        severity="info",
    )

    print("\n" + "=" * 72)
    print("  [SUCCESS] USB Analyzer is running in the background.")
    print("  - To view dashboard: Run `open_dashboard.bat`")
    print("  - To stop service:   Run `stop_usb_analyzer.bat`")
    print("=" * 72)
    time.sleep(2)


def stop_service() -> None:
    print("=" * 72)
    print("  USB ANALYZER - STOPPING BACKGROUND DEFENSE SERVICE")
    print("=" * 72)

    stored = get_stored_pids()
    killed = 0

    # 1. Kill stored PIDs
    for name, pid in stored.items():
        if is_pid_running(pid):
            print(f"[*] Terminating {name} (PID {pid})...")
            subprocess.run(["taskkill", "/F", "/PID", str(pid), "/T"], capture_output=True, check=False)
            killed += 1

    # 2. Kill anything listening on port 8000
    try:
        netstat = subprocess.run(["netstat", "-ano"], capture_output=True, text=True, check=False)
        for line in netstat.stdout.splitlines():
            if ":8000 " in line and "LISTENING" in line:
                parts = line.strip().split()
                if parts:
                    pid = parts[-1]
                    if pid.isdigit() and int(pid) != os.getpid():
                        print(f"[*] Terminating lingering process on port 8000 (PID {pid})...")
                        subprocess.run(["taskkill", "/F", "/PID", pid, "/T"], capture_output=True, check=False)
                        killed += 1
    except Exception:
        pass

    # 3. Terminate any lingering usb_analyzer processes
    try:
        wmic_cmd = [
            "wmic",
            "process",
            "where",
            "CommandLine like '%usb_analyzer%' and Name like '%python%'",
            "call",
            "terminate",
        ]
        subprocess.run(wmic_cmd, capture_output=True, check=False)
    except Exception:
        pass

    # 3. Clean PID file
    if PID_FILE.exists():
        try:
            PID_FILE.unlink()
        except Exception:
            pass

    send_desktop_notification(
        "USB Analyzer Stopped",
        "Endpoint defense has been paused.",
        severity="warning",
    )

    print("\n" + "=" * 72)
    print("  [STOPPED] USB Analyzer background service has been shut down.")
    print("=" * 72)
    time.sleep(2)


def open_dashboard() -> None:
    if not is_api_running():
        print("[*] USB Analyzer is not currently running. Starting it now...")
        start_service()

    print(f"[*] Opening USB Analyzer Dashboard at {DASHBOARD_URL} ...")
    webbrowser.open(DASHBOARD_URL)


def main() -> None:
    cmd = (sys.argv[1] if len(sys.argv) > 1 else "status").lower()
    if cmd == "start":
        start_service()
    elif cmd == "stop":
        stop_service()
    elif cmd in ("open", "open_dashboard", "dashboard"):
        open_dashboard()
    elif cmd == "status":
        running = is_api_running()
        stored = get_stored_pids()
        print(f"USB Analyzer API Active: {running}")
        print(f"Tracked PIDs: {stored}")
    else:
        print(f"Unknown command: {cmd}. Usage: service.py [start|stop|open|status]")


if __name__ == "__main__":
    main()
