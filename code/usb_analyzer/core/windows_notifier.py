"""Native Windows Desktop Notifications for USB Analyzer.

Delivers desktop toast / balloon notifications and triage prompts
similar to Windows Defender endpoint alerts.
"""

import logging
import platform
import subprocess
import threading

logger = logging.getLogger(__name__)


def _run_powershell_toast(title: str, message: str, is_critical: bool = False) -> None:
    if platform.system() != "Windows":
        return

    icon_type = "Error" if is_critical else "Warning"
    
    # Safe PowerShell script using Windows Forms NotifyIcon
    ps_script = f"""
Add-Type -AssemblyName System.Windows.Forms
$notify = New-Object System.Windows.Forms.NotifyIcon
$notify.Icon = [System.Drawing.SystemIcons]::Shield
$notify.Visible = $true
$notify.ShowBalloonTip(4000, {repr(title)}, {repr(message)}, [System.Windows.Forms.ToolTipIcon]::{icon_type})
Start-Sleep -Milliseconds 800
$notify.Dispose()
"""
    try:
        subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_script],
            capture_output=True,
            timeout=3.0,
            check=False,
        )
    except Exception as exc:
        logger.debug("Windows toast notification failed: %s", exc)


def send_desktop_notification(title: str, message: str, severity: str = "info") -> None:
    """Send a non-blocking Windows desktop notification."""
    is_critical = severity.lower() == "critical"
    threading.Thread(
        target=_run_powershell_toast,
        args=(title, message, is_critical),
        daemon=True,
    ).start()

