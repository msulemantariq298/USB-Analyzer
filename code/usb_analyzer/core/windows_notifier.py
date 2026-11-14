"""Native Windows Desktop Notifications for USB Analyzer.

Delivers clickable Windows 10/11 Toast notifications via WinRT
ToastNotificationManager:
- Clicking any notification opens the dashboard directly to the device details.
- Warning notifications include native "Block Device" and "Let It Run" buttons
  so the user can act immediately from the Windows notification banner.
"""

from __future__ import annotations

import base64
import html
import logging
import os
import platform
import subprocess
import threading
import urllib.parse

logger = logging.getLogger(__name__)

POWERSHELL_APP_ID = r"{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\WindowsPowerShell\v1.0\powershell.exe"
DEFAULT_DASHBOARD_URL = "http://127.0.0.1:8000/"


def build_notification_urls(
    device_id: str | None = None,
    severity: str = "info",
    dashboard_url: str = DEFAULT_DASHBOARD_URL,
) -> dict[str, str]:
    """Construct deep-link dashboard URLs for toast click and action buttons.
    
    Routes through /open so if a dashboard tab is already open in the browser,
    it directs focus and executes actions in that existing tab without opening
    duplicate tabs. If no tab is open, /open redirects to open the dashboard tab.
    """
    base = dashboard_url.rstrip("/") + "/"
    open_base = f"{base}open"
    if not device_id:
        return {
            "inspect": open_base,
            "block": open_base,
            "allow": open_base,
        }

    encoded_id = urllib.parse.quote(device_id, safe="")
    is_warning = severity.lower() == "warning"
    inspect_url = f"{open_base}?inspect_device={encoded_id}"
    if is_warning:
        inspect_url += "&triage=1"

    return {
        "inspect": inspect_url,
        "block": f"{open_base}?toast_action=block&device_id={encoded_id}",
        "allow": f"{open_base}?toast_action=allow&device_id={encoded_id}",
    }


def build_toast_xml(
    title: str,
    message: str,
    severity: str = "info",
    device_id: str | None = None,
    interactive: bool | None = None,
    dashboard_url: str = DEFAULT_DASHBOARD_URL,
) -> str:
    """Build Windows ToastNotification XML with click-to-open and warning action buttons."""
    sev = severity.lower()
    is_warning = sev == "warning"
    is_critical = sev == "critical"
    show_warning_actions = (
        interactive if interactive is not None else (is_warning and bool(device_id))
    )

    urls = build_notification_urls(
        device_id=device_id,
        severity=sev,
        dashboard_url=dashboard_url,
    )

    esc_title = html.escape(title, quote=True)
    esc_message = html.escape(message, quote=True)
    esc_inspect = html.escape(urls["inspect"], quote=True)

    toast_attrs = f'launch="{esc_inspect}" activationType="protocol"'
    if show_warning_actions:
        toast_attrs += ' scenario="reminder"'
    elif is_critical:
        toast_attrs += ' duration="long"'

    if show_warning_actions and device_id:
        esc_block = html.escape(urls["block"], quote=True)
        esc_allow = html.escape(urls["allow"], quote=True)
        actions_xml = (
            "  <actions>\n"
            f'    <action content="Block Device" arguments="{esc_block}" activationType="protocol" />\n'
            f'    <action content="Let It Run" arguments="{esc_allow}" activationType="protocol" />\n'
            "  </actions>\n"
        )
    elif is_critical:
        actions_xml = (
            "  <actions>\n"
            f'    <action content="View Details" arguments="{esc_inspect}" activationType="protocol" />\n'
            "  </actions>\n"
        )
    else:
        btn_label = "View Details" if device_id else "Open Dashboard"
        actions_xml = (
            "  <actions>\n"
            f'    <action content="{btn_label}" arguments="{esc_inspect}" activationType="protocol" />\n'
            "  </actions>\n"
        )

    return (
        f"<toast {toast_attrs}>\n"
        "  <visual>\n"
        '    <binding template="ToastGeneric">\n'
        f"      <text>{esc_title}</text>\n"
        f"      <text>{esc_message}</text>\n"
        "    </binding>\n"
        "  </visual>\n"
        f"{actions_xml}"
        "</toast>"
    )


def _run_powershell_toast(
    title: str,
    message: str,
    severity: str = "info",
    device_id: str | None = None,
    interactive: bool | None = None,
    dashboard_url: str = DEFAULT_DASHBOARD_URL,
) -> None:
    if platform.system() != "Windows" or os.environ.get("PYTEST_CURRENT_TEST"):
        return

    xml_str = build_toast_xml(
        title=title,
        message=message,
        severity=severity,
        device_id=device_id,
        interactive=interactive,
        dashboard_url=dashboard_url,
    )
    urls = build_notification_urls(
        device_id=device_id,
        severity=severity,
        dashboard_url=dashboard_url,
    )

    ps_script = "\n".join([
        "[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null",
        "[Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType = WindowsRuntime] | Out-Null",
        f"$AppId = '{POWERSHELL_APP_ID}'",
        f"$xmlText = @'\n{xml_str}\n'@",
        "$xml = New-Object Windows.Data.Xml.Dom.XmlDocument",
        "$xml.LoadXml($xmlText)",
        "$toast = New-Object Windows.UI.Notifications.ToastNotification $xml",
        "[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier($AppId).Show($toast)",
    ])
    encoded_cmd = base64.b64encode(ps_script.encode("utf-16-le")).decode("ascii")

    creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000) if os.name == "nt" else 0
    try:
        res = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded_cmd],
            capture_output=True,
            text=True,
            timeout=10.0,
            check=False,
            creationflags=creationflags,
        )
        if res.returncode != 0:
            logger.debug("WinRT toast returned %s (%s); falling back to NotifyIcon.", res.returncode, res.stderr.strip())
            _fallback_balloon_notification(title, message, severity, urls["inspect"])
    except Exception as exc:
        logger.debug("Windows toast notification failed: %s", exc)


def _fallback_balloon_notification(title: str, message: str, severity: str, open_url: str) -> None:
    """Fallback balloon tip with click-to-open if WinRT Toast fails."""
    icon_type = "Error" if severity.lower() == "critical" else ("Warning" if severity.lower() == "warning" else "Info")
    ps_script = "\n".join([
        "Add-Type -AssemblyName System.Windows.Forms",
        "$notify = New-Object System.Windows.Forms.NotifyIcon",
        "$notify.Icon = [System.Drawing.SystemIcons]::Shield",
        "$notify.Visible = $true",
        f"$targetUrl = '{open_url.replace(chr(39), chr(39)*2)}'",
        "$notify.add_BalloonTipClicked({ Start-Process $targetUrl })",
        f"$notify.ShowBalloonTip(8000, '{title.replace(chr(39), chr(39)*2)}', '{message.replace(chr(39), chr(39)*2)}', [System.Windows.Forms.ToolTipIcon]::{icon_type})",
        "for ($i = 0; $i -lt 80; $i++) { [System.Windows.Forms.Application]::DoEvents(); Start-Sleep -Milliseconds 100 }",
        "$notify.Dispose()",
    ])
    encoded_cmd = base64.b64encode(ps_script.encode("utf-16-le")).decode("ascii")
    creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000) if os.name == "nt" else 0
    try:
        subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded_cmd],
            capture_output=True,
            timeout=12.0,
            check=False,
            creationflags=creationflags,
        )
    except Exception as exc:
        logger.debug("Fallback Windows balloon notification failed: %s", exc)


def send_desktop_notification(
    title: str,
    message: str,
    severity: str = "info",
    device_id: str | None = None,
    interactive: bool | None = None,
    dashboard_url: str = DEFAULT_DASHBOARD_URL,
) -> None:
    """Send a non-blocking, clickable Windows desktop notification."""
    threading.Thread(
        target=_run_powershell_toast,
        args=(title, message, severity, device_id, interactive, dashboard_url),
        daemon=True,
    ).start()
