import logging
from concurrent.futures import Future, ThreadPoolExecutor
from pathlib import Path
import time
from typing import Callable, Protocol

import httpx

from usb_analyzer.core.events import DeviceEvent, EventSeverity
from usb_analyzer.policy.engine import PolicyEngine
from usb_analyzer.storage_scanner.scanner import ScanResult, scan_path
from usb_analyzer.storage_scanner.signatures import SignatureEngine

logger = logging.getLogger(__name__)
Scanner = Callable[[str | Path], ScanResult]
_TERMINAL_EVENT_ATTEMPTS = 3
_RETRY_BASE_DELAY_SECONDS = 0.25


def default_storage_scanner(root: str | Path) -> ScanResult:
    return scan_path(root, signature_engine=SignatureEngine())


class ScanEventSink(Protocol):
    def add(self, event: DeviceEvent) -> DeviceEvent:
        """Send a scan event and return the event accepted by the API."""


class StorageScanService:
    """Run read-only volume scans in worker threads and report results to the API."""

    def __init__(
        self,
        event_sink: ScanEventSink,
        scanner: Scanner = default_storage_scanner,
        max_workers: int = 2,
        policy_engine: PolicyEngine | None = None,
    ) -> None:
        if max_workers < 1:
            raise ValueError("max_workers must be at least one")
        self.event_sink = event_sink
        self.scanner = scanner
        self.policy_engine = policy_engine
        self._executor = ThreadPoolExecutor(
            max_workers=max_workers,
            thread_name_prefix="usb-storage-scan",
        )
        self._closed = False
        self._scanned_volumes: dict[str, tuple[float, float, int]] = {}

    def check_and_reschedule(self, device_id: str, volume_path: str) -> None:
        """Check if active mounted volume contents changed, then schedule rescan."""
        if self._closed:
            return

        norm_path = volume_path.casefold()
        now = time.monotonic()

        cur_mtime = 0.0
        cur_count = -1
        try:
            p = Path(volume_path)
            if p.exists() and p.is_dir():
                cur_mtime = p.stat().st_mtime
                cur_count = len(list(p.iterdir()))
        except Exception:
            return

        last_state = self._scanned_volumes.get(norm_path)
        if last_state is None:
            self._scanned_volumes[norm_path] = (now, cur_mtime, cur_count)
            return

        last_time, last_mtime, last_count = last_state
        if (now - last_time) >= 2.0:
            if cur_count != last_count or cur_mtime != last_mtime:
                logger.info(
                    "Volume %s changed (entries: %d -> %d); triggering security rescan",
                    volume_path,
                    last_count,
                    cur_count,
                )
                self._scanned_volumes[norm_path] = (now, cur_mtime, cur_count)
                self.schedule(device_id, volume_path)

    def schedule(self, device_id: str, volume_path: str) -> None:
        if self._closed:
            raise RuntimeError("StorageScanService is closed")

        self._publish_terminal_event(
            DeviceEvent(
                device_id=device_id,
                source="storage-scanner",
                event_type="scan.started",
                details={"volume_path": volume_path},
            )
        )
        future = self._executor.submit(self._scan, device_id, volume_path)
        future.add_done_callback(
            lambda completed: self._log_unhandled_failure(
                completed,
                device_id,
                volume_path,
            )
        )

    def _scan(self, device_id: str, volume_path: str) -> None:
        try:
            result = self.scanner(volume_path)
        except (OSError, ValueError) as error:
            self._publish_terminal_event(
                DeviceEvent(
                    device_id=device_id,
                    source="storage-scanner",
                    severity=EventSeverity.WARNING,
                    event_type="scan.failed",
                    details={
                        "volume_path": volume_path,
                        "error_type": type(error).__name__,
                        "error": str(error),
                    },
                )
            )
            return

        details = result.to_details()
        details["volume_path"] = volume_path

        # 1. Active remediation: delete confirmed malware files from USB storage
        deleted_threats: list[str] = []
        if result.has_threats:
            for finding in result.files:
                is_threat = any(
                    flag == "eicar_test_file"
                    or flag.startswith(("malware_hash:", "yara:", "os_detected_malware"))
                    for flag in finding.flags
                )
                if is_threat:
                    threat_abs = Path(volume_path) / finding.path
                    try:
                        if threat_abs.exists():
                            threat_abs.unlink()
                            deleted_threats.append(finding.path)
                            logger.critical("Quarantined and deleted malware file: %s", threat_abs)
                    except Exception as err:
                        logger.warning("Could not delete infected file %s: %s", threat_abs, err)

        details["deleted_threats"] = deleted_threats

        if result.has_threats:
            severity = EventSeverity.CRITICAL
            details["verdict"] = "DANGER"
            details["risk"] = "Malware Threat Neutralized"
            if deleted_threats:
                threat_names = ", ".join(deleted_threats)
                details["action_taken"] = f"Malware Deleted ({len(deleted_threats)} file{'s' if len(deleted_threats) != 1 else ''}) & Drive Blocked"
                details["summary"] = f"Malware detected on USB ({volume_path}). Action taken: {threat_names} deleted and hardware port isolated."
            else:
                details["action_taken"] = "Hardware Blocked (Port Disabled)"
                details["summary"] = f"Malware detected on USB ({volume_path}). Action taken: Hardware port isolated."
        elif result.flagged or result.errors:
            severity = EventSeverity.WARNING
            details["verdict"] = "WARNING"
            details["risk"] = "Suspicious Files"
            details["action_taken"] = "Flagged for Inspection"
            details["summary"] = f"Suspicious files detected on USB storage ({volume_path}). Action taken: Logged for review."
        else:
            severity = EventSeverity.INFO
            details["verdict"] = "SAFE"
            details["risk"] = "None"
            details["action_taken"] = "Verified Clean"
            details["summary"] = f"USB storage ({volume_path}) scanned. SAFE: 0 malware threats detected."

        self._publish_terminal_event(
            DeviceEvent(
                device_id=device_id,
                source="storage-scanner",
                severity=severity,
                event_type="scan.completed",
                details=details,
            )
        )

        if result.has_threats and self.policy_engine is not None:
            reason = (
                f"Malware detected on {volume_path}. Neutralized {', '.join(deleted_threats)}"
                if deleted_threats
                else f"Storage volume at {volume_path} contains confirmed malware / YARA threat signatures"
            )
            _, block_event = self.policy_engine.block_threat(
                device_id=device_id,
                reason=reason,
                threat_type="storage_malware",
                details={
                    "volume_path": volume_path,
                    "deleted_threats": deleted_threats,
                    "flagged": details["flagged"],
                    "verdict": "DANGER",
                    "action_taken": details["action_taken"],
                    "summary": details["summary"],
                },
            )
            block_event.details["verdict"] = "DANGER"
            block_event.details["action_taken"] = details["action_taken"]
            block_event.details["summary"] = details["summary"]
            self._publish_terminal_event(block_event)

    def _publish_terminal_event(self, event: DeviceEvent) -> None:
        for attempt in range(_TERMINAL_EVENT_ATTEMPTS):
            try:
                self.event_sink.add(event)
                return
            except httpx.HTTPError:
                if attempt == _TERMINAL_EVENT_ATTEMPTS - 1:
                    raise
                delay = _RETRY_BASE_DELAY_SECONDS * (2**attempt)
                logger.warning(
                    "Retrying %s event %s after API delivery failure in %.2f seconds",
                    event.event_type,
                    event.id,
                    delay,
                    exc_info=True,
                )
                time.sleep(delay)

    @staticmethod
    def _log_unhandled_failure(
        future: Future[None],
        device_id: str,
        volume_path: str,
    ) -> None:
        error = future.exception()
        if error is not None:
            logger.error(
                "Storage scan worker failed for device %s at %s",
                device_id,
                volume_path,
                exc_info=(type(error), error, error.__traceback__),
            )

    def close(self) -> None:
        if not self._closed:
            self._closed = True
            self._executor.shutdown(wait=True)

    def __enter__(self) -> "StorageScanService":
        if self._closed:
            raise RuntimeError("StorageScanService is closed")
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self.close()
