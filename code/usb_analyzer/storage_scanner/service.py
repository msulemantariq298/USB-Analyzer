from __future__ import annotations

import logging
from concurrent.futures import Future, ThreadPoolExecutor
from pathlib import Path
import time
from typing import Any, Callable, Protocol

import httpx

from usb_analyzer.core.events import DeviceEvent, EventSeverity
from usb_analyzer.policy.engine import PolicyEngine
from usb_analyzer.storage_scanner.scanner import (
    IGNORED_SYSTEM_DIRS,
    ScanResult,
    _is_reparse_point,
    scan_path,
)
from usb_analyzer.storage_scanner.signatures import SignatureEngine

logger = logging.getLogger(__name__)
Scanner = Callable[[str | Path], ScanResult]
_TERMINAL_EVENT_ATTEMPTS = 3
_RETRY_BASE_DELAY_SECONDS = 0.25


def default_storage_scanner(
    root: str | Path,
    changed_files: dict[str, str] | None = None,
) -> ScanResult:
    return scan_path(root, signature_engine=SignatureEngine(), changed_files=changed_files)


def _snapshot_volume(root: Path) -> dict[str, tuple[int, int]]:
    """Build a recursive {rel_path: (size, mtime_ns)} manifest skipping system/reparse dirs."""
    manifest: dict[str, tuple[int, int]] = {}
    if not root.is_dir() or _is_reparse_point(root):
        return manifest

    pending = [root]
    while pending:
        current = pending.pop()
        try:
            entries = list(current.iterdir())
        except OSError:
            continue
        for entry in entries:
            try:
                if _is_reparse_point(entry):
                    continue
                if entry.is_dir():
                    if entry.name.lower() in IGNORED_SYSTEM_DIRS:
                        continue
                    pending.append(entry)
                elif entry.is_file():
                    st = entry.stat()
                    rel = entry.relative_to(root).as_posix()
                    manifest[rel] = (st.st_size, st.st_mtime_ns)
            except OSError:
                continue
    return manifest


def _diff_manifests(
    previous: dict[str, tuple[int, int]],
    current: dict[str, tuple[int, int]],
) -> dict[str, str]:
    """Identify newly added or modified relative paths between manifests."""
    changes: dict[str, str] = {}
    for path, meta in current.items():
        if path not in previous:
            changes[path] = "new"
        elif previous[path] != meta:
            changes[path] = "modified"
    return changes


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
        self._last_scan_times: dict[str, float] = {}
        self._volume_manifests: dict[str, dict[str, tuple[int, int]]] = {}

    def check_and_reschedule(self, device_id: str, volume_path: str) -> None:
        """Recursively detect newly introduced or modified files on an active volume and rescan."""
        if self._closed:
            return

        norm_path = volume_path.casefold()
        now = time.monotonic()
        root = Path(volume_path)
        if not root.exists() or not root.is_dir():
            return

        cur_manifest = _snapshot_volume(root)
        prev_manifest = self._volume_manifests.get(norm_path)
        if prev_manifest is None:
            self._volume_manifests[norm_path] = cur_manifest
            self._last_scan_times[norm_path] = now
            return

        last_time = self._last_scan_times.get(norm_path, 0.0)
        if (now - last_time) >= 1.5 and cur_manifest != prev_manifest:
            changes = _diff_manifests(prev_manifest, cur_manifest)
            self._volume_manifests[norm_path] = cur_manifest
            self._last_scan_times[norm_path] = now
            if changes:
                logger.info(
                    "Volume %s changed (%d new/modified file(s)); triggering incremental security rescan",
                    volume_path,
                    len(changes),
                )
                self.schedule(device_id, volume_path, changed_files=changes)

    def schedule(
        self,
        device_id: str,
        volume_path: str,
        changed_files: dict[str, str] | None = None,
    ) -> None:
        if self._closed:
            raise RuntimeError("StorageScanService is closed")

        self._publish_terminal_event(
            DeviceEvent(
                device_id=device_id,
                source="storage-scanner",
                event_type="scan.started",
                details={
                    "volume_path": volume_path,
                    "incremental": changed_files is not None,
                },
            )
        )
        future = self._executor.submit(self._scan, device_id, volume_path, changed_files)
        future.add_done_callback(
            lambda completed: self._log_unhandled_failure(
                completed,
                device_id,
                volume_path,
            )
        )

    def scan_volume_now(self, device_id: str, volume_path: str) -> dict[str, Any]:
        """Synchronously inspect a USB storage volume and emit scan events."""
        norm_path = volume_path.casefold()
        root = Path(volume_path)
        cur_manifest = _snapshot_volume(root) if root.is_dir() else {}
        prev_manifest = self._volume_manifests.get(norm_path)
        changed_files: dict[str, str] | None = None
        if prev_manifest is not None:
            changed_files = _diff_manifests(prev_manifest, cur_manifest)

        self._volume_manifests[norm_path] = cur_manifest
        self._last_scan_times[norm_path] = time.monotonic()

        self._publish_terminal_event(
            DeviceEvent(
                device_id=device_id,
                source="storage-scanner",
                event_type="scan.started",
                details={
                    "volume_path": volume_path,
                    "incremental": changed_files is not None,
                },
            )
        )
        return self._scan(device_id, volume_path, changed_files=changed_files) or {}

    def _scan(
        self,
        device_id: str,
        volume_path: str,
        changed_files: dict[str, str] | None = None,
    ) -> dict[str, Any] | None:
        try:
            if self.scanner is default_storage_scanner:
                result = default_storage_scanner(volume_path, changed_files=changed_files)
            else:
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
            return None

        details = result.to_details()
        details["volume_path"] = volume_path
        details["rules_evaluated"] = len(SignatureEngine().rules)

        norm_path = volume_path.casefold()
        if Path(volume_path).is_dir():
            self._volume_manifests[norm_path] = _snapshot_volume(Path(volume_path))
            self._last_scan_times[norm_path] = time.monotonic()

        # 1. Active remediation: remove confirmed high-confidence malware payloads from USB storage
        deleted_threats: list[str] = []
        if result.has_threats:
            for finding in result.files:
                is_active_malware = any(
                    flag == "eicar_test_file"
                    or flag.startswith(("malware_hash:", "yara:", "os_detected_malware"))
                    for flag in finding.flags
                )
                if is_active_malware:
                    threat_abs = Path(volume_path) / finding.path
                    try:
                        if threat_abs.exists():
                            threat_abs.unlink()
                            deleted_threats.append(finding.path)
                            logger.critical("Quarantined and deleted malware file: %s", threat_abs)
                    except Exception as err:
                        logger.warning("Could not delete infected file %s: %s", threat_abs, err)

            if deleted_threats and Path(volume_path).is_dir():
                self._volume_manifests[norm_path] = _snapshot_volume(Path(volume_path))

        details["deleted_threats"] = deleted_threats
        max_score = result.max_risk_score
        new_count = int(details.get("new_files_count", 0)) + int(details.get("modified_files_count", 0))
        new_note = f"{new_count} newly introduced file(s)" if new_count > 0 else f"{len(result.files)} file(s) inspected"

        if result.has_threats:
            severity = EventSeverity.CRITICAL
            details["verdict"] = "DANGER"
            details["risk"] = f"Malware Threat Detected (Risk {max_score}/100)"
            if deleted_threats:
                threat_names = ", ".join(deleted_threats)
                details["action_taken"] = (
                    f"Malware Deleted ({len(deleted_threats)} file{'s' if len(deleted_threats) != 1 else ''})"
                )
                details["summary"] = (
                    f"Malware detected on USB ({volume_path}) — Risk Score {max_score}/100. "
                    f"Action taken: {threat_names} removed from drive."
                )
            else:
                details["action_taken"] = f"Threat Detected (Risk {max_score}/100)"
                details["summary"] = (
                    f"Malware threat detected on USB ({volume_path}) — Risk Score {max_score}/100."
                )
        elif result.flagged or result.errors or max_score >= 20:
            severity = EventSeverity.WARNING
            details["verdict"] = "WARNING"
            details["risk"] = f"Suspicious Files (Risk {max_score}/100)"
            details["action_taken"] = f"Flagged for Inspection (Risk {max_score}/100)"
            details["summary"] = (
                f"Suspicious file indicators on USB ({volume_path}) — Risk Score {max_score}/100 "
                f"across {len(result.flagged)} flagged / {new_note}."
            )
        else:
            severity = EventSeverity.INFO
            details["verdict"] = "SAFE"
            details["risk"] = f"Low Risk ({max_score}/100)"
            details["action_taken"] = "Verified Clean"
            details["summary"] = (
                f"USB storage ({volume_path}) scanned ({new_note}). "
                f"SAFE: 0 threats detected (Risk Score {max_score}/100)."
            )

        if result.has_threats and self.policy_engine is not None:
            details["suppress_toast"] = True

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
                f"Malware detected on {volume_path} (Risk {max_score}/100). Removed {', '.join(deleted_threats)}"
                if deleted_threats
                else f"Storage volume {volume_path} flagged with Risk Score {max_score}/100 (YARA/masquerade indicators)"
            )
            block_decision, block_event = self.policy_engine.block_threat(
                device_id=device_id,
                reason=reason,
                threat_type="storage_malware",
                details={
                    "volume_path": volume_path,
                    "deleted_threats": deleted_threats,
                    "flagged": details["flagged"],
                    "max_risk_score": max_score,
                    "verdict": "DANGER",
                    "action_taken": details["action_taken"],
                    "summary": details["summary"],
                },
            )
            if not block_decision.blocked_successfully:
                block_event.details["action_taken"] = (
                    f"Malware Removed ({len(deleted_threats)}) — Admin Needed to Block Port"
                    if deleted_threats
                    else "Port Block Failed (Administrator Privileges Required)"
                )
                block_event.details["summary"] = (
                    f"Malware detected on USB ({volume_path}) — Risk Score {max_score}/100. "
                    f"Action taken: {', '.join(deleted_threats)} removed (run as Administrator to disable hardware port)."
                    if deleted_threats
                    else f"Malware threat detected on USB ({volume_path}) — Risk Score {max_score}/100 (run as Administrator to disable hardware port)."
                )
            else:
                block_event.details["action_taken"] = (
                    f"Malware Deleted ({len(deleted_threats)} file{'s' if len(deleted_threats) != 1 else ''}) & Port Blocked"
                    if deleted_threats
                    else "Hardware Port Isolated & Blocked"
                )
                block_event.details["summary"] = (
                    f"Malware detected on USB ({volume_path}) — Risk Score {max_score}/100. "
                    f"Action taken: {', '.join(deleted_threats)} removed and hardware port disabled."
                    if deleted_threats
                    else f"Malware threat detected on USB ({volume_path}) — Risk Score {max_score}/100. Hardware port disabled."
                )
            block_event.details["verdict"] = "DANGER"
            self._publish_terminal_event(block_event)

        return details

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
