import logging
from concurrent.futures import Future, ThreadPoolExecutor
from pathlib import Path
import time
from typing import Callable, Protocol

import httpx

from usb_analyzer.core.events import DeviceEvent, EventSeverity
from usb_analyzer.storage_scanner.scanner import ScanResult, scan_path

logger = logging.getLogger(__name__)
Scanner = Callable[[str | Path], ScanResult]
_TERMINAL_EVENT_ATTEMPTS = 3
_RETRY_BASE_DELAY_SECONDS = 0.25


class ScanEventSink(Protocol):
    def add(self, event: DeviceEvent) -> DeviceEvent:
        """Send a scan event and return the event accepted by the API."""


class StorageScanService:
    """Run read-only volume scans in worker threads and report results to the API."""

    def __init__(
        self,
        event_sink: ScanEventSink,
        scanner: Scanner = scan_path,
        max_workers: int = 2,
    ) -> None:
        if max_workers < 1:
            raise ValueError("max_workers must be at least one")
        self.event_sink = event_sink
        self.scanner = scanner
        self._executor = ThreadPoolExecutor(
            max_workers=max_workers,
            thread_name_prefix="usb-storage-scan",
        )
        self._closed = False

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
        severity = (
            EventSeverity.WARNING
            if result.flagged or result.errors
            else EventSeverity.INFO
        )
        self._publish_terminal_event(
            DeviceEvent(
                device_id=device_id,
                source="storage-scanner",
                severity=severity,
                event_type="scan.completed",
                details=details,
            )
        )

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
