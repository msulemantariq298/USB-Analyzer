from pathlib import Path
from threading import Event, Thread

import httpx

from usb_analyzer.core.database import EventStore
from usb_analyzer.core.events import DeviceEvent, EventSeverity
from usb_analyzer.storage_scanner.scanner import (
    FLAG_RISKY_EXTENSION,
    FileFinding,
    ScanResult,
)
from usb_analyzer.storage_scanner.service import StorageScanService


class CollectingEventSink:
    def __init__(self) -> None:
        self.events: list[DeviceEvent] = []

    def add(self, event: DeviceEvent) -> DeviceEvent:
        self.events.append(event)
        return event


def test_scan_service_reports_completed_scan_and_findings() -> None:
    event_sink = CollectingEventSink()
    result = ScanResult(
        root="E:\\",
        files=[
            FileFinding(
                path="setup.exe",
                size=120,
                sha256="abc123",
                flags=(FLAG_RISKY_EXTENSION,),
            )
        ],
    )

    with StorageScanService(event_sink, scanner=lambda root: result) as service:
        service.schedule("usb:test", "E:\\")

    assert [event.event_type for event in event_sink.events] == [
        "scan.started",
        "scan.completed",
    ]
    completed = event_sink.events[-1]
    assert completed.severity is EventSeverity.WARNING
    assert completed.details["volume_path"] == "E:\\"
    assert completed.details["flagged"][0]["path"] == "setup.exe"


def test_scan_service_reports_clean_scan_as_info() -> None:
    event_sink = CollectingEventSink()
    result = ScanResult(root="E:\\")

    with StorageScanService(event_sink, scanner=lambda root: result) as service:
        service.schedule("usb:test", "E:\\")

    assert event_sink.events[-1].event_type == "scan.completed"
    assert event_sink.events[-1].severity is EventSeverity.INFO


def test_scan_service_reports_scan_errors() -> None:
    event_sink = CollectingEventSink()

    def missing_volume(root: str) -> ScanResult:
        raise FileNotFoundError(root)

    with StorageScanService(event_sink, scanner=missing_volume) as service:
        service.schedule("usb:test", "E:\\")

    failed = event_sink.events[-1]
    assert failed.event_type == "scan.failed"
    assert failed.severity is EventSeverity.WARNING
    assert failed.details["error_type"] == "FileNotFoundError"


def test_scan_service_retries_terminal_event_delivery() -> None:
    class TemporarilyUnavailableSink(CollectingEventSink):
        attempts = 0

        def add(self, event: DeviceEvent) -> DeviceEvent:
            if event.event_type == "scan.completed":
                self.attempts += 1
                if self.attempts == 1:
                    raise httpx.ConnectError("temporary API outage")
            return super().add(event)

    event_sink = TemporarilyUnavailableSink()
    result = ScanResult(root="E:\\")

    with StorageScanService(event_sink, scanner=lambda root: result) as service:
        service.schedule("usb:test", "E:\\")

    assert event_sink.attempts == 2
    assert [event.event_type for event in event_sink.events] == [
        "scan.started",
        "scan.completed",
    ]


def test_scan_service_retry_is_safe_if_api_stored_event_before_disconnect(
    tmp_path: Path,
) -> None:
    event_store = EventStore(tmp_path / "events.db")

    class LostResponseSink:
        attempts = 0

        def add(self, event: DeviceEvent) -> DeviceEvent:
            accepted = event_store.add(event)
            if event.event_type == "scan.completed":
                self.attempts += 1
                if self.attempts == 1:
                    raise httpx.ConnectError("API response was lost")
            return accepted

    event_sink = LostResponseSink()
    result = ScanResult(root="E:\\")

    with StorageScanService(event_sink, scanner=lambda root: result) as service:
        service.schedule("usb:test", "E:\\")

    stored_events = event_store.list()
    assert event_sink.attempts == 2
    assert len(stored_events) == 2
    assert {event.event_type for event in stored_events} == {
        "scan.started",
        "scan.completed",
    }


def test_scan_service_runs_scan_outside_calling_thread() -> None:
    event_sink = CollectingEventSink()
    scan_started = Event()
    finish_scan = Event()

    def blocked_scanner(root: str) -> ScanResult:
        scan_started.set()
        if not finish_scan.wait(timeout=5):
            raise TimeoutError("test scan release was not signaled")
        return ScanResult(root=root)

    service = StorageScanService(event_sink, scanner=blocked_scanner)
    try:
        scheduling_thread = Thread(
            target=service.schedule,
            args=("usb:test", "E:\\"),
        )
        scheduling_thread.start()
        scheduling_thread.join(timeout=2)

        assert not scheduling_thread.is_alive()
        assert scan_started.wait(timeout=2)
        assert event_sink.events[0].event_type == "scan.started"
    finally:
        finish_scan.set()
        scheduling_thread.join(timeout=2)
        service.close()

    assert not scheduling_thread.is_alive()
    assert event_sink.events[-1].event_type == "scan.completed"


def test_storage_scan_service_deletes_malware_file(tmp_path: Path) -> None:
    # Create a simulated infected USB volume
    malware_file = tmp_path / "eicar.com"
    malware_file.write_bytes(b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*")

    event_sink = CollectingEventSink()
    result = ScanResult(
        root=str(tmp_path),
        files=[
            FileFinding(
                path="eicar.com",
                size=malware_file.stat().st_size,
                sha256="275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
                flags=("eicar_test_file",),
            )
        ],
    )

    with StorageScanService(event_sink, scanner=lambda root: result) as service:
        service.schedule("usb:test_drive", str(tmp_path))

    # The file must be deleted from the disk automatically
    assert not malware_file.exists()
    completed = [e for e in event_sink.events if e.event_type == "scan.completed"][0]
    assert completed.severity is EventSeverity.CRITICAL
    assert completed.details["verdict"] == "DANGER"
    assert "deleted" in completed.details["action_taken"].lower()
    assert "eicar.com" in completed.details["deleted_threats"]

