import hashlib
from pathlib import Path

import pytest

from usb_analyzer.core.events import DeviceEvent
from usb_analyzer.storage_scanner import flag_file, scan_path, sha256_file
from usb_analyzer.storage_scanner.scanner import FLAG_AUTORUN, FLAG_RISKY_EXTENSION


def _snapshot(root: Path) -> dict[str, tuple[bytes, int]]:
    return {
        p.relative_to(root).as_posix(): (p.read_bytes(), p.stat().st_mtime_ns)
        for p in root.rglob("*")
        if p.is_file()
    }


def test_sha256_matches_hashlib_with_small_chunks(tmp_path: Path) -> None:
    data = b"harmless test data" * 1000
    target = tmp_path / "a.txt"
    target.write_bytes(data)

    assert sha256_file(target, chunk_size=7) == hashlib.sha256(data).hexdigest()


def test_empty_file_hash(tmp_path: Path) -> None:
    target = tmp_path / "empty.txt"
    target.write_bytes(b"")

    assert sha256_file(target) == hashlib.sha256(b"").hexdigest()


def test_flag_file_rules() -> None:
    assert flag_file("AUTORUN.INF") == (FLAG_AUTORUN,)
    assert flag_file("setup.EXE") == (FLAG_RISKY_EXTENSION,)
    assert flag_file("notes.txt") == ()
    assert flag_file("exe") == ()


def test_flag_file_is_case_insensitive() -> None:
    assert flag_file("VIRUS.EXE") == (FLAG_RISKY_EXTENSION,)
    assert flag_file("Report.DocM") == (FLAG_RISKY_EXTENSION,)
    assert flag_file("AutoRun.Inf") == (FLAG_AUTORUN,)
    assert flag_file("tool.exe", frozenset({".EXE"})) == (FLAG_RISKY_EXTENSION,)


def test_scan_hashes_and_flags_nested_files(tmp_path: Path) -> None:
    (tmp_path / "autorun.inf").write_text("[autorun]\nopen=fake.exe\n")
    (tmp_path / "docs").mkdir()
    (tmp_path / "docs" / "readme.txt").write_text("hello")
    (tmp_path / "docs" / "run.bat").write_text("echo harmless")

    result = scan_path(tmp_path)
    by_path = {f.path: f for f in result.files}

    assert set(by_path) == {"autorun.inf", "docs/readme.txt", "docs/run.bat"}
    assert by_path["docs/readme.txt"].sha256 == hashlib.sha256(b"hello").hexdigest()
    assert by_path["autorun.inf"].flags == (FLAG_AUTORUN,)
    assert by_path["docs/run.bat"].flags == (FLAG_RISKY_EXTENSION,)
    assert by_path["docs/readme.txt"].flags == ()
    assert {f.path for f in result.flagged} == {"autorun.inf", "docs/run.bat"}


def test_scan_leaves_files_unchanged(tmp_path: Path) -> None:
    (tmp_path / "autorun.inf").write_text("[autorun]")
    (tmp_path / "x.exe").write_bytes(b"not a real executable")
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "y.txt").write_text("data")
    before = _snapshot(tmp_path)

    scan_path(tmp_path)

    assert _snapshot(tmp_path) == before


def test_scan_rejects_non_directory(tmp_path: Path) -> None:
    file_path = tmp_path / "f.txt"
    file_path.write_text("x")

    with pytest.raises(NotADirectoryError):
        scan_path(file_path)


def test_details_fit_device_event_without_schema_change(tmp_path: Path) -> None:
    (tmp_path / "autorun.inf").write_text("[autorun]")

    result = scan_path(tmp_path)
    event = DeviceEvent(
        device_id="usb:test",
        source="storage-scanner",
        event_type="scan.completed",
        details=result.to_details(),
    )

    details = event.model_dump(mode="json")["details"]
    assert details["files_scanned"] == 1
    assert details["flagged"][0]["flags"] == [FLAG_AUTORUN]
    event.sqlite_values()  # must be JSON-serialisable
