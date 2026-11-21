import hashlib
import os
from pathlib import Path
import subprocess

import pytest

from usb_analyzer.core.events import DeviceEvent
from usb_analyzer.storage_scanner import flag_file, scan_path, sha256_file
from usb_analyzer.storage_scanner.scanner import (
    FLAG_AUTORUN,
    FLAG_RISKY_EXTENSION,
    _is_reparse_point,
)


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


@pytest.mark.parametrize("chunk_size", [0, -1])
def test_sha256_rejects_non_positive_chunk_size(
    tmp_path: Path,
    chunk_size: int,
) -> None:
    target = tmp_path / "data.bin"
    target.write_bytes(b"data")

    with pytest.raises(ValueError, match="chunk_size must be greater than zero"):
        sha256_file(target, chunk_size=chunk_size)


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


def test_scan_skips_symlink_to_directory(tmp_path: Path) -> None:
    root = tmp_path / "root"
    outside = tmp_path / "outside"
    root.mkdir()
    outside.mkdir()
    (outside / "outside.txt").write_text("outside")
    link = root / "linked-directory"

    try:
        link.symlink_to(outside, target_is_directory=True)
    except OSError as error:
        pytest.skip(f"Directory symlinks are unavailable: {error}")

    result = scan_path(root)

    assert result.files == []


@pytest.mark.skipif(os.name != "nt", reason="Windows junction test")
def test_scan_skips_junction_to_directory(tmp_path: Path) -> None:
    root = tmp_path / "root"
    outside = tmp_path / "outside"
    root.mkdir()
    outside.mkdir()
    (outside / "outside.txt").write_text("outside")
    junction = root / "linked-directory"

    result = subprocess.run(
        ["cmd.exe", "/c", "mklink", "/J", str(junction), str(outside)],
        capture_output=True,
        check=False,
        text=True,
    )
    if result.returncode != 0:
        pytest.skip(f"Could not create a test junction: {result.stderr or result.stdout}")

    try:
        assert _is_reparse_point(junction)
        scan_result = scan_path(root)
        assert scan_result.files == []
    finally:
        junction.rmdir()


def test_scan_rejects_reparse_point_root(tmp_path: Path) -> None:
    root = tmp_path / "root"
    target = tmp_path / "target"
    root.mkdir()
    target.mkdir()
    link = tmp_path / "root-link"

    try:
        link.symlink_to(target, target_is_directory=True)
    except OSError as error:
        pytest.skip(f"Directory symlinks are unavailable: {error}")

    with pytest.raises(ValueError, match="Scan root must not be a symlink or reparse point"):
        scan_path(link)


def test_scan_rejects_non_directory(tmp_path: Path) -> None:
    file_path = tmp_path / "f.txt"
    file_path.write_text("x")

    with pytest.raises(NotADirectoryError):
        scan_path(file_path)


@pytest.mark.parametrize("chunk_size", [0, -1])
def test_scan_rejects_non_positive_chunk_size(
    tmp_path: Path,
    chunk_size: int,
) -> None:
    with pytest.raises(ValueError, match="chunk_size must be greater than zero"):
        scan_path(tmp_path, chunk_size=chunk_size)


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


def test_entropy_magic_metadata_and_risk_scoring(tmp_path: Path) -> None:
    import os as _os
    import struct
    from usb_analyzer.storage_scanner.analyzer import (
        FLAG_EXTENSION_MISMATCH,
        FLAG_HIGH_ENTROPY,
    )
    from usb_analyzer.storage_scanner.signatures import SignatureEngine

    # 1. Clean text file -> low entropy, low risk score
    clean = tmp_path / "notes.txt"
    clean.write_text("Quarterly budget notes and harmless text." * 4, encoding="utf-8")

    # 2. High-entropy packed blob disguised with .bin extension -> flagged + risk score
    packed = tmp_path / "payload.bin"
    packed.write_bytes(bytes(range(256)) * 16)  # uniform 256-byte distribution -> entropy 8.00

    # 3. Naturally compressed .png should keep high entropy without false mismatch penalty
    png_file = tmp_path / "photo.png"
    png_file.write_bytes(b"\x89PNG\r\n\x1a\n" + bytes(range(256)) * 8)

    # 4. Real PE/MZ header disguised as .pdf -> extension_signature_mismatch + PE metadata
    pe_blob = bytearray(256)
    pe_blob[0:2] = b"MZ"
    struct.pack_into("<I", pe_blob, 0x3C, 0x80)
    pe_blob[0x80:0x84] = b"PE\x00\x00"
    struct.pack_into("<HHIIIHH", pe_blob, 0x84, 0x8664, 4, 1700000000, 0, 0, 0, 0x0022)
    spoof_pdf = tmp_path / "invoice.pdf"
    spoof_pdf.write_bytes(bytes(pe_blob))

    # 5. System Volume Information metadata folder should be skipped cleanly
    sys_dir = tmp_path / "System Volume Information"
    sys_dir.mkdir()
    (sys_dir / "IndexerVolumeGuid").write_bytes(b"\x01\x02\x03")

    res = scan_path(tmp_path, signature_engine=SignatureEngine())
    by_path = {f.path: f for f in res.files}

    assert set(by_path) == {"invoice.pdf", "notes.txt", "payload.bin", "photo.png"}

    # Clean file
    assert by_path["notes.txt"].md5 == hashlib.md5(clean.read_bytes()).hexdigest()
    assert by_path["notes.txt"].file_type == "Text / Document"
    assert by_path["notes.txt"].risk_score < 20
    assert by_path["notes.txt"].risk_level == "clean"
    assert "created_at" in by_path["notes.txt"].metadata

    # High-entropy binary
    assert by_path["payload.bin"].entropy >= 7.9
    assert FLAG_HIGH_ENTROPY in by_path["payload.bin"].flags
    assert by_path["payload.bin"].risk_score >= 25

    # Compressed PNG image stays clean
    assert by_path["photo.png"].file_type == "PNG Image"
    assert FLAG_HIGH_ENTROPY not in by_path["photo.png"].flags
    assert by_path["photo.png"].risk_score == 0

    # Disguised PE PDF triggers mismatch + YARA + critical risk score + PE COFF metadata
    assert by_path["invoice.pdf"].file_type == "PE Executable (MZ/PE)"
    assert FLAG_EXTENSION_MISMATCH in by_path["invoice.pdf"].flags
    assert by_path["invoice.pdf"].metadata["pe_info"]["architecture"] == "x64 (64-bit)"
    assert by_path["invoice.pdf"].metadata["pe_info"]["sections"] == 4
    assert by_path["invoice.pdf"].risk_score >= 80
    assert by_path["invoice.pdf"].risk_level == "critical"
    assert res.max_risk_score == by_path["invoice.pdf"].risk_score
    _ = _os.name


def test_winerror_225_virus_quarantine_produces_critical_finding(monkeypatch, tmp_path: Path) -> None:
    locked = tmp_path / "real_virus.exe"
    locked.write_bytes(b"placeholder")

    def raise_win225(*_args, **_kwargs):
        exc = PermissionError(13, "Virus blocked")
        exc.winerror = 225
        raise exc

    monkeypatch.setattr("usb_analyzer.storage_scanner.scanner.analyze_file_stream", raise_win225)
    res = scan_path(tmp_path)

    assert res.has_threats is True
    assert res.max_risk_score == 100
    assert len(res.files) == 1
    assert res.files[0].path == "real_virus.exe"
    assert res.files[0].flags == ("os_detected_malware",)
    assert res.files[0].risk_level == "critical"
    assert res.errors[0]["threat"] == "antivirus_quarantined_by_os"
