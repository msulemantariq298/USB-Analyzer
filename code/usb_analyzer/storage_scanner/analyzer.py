"""Deep static & behavioral file analysis for removable USB media.

Computes single-pass SHA-256 and MD5 hashes, Shannon entropy, magic-byte file
type verification (plus COFF/PE header metadata), OS file attributes/timestamps,
and an explainable 0-100 risk score with per-indicator weight breakdowns.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import math
import os
from pathlib import Path
import stat
import struct
from typing import Any

FLAG_EXTENSION_MISMATCH = "extension_signature_mismatch"
FLAG_HIGH_ENTROPY = "high_entropy_packed"
FLAG_OBFUSCATED_SCRIPT_ENTROPY = "obfuscated_script_entropy"
FLAG_HIDDEN_SYSTEM = "hidden_system_attribute"
FLAG_KEYWORD_INDICATOR = "suspicious_keyword_indicator"

_HEADER_SAMPLE_BYTES = 8192
_FILE_ATTRIBUTE_READONLY = getattr(stat, "FILE_ATTRIBUTE_READONLY", 0x1)
_FILE_ATTRIBUTE_HIDDEN = getattr(stat, "FILE_ATTRIBUTE_HIDDEN", 0x2)
_FILE_ATTRIBUTE_SYSTEM = getattr(stat, "FILE_ATTRIBUTE_SYSTEM", 0x4)

_NATURALLY_COMPRESSED_EXTENSIONS: frozenset[str] = frozenset(
    {
        ".zip", ".7z", ".rar", ".gz", ".bz2", ".xz", ".tar", ".tgz", ".cab",
        ".jpg", ".jpeg", ".png", ".gif", ".webp", ".heic", ".avif",
        ".mp3", ".aac", ".ogg", ".flac", ".m4a", ".mp4", ".mkv", ".avi", ".mov", ".webm",
        ".docx", ".xlsx", ".pptx", ".odt", ".ods", ".odp", ".pdf",
        ".jar", ".apk", ".whl", ".iso", ".img",
    }
)

_SCRIPT_EXTENSIONS: frozenset[str] = frozenset(
    {".ps1", ".psm1", ".psd1", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh", ".hta", ".py"}
)

_BENIGN_DOCUMENT_OR_MEDIA_EXTENSIONS: frozenset[str] = frozenset(
    {
        ".txt", ".csv", ".log", ".md", ".pdf", ".doc", ".docx", ".xls", ".xlsx",
        ".ppt", ".pptx", ".rtf", ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp",
        ".mp3", ".wav", ".mp4", ".avi", ".mov",
    }
)

_OFFICE_OPENXML_EXTENSIONS: frozenset[str] = frozenset({".docx", ".xlsx", ".pptx", ".odt", ".ods", ".odp"})

_MAGIC_SIGNATURES: tuple[tuple[bytes, int, str, str, bool], ...] = (
    (b"MZ", 0, "PE Executable (MZ/PE)", "application/x-dosexec", False),
    (b"\x7fELF", 0, "ELF Executable", "application/x-elf", False),
    (b"\xfe\xed\xfa\xce", 0, "Mach-O Binary", "application/x-mach-binary", False),
    (b"\xce\xfa\xed\xfe", 0, "Mach-O Binary", "application/x-mach-binary", False),
    (b"\xfe\xed\xfa\xcf", 0, "Mach-O 64-bit Binary", "application/x-mach-binary", False),
    (b"\xcf\xfa\xed\xfe", 0, "Mach-O 64-bit Binary", "application/x-mach-binary", False),
    (b"L\x00\x00\x00\x01\x14\x02\x00", 0, "Windows Shortcut (LNK)", "application/x-ms-shortcut", False),
    (b"%PDF-", 0, "PDF Document", "application/pdf", True),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", 0, "Legacy Office / MSI (OLE2)", "application/x-ole-storage", False),
    (b"Rar!\x1a\x07", 0, "RAR Archive", "application/vnd.rar", True),
    (b"7z\xbc\xaf\x27\x1c", 0, "7-Zip Archive", "application/x-7z-compressed", True),
    (b"\x1f\x8b\x08", 0, "GZIP Archive", "application/gzip", True),
    (b"\x89PNG\r\n\x1a\n", 0, "PNG Image", "image/png", True),
    (b"\xff\xd8\xff", 0, "JPEG Image", "image/jpeg", True),
    (b"GIF87a", 0, "GIF Image", "image/gif", True),
    (b"GIF89a", 0, "GIF Image", "image/gif", True),
    (b"BM", 0, "BMP Image", "image/bmp", False),
    (b"SQLite format 3\x00", 0, "SQLite Database", "application/vnd.sqlite3", False),
    (b"RIFF", 0, "RIFF Media", "application/octet-stream", True),
)

_MACHINE_NAMES: dict[int, str] = {
    0x014C: "x86 (32-bit)",
    0x8664: "x64 (64-bit)",
    0xAA64: "ARM64",
    0x01C4: "ARMv7",
}


@dataclass(frozen=True)
class FileTypeInfo:
    magic_type: str
    mime_hint: str
    expected_compressed: bool
    extension_mismatch: bool
    mismatch_detail: str | None = None
    pe_info: dict[str, Any] | None = None


def calculate_shannon_entropy(data: bytes) -> float:
    """Compute Shannon entropy in bits/byte (0.00 - 8.00)."""
    if not data:
        return 0.0
    counts = [0] * 256
    for byte in data:
        counts[byte] += 1
    return _entropy_from_counts(counts, len(data))


def _entropy_from_counts(counts: list[int], total: int) -> float:
    if total <= 0:
        return 0.0
    entropy = 0.0
    for count in counts:
        if count:
            p = count / total
            entropy -= p * math.log2(p)
    return round(min(8.0, max(0.0, entropy)), 2)


def analyze_file_stream(path: Path, chunk_size: int = 1024 * 1024) -> tuple[str, str, float, int, bytes]:
    """Read a file in chunks once, returning (sha256, md5, entropy, size_bytes, header_sample)."""
    if chunk_size <= 0:
        raise ValueError("chunk_size must be greater than zero")

    sha256_h = hashlib.sha256()
    md5_h = hashlib.md5()
    counts = [0] * 256
    total_bytes = 0
    header_parts: list[bytes] = []
    header_collected = 0

    with open(path, "rb") as handle:
        while chunk := handle.read(chunk_size):
            sha256_h.update(chunk)
            md5_h.update(chunk)
            total_bytes += len(chunk)
            if header_collected < _HEADER_SAMPLE_BYTES:
                take = min(len(chunk), _HEADER_SAMPLE_BYTES - header_collected)
                header_parts.append(chunk[:take])
                header_collected += take
            for idx in range(256):
                c = chunk.count(idx)
                if c:
                    counts[idx] += c

    entropy = _entropy_from_counts(counts, total_bytes)
    return sha256_h.hexdigest(), md5_h.hexdigest(), entropy, total_bytes, b"".join(header_parts)


def extract_pe_metadata(header: bytes) -> dict[str, Any] | None:
    """Parse minimal DOS + COFF header metadata from a Windows PE binary without modifying it."""
    if len(header) < 64 or not header.startswith(b"MZ"):
        return None
    try:
        pe_offset = struct.unpack_from("<I", header, 0x3C)[0]
    except struct.error:
        return None
    if pe_offset + 24 > len(header) or header[pe_offset : pe_offset + 4] != b"PE\x00\x00":
        return None
    try:
        machine, num_sections, time_stamp, _, _, _, characteristics = struct.unpack_from(
            "<HHIIIHH", header, pe_offset + 4
        )
    except struct.error:
        return None

    compiled_at = None
    if time_stamp > 0:
        try:
            compiled_at = datetime.fromtimestamp(time_stamp, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        except (OSError, OverflowError, ValueError):
            compiled_at = None

    return {
        "architecture": _MACHINE_NAMES.get(machine, f"0x{machine:04X}"),
        "sections": int(num_sections),
        "is_dll": bool(characteristics & 0x2000),
        "compiled_at": compiled_at,
    }


def _looks_like_text(sample: bytes) -> bool:
    if not sample:
        return False
    if b"\x00" in sample:
        return False
    printable = sum(1 for b in sample if 32 <= b <= 126 or b in (9, 10, 13))
    return (printable / len(sample)) >= 0.85


def _looks_like_script_or_markup(sample: bytes) -> bool:
    lowered = sample[:512].lstrip().lower()
    script_markers = (
        b"#!",
        b"@echo",
        b"powershell",
        b"invoke-expression",
        b"<script",
        b"<hta:application",
        b"createobject(",
        b"wscript.",
    )
    return any(marker in lowered for marker in script_markers)


def detect_magic_file_type(header: bytes, extension: str = "") -> FileTypeInfo:
    """Identify true file format from magic bytes and check for extension spoofing."""
    ext = extension.lower()
    if not header:
        return FileTypeInfo("Empty File", "inode/x-empty", False, False)

    pe_info = extract_pe_metadata(header)

    # ZIP-based containers (OOXML documents, JAR, ZIP)
    if header.startswith(b"PK\x03\x04") or header.startswith(b"PK\x05\x06"):
        if ext in _OFFICE_OPENXML_EXTENSIONS:
            return FileTypeInfo("OOXML Document", "application/vnd.openxmlformats-officedocument", True, False)
        if ext == ".jar":
            return FileTypeInfo("Java Archive (JAR)", "application/java-archive", True, False)
        if ext in _NATURALLY_COMPRESSED_EXTENSIONS:
            return FileTypeInfo("ZIP Archive", "application/zip", True, False)
        mismatch = ext in _BENIGN_DOCUMENT_OR_MEDIA_EXTENSIONS
        return FileTypeInfo(
            "ZIP Archive",
            "application/zip",
            True,
            mismatch,
            f"Archive signature (PK) disguised with '{ext}' extension" if mismatch else None,
        )

    for sig, offset, label, mime, compressed in _MAGIC_SIGNATURES:
        if len(header) >= offset + len(sig) and header[offset : offset + len(sig)] == sig:
            # Verify MZ has either PE header or non-text binary bytes so plain prose starting with 'MZ' is ignored
            if sig == b"MZ" and pe_info is None and (len(header) < 64 or _looks_like_text(header[:256])):
                continue
            mismatch = False
            detail = None
            if label in ("PE Executable (MZ/PE)", "ELF Executable", "Mach-O Binary", "Mach-O 64-bit Binary"):
                if ext and ext not in {".exe", ".dll", ".sys", ".scr", ".com", ".efi", ".drv", ".ocx", ".bin", ".elf", ".so"}:
                    mismatch = True
                    detail = f"{label} binary signature disguised as '{ext}'"
            elif label == "Windows Shortcut (LNK)" and ext and ext != ".lnk":
                mismatch = True
                detail = f"Windows LNK shortcut binary disguised as '{ext}'"
            elif label == "PDF Document" and ext and ext not in {".pdf"} and ext in _BENIGN_DOCUMENT_OR_MEDIA_EXTENSIONS:
                mismatch = True
                detail = f"PDF document signature does not match extension '{ext}'"
            elif label in ("PNG Image", "JPEG Image", "GIF Image") and ext in _SCRIPT_EXTENSIONS | {".exe", ".dll", ".scr"}:
                mismatch = True
                detail = f"{label} signature inside executable/script extension '{ext}'"

            return FileTypeInfo(label, mime, compressed, mismatch, detail, pe_info=pe_info)

    if len(header) >= 0x8006 and header[0x8001:0x8006] == b"CD001":
        return FileTypeInfo("ISO Disk Image", "application/x-iso9660-image", True, False)

    if _looks_like_text(header[:1024]):
        is_script = _looks_like_script_or_markup(header)
        if is_script and ext in {".jpg", ".jpeg", ".png", ".gif", ".pdf", ".mp3", ".mp4"}:
            return FileTypeInfo(
                "Embedded Script Payload",
                "text/x-script",
                False,
                True,
                f"Active script syntax hidden inside '{ext}' media/document file",
            )
        if ext in _SCRIPT_EXTENSIONS or is_script:
            return FileTypeInfo("Text / Script", "text/plain", False, False)
        if ext in {".inf", ".ini", ".cfg", ".conf", ".json", ".xml", ".yaml", ".yml"}:
            return FileTypeInfo("Text / Configuration", "text/plain", False, False)
        return FileTypeInfo("Text / Document", "text/plain", False, False)

    return FileTypeInfo(
        "Binary Data",
        "application/octet-stream",
        ext in _NATURALLY_COMPRESSED_EXTENSIONS,
        False,
    )


def extract_file_metadata(
    path: Path,
    type_info: FileTypeInfo,
    stat_result: os.stat_result | None = None,
) -> dict[str, Any]:
    """Collect normalized file metadata including timestamps and OS attributes."""
    st = stat_result if stat_result is not None else path.stat()
    ext = path.suffix.lower() or "(none)"

    file_attrs = getattr(st, "st_file_attributes", 0)
    is_hidden = path.name.startswith(".") or bool(file_attrs & _FILE_ATTRIBUTE_HIDDEN)
    is_system = bool(file_attrs & _FILE_ATTRIBUTE_SYSTEM)
    is_readonly = bool(file_attrs & _FILE_ATTRIBUTE_READONLY) or not bool(st.st_mode & 0o200)

    created_ts = getattr(st, "st_birthtime", None)
    if created_ts is None:
        created_ts = st.st_ctime

    meta: dict[str, Any] = {
        "extension": ext,
        "magic_type": type_info.magic_type,
        "mime_hint": type_info.mime_hint,
        "expected_compressed": type_info.expected_compressed,
        "extension_mismatch": type_info.extension_mismatch,
        "created_at": datetime.fromtimestamp(created_ts, tz=timezone.utc).isoformat().replace("+00:00", "Z"),
        "modified_at": datetime.fromtimestamp(st.st_mtime, tz=timezone.utc).isoformat().replace("+00:00", "Z"),
        "hidden": is_hidden,
        "system": is_system,
        "readonly": is_readonly,
    }
    if type_info.mismatch_detail:
        meta["mismatch_detail"] = type_info.mismatch_detail
    if type_info.pe_info:
        meta["pe_info"] = type_info.pe_info
    return meta


def classify_entropy_band(entropy: float, expected_compressed: bool = False) -> str:
    if expected_compressed and entropy >= 6.8:
        return "compressed"
    if entropy >= 7.2:
        return "high_packed"
    if entropy >= 6.8:
        return "elevated"
    if entropy < 3.5:
        return "low"
    return "normal"


def score_file_risk(
    *,
    flags: tuple[str, ...] | list[str],
    entropy: float,
    file_type: FileTypeInfo,
    metadata: dict[str, Any],
    size_bytes: int,
) -> tuple[int, str, tuple[dict[str, Any], ...]]:
    """Calculate explainable 0-100 risk score, severity tier, and contributing factors."""
    factors: list[dict[str, Any]] = []
    seen_indicators: set[str] = set()

    def _add(indicator: str, category: str, points: int, detail: str) -> None:
        if indicator in seen_indicators:
            return
        seen_indicators.add(indicator)
        factors.append({
            "indicator": indicator,
            "category": category,
            "points": points,
            "detail": detail,
        })

    for flag in flags:
        if flag == "eicar_test_file" or flag.startswith("malware_hash:"):
            _add("known_malware_hash", "hash", 100, f"Matched known malware digest/test signature ({flag})")
        elif flag.startswith("yara:"):
            rule_name = flag.split(":", 1)[1]
            if rule_name == "Macro_AutoExec":
                _add(flag, "signature", 40, f"YARA heuristic matched automatic macro execution ({rule_name})")
            elif rule_name == "Double_Extension_Masquerade" or rule_name == "RTLO_Character_Spoof":
                _add(flag, "file_type", 50, f"YARA spoofing rule matched ({rule_name})")
            else:
                _add(flag, "signature", 75, f"YARA signature rule matched ({rule_name})")
        elif flag == "os_detected_malware":
            _add(flag, "signature", 90, "Blocked/quarantined by OS security engine")
        elif flag == FLAG_EXTENSION_MISMATCH:
            _add(
                flag,
                "file_type",
                55,
                file_type.mismatch_detail or f"File signature '{file_type.magic_type}' conflicts with declared extension",
            )
        elif flag == "double_extension_masquerade":
            _add(flag, "file_type", 50, "Filename uses double extension to mask executable type")
        elif flag == "rtlo_filename_spoof":
            _add(flag, "file_type", 55, "Unicode Right-to-Left Override (U+202E) character spoofing in filename")
        elif flag == "autorun_inf":
            _add(flag, "behavioral", 35, "USB autorun.inf auto-execution configuration present")
        elif flag == FLAG_HIGH_ENTROPY:
            _add(flag, "entropy", 25, f"High Shannon entropy ({entropy:.2f} bits/byte) suggests packing or encryption")
        elif flag == FLAG_OBFUSCATED_SCRIPT_ENTROPY:
            _add(flag, "entropy", 20, f"Elevated script entropy ({entropy:.2f} bits/byte) suggests obfuscated payload")
        elif flag == FLAG_HIDDEN_SYSTEM:
            _add(flag, "metadata", 20, "Suspicious hidden/system file attribute on removable USB file")
        elif flag == FLAG_KEYWORD_INDICATOR:
            _add(flag, "behavioral", 25, "Filename or contents reference suspicious malware indicators")
        elif flag == "risky_extension":
            ext = metadata.get("extension") or ""
            _add(flag, "behavioral", 20, f"Executable or active script file type ({ext}) present on USB")

    total = min(100, sum(f["points"] for f in factors))
    if total >= 80:
        level = "critical"
    elif total >= 50:
        level = "high"
    elif total >= 20:
        level = "suspicious"
    else:
        level = "clean"

    # Surface entropy band even on non-flagged files when contextually interesting? Keep factors crisp!
    _ = size_bytes  # reserved for size heuristics without unused warning
    return total, level, tuple(factors)
