"""Read-only storage scanner: SHA-256/MD5 hashing, magic file types, entropy, metadata, YARA, and risk scoring.

The scanner never mounts drives or modifies/deletes files during inspection. It
walks a target directory safely (skipping symlinks/reparse points and OS metadata
folders) and computes comprehensive static and behavioral characteristics.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
from pathlib import Path
import stat
from typing import Any

from usb_analyzer.storage_scanner.analyzer import (
    FLAG_EXTENSION_MISMATCH,
    FLAG_HIDDEN_SYSTEM,
    FLAG_HIGH_ENTROPY,
    FLAG_KEYWORD_INDICATOR,
    FLAG_OBFUSCATED_SCRIPT_ENTROPY,
    analyze_file_stream,
    detect_magic_file_type,
    extract_file_metadata,
    score_file_risk,
)
from usb_analyzer.storage_scanner.signatures import SignatureEngine

CHUNK_SIZE = 1024 * 1024

# Extensions flagged as risky per project specification
RISKY_EXTENSIONS: frozenset[str] = frozenset(
    {
        # Executables / installers
        ".exe", ".dll", ".scr", ".com", ".pif", ".msi", ".msp", ".cpl",
        ".jar", ".appx", ".msix", ".application",
        # Scripts
        ".bat", ".cmd", ".ps1", ".psm1", ".vbs", ".vbe", ".js", ".jse",
        ".wsf", ".wsh", ".hta",
        # Shortcuts / system
        ".lnk", ".scf", ".url", ".reg", ".msc", ".chm",
        # Macro-enabled Office
        ".docm", ".xlsm", ".pptm", ".dotm",
        # Disk images
        ".iso", ".img", ".vhd", ".vhdx",
    }
)

_SCRIPT_EXTENSIONS: frozenset[str] = frozenset(
    {".ps1", ".psm1", ".psd1", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh", ".hta"}
)

IGNORED_SYSTEM_DIRS: frozenset[str] = frozenset(
    {
        "system volume information",
        "$recycle.bin",
        ".trashes",
        ".spotlight-v100",
        ".fseventsd",
        ".temporaryitems",
    }
)

AUTORUN_FILENAME = "autorun.inf"

FLAG_AUTORUN = "autorun_inf"
FLAG_RISKY_EXTENSION = "risky_extension"
FLAG_DOUBLE_EXTENSION = "double_extension_masquerade"
FLAG_RTLO_SPOOF = "rtlo_filename_spoof"
_FILE_ATTRIBUTE_REPARSE_POINT = 0x400


@dataclass(frozen=True)
class FileFinding:
    path: str  # relative to the scan root, POSIX-style
    size: int
    sha256: str
    flags: tuple[str, ...] = ()
    md5: str = ""
    file_type: str = "Unknown"
    entropy: float = 0.0
    metadata: dict[str, Any] = field(default_factory=dict)
    risk_score: int = 0
    risk_level: str = "clean"
    risk_factors: tuple[dict[str, Any], ...] = ()
    change_status: str = "initial"  # "new" | "modified" | "existing" | "initial"

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "size": self.size,
            "sha256": self.sha256,
            "md5": self.md5,
            "file_type": self.file_type,
            "entropy": self.entropy,
            "metadata": self.metadata,
            "flags": list(self.flags),
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
            "risk_factors": list(self.risk_factors),
            "change_status": self.change_status,
        }


@dataclass
class ScanResult:
    root: str
    files: list[FileFinding] = field(default_factory=list)
    errors: list[dict[str, str]] = field(default_factory=list)

    @property
    def flagged(self) -> list[FileFinding]:
        return [f for f in self.files if f.flags or f.risk_score >= 20]

    @property
    def max_risk_score(self) -> int:
        return max((f.risk_score for f in self.files), default=0)

    @property
    def volume_risk_level(self) -> str:
        score = self.max_risk_score
        if score >= 80 or self.has_threats:
            return "critical"
        if score >= 50:
            return "high"
        if score >= 20 or self.flagged or self.errors:
            return "suspicious"
        return "clean"

    @property
    def has_threats(self) -> bool:
        """Return True if any high-severity malware, masquerade, or signature match was detected."""
        threat_prefixes = (
            "malware_hash:",
            "yara:",
            "eicar_test_file",
            "os_detected_malware",
            "double_extension_masquerade",
            "rtlo_filename_spoof",
            FLAG_EXTENSION_MISMATCH,
        )
        for finding in self.files:
            if finding.risk_score >= 70:
                return True
            for flag in finding.flags:
                if any(flag == p or flag.startswith(p) for p in threat_prefixes):
                    return True
        for err in self.errors:
            if err.get("threat"):
                return True
        return False

    def to_details(self) -> dict[str, Any]:
        """JSON-serialisable dict suitable for ``DeviceEvent.details``."""
        ranked_files = sorted(self.files, key=lambda f: (-f.risk_score, f.path))
        new_files = [f.path for f in self.files if f.change_status == "new"]
        modified_files = [f.path for f in self.files if f.change_status == "modified"]
        return {
            "root": self.root,
            "files_scanned": len(self.files),
            "flagged_count": len(self.flagged),
            "has_threats": self.has_threats,
            "max_risk_score": self.max_risk_score,
            "volume_risk_level": self.volume_risk_level,
            "new_files_count": len(new_files),
            "modified_files_count": len(modified_files),
            "new_files": new_files,
            "modified_files": modified_files,
            "flagged": [f.to_dict() for f in self.flagged],
            "file_analyses": [f.to_dict() for f in ranked_files[:100]],
            "errors": self.errors,
        }


def sha256_file(path: Path, chunk_size: int = CHUNK_SIZE) -> str:
    """Hash a file using chunked reads so large files are not loaded into memory."""
    if chunk_size <= 0:
        raise ValueError("chunk_size must be greater than zero")
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        while chunk := handle.read(chunk_size):
            digest.update(chunk)
    return digest.hexdigest()


def flag_file(name: str, risky_extensions: frozenset[str] = RISKY_EXTENSIONS) -> tuple[str, ...]:
    lowered = name.lower()
    normalized = {ext.lower() for ext in risky_extensions}
    flags: list[str] = []
    if lowered == AUTORUN_FILENAME:
        flags.append(FLAG_AUTORUN)
    if Path(lowered).suffix in normalized:
        flags.append(FLAG_RISKY_EXTENSION)
    if "\u202e" in name:
        flags.append(FLAG_RTLO_SPOOF)
    parts = lowered.split(".")
    if len(parts) >= 3 and f".{parts[-1]}" in normalized:
        trusted_exts = {"pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "jpg", "png", "mp4"}
        if parts[-2] in trusted_exts:
            flags.append(FLAG_DOUBLE_EXTENSION)
    return tuple(flags)


def scan_path(
    root: str | Path,
    risky_extensions: frozenset[str] = RISKY_EXTENSIONS,
    chunk_size: int = CHUNK_SIZE,
    signature_engine: SignatureEngine | None = None,
    skip_system_dirs: bool = True,
    changed_files: dict[str, str] | None = None,
) -> ScanResult:
    """Scan a folder/volume root without following symlinks or reparse points."""
    if chunk_size <= 0:
        raise ValueError("chunk_size must be greater than zero")
    root_path = Path(root)
    if _is_reparse_point(root_path):
        raise ValueError("Scan root must not be a symlink or reparse point")
    if not root_path.is_dir():
        raise NotADirectoryError(f"Not a directory: {root_path}")

    normalized_risky = {ext.lower() for ext in risky_extensions}
    result = ScanResult(root=str(root_path))
    pending = [root_path]

    while pending:
        current = pending.pop()
        try:
            entries = sorted(current.iterdir())
        except OSError as exc:
            err_dict = {"path": _rel(root_path, current), "error": type(exc).__name__}
            if getattr(exc, "winerror", None) == 225:
                err_dict["threat"] = "antivirus_quarantined_by_os"
            result.errors.append(err_dict)
            continue

        for entry in entries:
            try:
                if _is_reparse_point(entry):
                    continue
                if entry.is_dir():
                    if skip_system_dirs and entry.name.lower() in IGNORED_SYSTEM_DIRS:
                        continue
                    pending.append(entry)
                elif entry.is_file():
                    rel_path = _rel(root_path, entry)
                    st = entry.stat()
                    sha256, md5, entropy, total_size, header = analyze_file_stream(entry, chunk_size)
                    type_info = detect_magic_file_type(header, entry.suffix)
                    metadata = extract_file_metadata(entry, type_info, stat_result=st)

                    flags = list(flag_file(entry.name, risky_extensions))

                    if type_info.extension_mismatch and FLAG_EXTENSION_MISMATCH not in flags:
                        flags.append(FLAG_EXTENSION_MISMATCH)

                    ext_lower = entry.suffix.lower()
                    if ext_lower in _SCRIPT_EXTENSIONS and entropy >= 6.2:
                        flags.append(FLAG_OBFUSCATED_SCRIPT_ENTROPY)
                    elif not metadata["expected_compressed"] and entropy >= 7.2:
                        flags.append(FLAG_HIGH_ENTROPY)

                    is_os_hidden_non_dot = metadata["hidden"] and not entry.name.startswith(".")
                    if (is_os_hidden_non_dot or metadata["system"]) and (
                        entry.name.lower() == AUTORUN_FILENAME
                        or ext_lower in normalized_risky
                        or type_info.extension_mismatch
                        or metadata["system"]
                    ):
                        flags.append(FLAG_HIDDEN_SYSTEM)

                    if signature_engine is not None:
                        sig_flags = signature_engine.scan_file(entry, sha256, md5=md5)
                        for sf in sig_flags:
                            if sf not in flags:
                                flags.append(sf)

                    risk_score, risk_level, risk_factors = score_file_risk(
                        flags=flags,
                        entropy=entropy,
                        file_type=type_info,
                        metadata=metadata,
                        size_bytes=total_size,
                    )

                    change_status = changed_files.get(rel_path, "existing") if changed_files is not None else "initial"

                    result.files.append(
                        FileFinding(
                            path=rel_path,
                            size=total_size,
                            sha256=sha256,
                            flags=tuple(flags),
                            md5=md5,
                            file_type=type_info.magic_type,
                            entropy=entropy,
                            metadata=metadata,
                            risk_score=risk_score,
                            risk_level=risk_level,
                            risk_factors=risk_factors,
                            change_status=change_status,
                        )
                    )
            except OSError as exc:
                rel_err_path = _rel(root_path, entry)
                err_dict = {"path": rel_err_path, "error": type(exc).__name__}
                if getattr(exc, "winerror", None) in (225, 226):
                    err_dict["threat"] = "antivirus_quarantined_by_os"
                    try:
                        l_st = entry.lstat()
                        l_size = int(l_st.st_size)
                    except OSError:
                        l_size = 0
                    change_status = changed_files.get(rel_err_path, "existing") if changed_files is not None else "initial"
                    result.files.append(
                        FileFinding(
                            path=rel_err_path,
                            size=l_size,
                            sha256="(locked by OS Antivirus)",
                            md5="(locked by OS Antivirus)",
                            flags=("os_detected_malware",),
                            file_type="OS Quarantined Virus Payload",
                            entropy=0.0,
                            metadata={
                                "extension": entry.suffix.lower() or "(none)",
                                "magic_type": "OS Quarantined Virus Payload",
                                "hidden": entry.name.startswith("."),
                                "system": False,
                                "readonly": False,
                            },
                            risk_score=100,
                            risk_level="critical",
                            risk_factors=(
                                {
                                    "indicator": "os_detected_malware",
                                    "category": "signature",
                                    "points": 100,
                                    "detail": f"OS kernel/Defender blocked file read (WinError {getattr(exc, 'winerror', '')}): virus or unwanted software detected",
                                },
                            ),
                            change_status=change_status,
                        )
                    )
                result.errors.append(err_dict)

    result.files.sort(key=lambda f: f.path)
    return result


def _rel(root: Path, path: Path) -> str:
    return path.relative_to(root).as_posix() if path != root else "."


def _is_reparse_point(path: Path) -> bool:
    metadata = path.lstat()
    return stat.S_ISLNK(metadata.st_mode) or bool(
        getattr(metadata, "st_file_attributes", 0) & _FILE_ATTRIBUTE_REPARSE_POINT
    )
