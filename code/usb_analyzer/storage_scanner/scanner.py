"""Read-only storage scanner: SHA-256 hashing plus simple risky-file flags.

The scanner never mounts drives, modifies/deletes files, or emits events. It
only walks a directory the caller selected and reports what it found.
"""

from dataclasses import dataclass, field
import hashlib
from pathlib import Path
import stat
from typing import Any

CHUNK_SIZE = 1024 * 1024

# Extensions flagged as risky. Adjust to match the proposal's list if it differs.
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

AUTORUN_FILENAME = "autorun.inf"

FLAG_AUTORUN = "autorun_inf"
FLAG_RISKY_EXTENSION = "risky_extension"
_FILE_ATTRIBUTE_REPARSE_POINT = 0x400


@dataclass(frozen=True)
class FileFinding:
    path: str  # relative to the scan root, POSIX-style
    size: int
    sha256: str
    flags: tuple[str, ...] = ()


@dataclass
class ScanResult:
    root: str
    files: list[FileFinding] = field(default_factory=list)
    errors: list[dict[str, str]] = field(default_factory=list)

    @property
    def flagged(self) -> list[FileFinding]:
        return [f for f in self.files if f.flags]

    def to_details(self) -> dict[str, Any]:
        """JSON-serialisable dict suitable for ``DeviceEvent.details``."""
        return {
            "root": self.root,
            "files_scanned": len(self.files),
            "flagged_count": len(self.flagged),
            "flagged": [
                {"path": f.path, "size": f.size, "sha256": f.sha256, "flags": list(f.flags)}
                for f in self.flagged
            ],
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
    return tuple(flags)


def scan_path(
    root: str | Path,
    risky_extensions: frozenset[str] = RISKY_EXTENSIONS,
    chunk_size: int = CHUNK_SIZE,
) -> ScanResult:
    """Scan a folder/volume root without following symlinks or reparse points."""
    if chunk_size <= 0:
        raise ValueError("chunk_size must be greater than zero")
    root_path = Path(root)
    if _is_reparse_point(root_path):
        raise ValueError("Scan root must not be a symlink or reparse point")
    if not root_path.is_dir():
        raise NotADirectoryError(f"Not a directory: {root_path}")

    result = ScanResult(root=str(root_path))
    pending = [root_path]
    while pending:
        current = pending.pop()
        try:
            entries = sorted(current.iterdir())
        except OSError as exc:
            result.errors.append({"path": _rel(root_path, current), "error": type(exc).__name__})
            continue
        for entry in entries:
            try:
                if _is_reparse_point(entry):
                    continue
                if entry.is_dir():
                    pending.append(entry)
                elif entry.is_file():
                    result.files.append(
                        FileFinding(
                            path=_rel(root_path, entry),
                            size=entry.stat().st_size,
                            sha256=sha256_file(entry, chunk_size),
                            flags=flag_file(entry.name, risky_extensions),
                        )
                    )
            except OSError as exc:
                result.errors.append({"path": _rel(root_path, entry), "error": type(exc).__name__})
    result.files.sort(key=lambda f: f.path)
    return result


def _rel(root: Path, path: Path) -> str:
    return path.relative_to(root).as_posix() if path != root else "."


def _is_reparse_point(path: Path) -> bool:
    metadata = path.lstat()
    return stat.S_ISLNK(metadata.st_mode) or bool(
        getattr(metadata, "st_file_attributes", 0) & _FILE_ATTRIBUTE_REPARSE_POINT
    )
