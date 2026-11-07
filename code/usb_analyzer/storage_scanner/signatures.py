"""Malware signatures, YARA-compatible rules, and known hash matching.

Supports EICAR test file, malicious autorun commands, macro droppers,
PowerShell cradles, and custom YARA / regex rule signatures.
"""

from dataclasses import dataclass, field
import hashlib
from pathlib import Path
import re
from typing import Any, Callable

EICAR_SHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
EICAR_STRING = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"

# Known malicious file hashes (SHA-256)
KNOWN_MALWARE_HASHES: dict[str, str] = {
    EICAR_SHA256: "EICAR Standard Anti-Virus Test File (EICAR.org)",
}


@dataclass
class YaraRule:
    """YARA-compatible signature rule definition."""

    name: str
    description: str
    severity: str = "critical"
    patterns: list[bytes] = field(default_factory=list)
    regexes: list[re.Pattern] = field(default_factory=list)
    condition: str = "any"  # "any" or "all"

    def match(self, content: bytes, filename: str = "") -> bool:
        matches = 0
        total_checks = len(self.patterns) + len(self.regexes)
        if total_checks == 0:
            return False

        for pattern in self.patterns:
            if pattern in content:
                matches += 1
                if self.condition == "any":
                    return True

        for regex in self.regexes:
            if regex.search(content):
                matches += 1
                if self.condition == "any":
                    return True

        return matches == total_checks if self.condition == "all" else False


def _build_default_rules() -> list[YaraRule]:
    return [
        YaraRule(
            name="EICAR_Test_File",
            description="Matches EICAR standard antivirus test signature",
            severity="critical",
            patterns=[EICAR_STRING],
            condition="any",
        ),
        YaraRule(
            name="Suspicious_Autorun_Inf",
            description="Autorun configuration that automatically executes a binary or script",
            severity="critical",
            regexes=[
                re.compile(rb"(?i)open\s*=\s*.*\.(exe|bat|cmd|vbs|ps1|scr)", re.IGNORECASE),
                re.compile(rb"(?i)shellexecute\s*=\s*.*\.(exe|bat|cmd|vbs|ps1|scr)", re.IGNORECASE),
                re.compile(rb"(?i)action\s*=\s*.*", re.IGNORECASE),
            ],
            condition="any",
        ),
        YaraRule(
            name="PowerShell_Download_Cradle",
            description="PowerShell script containing remote execution download cradle",
            severity="critical",
            regexes=[
                re.compile(rb"(?i)DownloadString\s*\(", re.IGNORECASE),
                re.compile(rb"(?i)DownloadFile\s*\(", re.IGNORECASE),
                re.compile(rb"(?i)Invoke-Expression.*(http|https)", re.IGNORECASE),
                re.compile(rb"(?i)IEX\s*\(.*(http|https)", re.IGNORECASE),
            ],
            condition="any",
        ),
        YaraRule(
            name="Macro_AutoExec",
            description="Office document containing automatic macro execution routines",
            severity="warning",
            regexes=[
                re.compile(rb"(?i)(Sub\s+AutoOpen|Sub\s+Document_Open|Sub\s+Auto_Open)", re.IGNORECASE),
                re.compile(rb"(?i)(AutoExec|Workbook_Open)", re.IGNORECASE),
            ],
            condition="any",
        ),
    ]


class SignatureEngine:
    """Matches files against known malware hashes and YARA signature rules."""

    def __init__(
        self,
        known_hashes: dict[str, str] | None = None,
        custom_rules: list[YaraRule] | None = None,
    ) -> None:
        self.known_hashes = dict(KNOWN_MALWARE_HASHES)
        if known_hashes:
            self.known_hashes.update(known_hashes)

        self.rules = _build_default_rules()
        if custom_rules:
            self.rules.extend(custom_rules)

        self._has_native_yara = False
        try:
            import yara  # noqa: F401
            self._has_native_yara = True
        except ImportError:
            pass

    def check_hash(self, sha256: str) -> str | None:
        """Return threat name if SHA-256 is in the known malware hash list."""
        return self.known_hashes.get(sha256.lower())

    def scan_content(
        self,
        content: bytes,
        filename: str = "",
    ) -> list[tuple[str, str, str]]:
        """Scan file bytes against rules.
        
        Returns a list of tuples: (rule_name, severity, description).
        """
        matches: list[tuple[str, str, str]] = []
        for rule in self.rules:
            if rule.match(content, filename):
                matches.append((rule.name, rule.severity, rule.description))
        return matches

    def scan_file(
        self,
        file_path: Path,
        sha256: str,
        max_bytes: int = 5 * 1024 * 1024,
    ) -> list[str]:
        """Inspect a file by hash and content signatures, returning flags."""
        flags: list[str] = []

        # 1. Hash check
        threat_name = self.check_hash(sha256)
        if threat_name:
            flags.append(f"malware_hash:{threat_name}")
            if "eicar" in threat_name.lower():
                flags.append("eicar_test_file")

        # 2. Content scan (read up to max_bytes to avoid loading gigantic files)
        try:
            with open(file_path, "rb") as f:
                content = f.read(max_bytes)

            rule_matches = self.scan_content(content, filename=file_path.name)
            for rule_name, _, _ in rule_matches:
                flags.append(f"yara:{rule_name}")
                if rule_name == "EICAR_Test_File" and "eicar_test_file" not in flags:
                    flags.append("eicar_test_file")
        except OSError:
            pass

        return flags
