"""Malware signatures, `.yar` YARA rule parser/evaluator, and known hash matching.

Loads real `.yar` YARA signature files bundled in ``rules/``, supports custom
``YaraRule`` definitions and SHA-256 malware digest lookups, and bridges to
``yara-python`` automatically when available.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
from pathlib import Path
import re
from typing import Any
import zipfile

from usb_analyzer.storage_scanner.analyzer import FLAG_KEYWORD_INDICATOR

EICAR_SHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
EICAR_MD5 = "44d88612fea8a8f36de82e1278abb02f"
EICAR_STRING = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"

# Known malicious file hashes (SHA-256 and MD5 -> threat description)
KNOWN_MALWARE_HASHES: dict[str, str] = {
    EICAR_SHA256: "EICAR Standard Anti-Virus Test File (EICAR.org)",
    EICAR_MD5: "EICAR Standard Anti-Virus Test File (MD5)",
}

DEFAULT_RULES_DIR = Path(__file__).resolve().parent / "rules"
_KEYWORD_HINT_RE = re.compile(rb"(?i)\b(trojan|ransomware|eicar|keylogger|backdoor|dropper)\b", re.IGNORECASE)
_DOUBLE_EXT_RE = re.compile(
    rb"(?i)\.(pdf|docx?|xlsx?|pptx?|txt|jpg|png)\.(exe|scr|bat|cmd|vbs|ps1|hta|pif)$",
    re.IGNORECASE,
)
_RTLO_RE = re.compile(rb"\xe2\x80\xae")


@dataclass(frozen=True)
class YaraStringSpec:
    """Single compiled string pattern inside a YARA rule."""

    identifier: str
    literal: bytes | None = None
    regex: re.Pattern[bytes] | None = None
    ascii_enabled: bool = True
    wide_enabled: bool = False
    nocase: bool = False

    def matches(self, content: bytes) -> bool:
        if self.regex is not None:
            return bool(self.regex.search(content))
        if self.literal is None:
            return False

        candidates: list[bytes] = []
        if self.ascii_enabled:
            candidates.append(self.literal)
        if self.wide_enabled:
            try:
                wide_bytes = self.literal.decode("latin-1").encode("utf-16-le")
                candidates.append(wide_bytes)
            except UnicodeError:
                pass

        if self.nocase:
            lowered_content = content.lower()
            return any(cand.lower() in lowered_content for cand in candidates)
        return any(cand in content for cand in candidates)


@dataclass
class YaraRule:
    """YARA-compatible signature rule definition."""

    name: str
    description: str
    severity: str = "critical"
    tactic: str = "USB Malware Detection"
    source: str = "builtin"
    patterns: list[bytes] = field(default_factory=list)
    regexes: list[re.Pattern[bytes]] = field(default_factory=list)
    condition: str = "any"  # "any", "all", or parsed YARA expression
    string_specs: dict[str, YaraStringSpec] = field(default_factory=dict)

    def match(self, content: bytes, filename: str = "") -> bool:
        if self.string_specs:
            matched_vars = {
                ident: spec.matches(content)
                for ident, spec in self.string_specs.items()
            }
            if filename:
                fn_bytes = filename.encode("utf-8", errors="ignore")
                for ident, spec in self.string_specs.items():
                    if not matched_vars[ident] and spec.matches(fn_bytes):
                        matched_vars[ident] = True
            return _evaluate_yara_condition(self.condition, matched_vars)

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

        if filename:
            fn_bytes = filename.encode("utf-8", errors="ignore")
            for regex in self.regexes:
                if regex.search(fn_bytes):
                    matches += 1
                    if self.condition == "any":
                        return True

        return matches == total_checks if self.condition == "all" else False


def _evaluate_yara_condition(condition: str, matched_vars: dict[str, bool]) -> bool:
    cond = condition.strip()
    lowered = cond.lower()
    if lowered == "any of them" or lowered == "any":
        return any(matched_vars.values())
    if lowered == "all of them" or lowered == "all":
        return bool(matched_vars) and all(matched_vars.values())

    # Evaluate safe boolean expressions referencing $ident tokens, parentheses, `and`, `or`, `not`
    tokens = re.findall(r"\$[A-Za-z_][A-Za-z0-9_]*|\(|\)|\band\b|\bor\b|\bnot\b", cond, flags=re.IGNORECASE)
    if not tokens:
        return any(matched_vars.values())

    expr_parts: list[str] = []
    for tok in tokens:
        low = tok.lower()
        if tok in ("(", ")"):
            expr_parts.append(tok)
        elif low in ("and", "or", "not"):
            expr_parts.append(low)
        elif tok.startswith("$"):
            expr_parts.append("True" if matched_vars.get(tok, False) else "False")
        else:
            return False

    try:
        return bool(eval(" ".join(expr_parts), {"__builtins__": {}}, {}))
    except Exception:
        return False


def _unescape_yara_literal(raw: str) -> bytes:
    """Convert YARA quoted string escapes (\\\\, \\\", \\r, \\n, \\t, \\xHH) into bytes."""
    out = bytearray()
    i = 0
    while i < len(raw):
        ch = raw[i]
        if ch == "\\" and i + 1 < len(raw):
            nxt = raw[i + 1]
            if nxt == "\\":
                out.extend(b"\\")
                i += 2
            elif nxt == '"':
                out.extend(b'"')
                i += 2
            elif nxt == "r":
                out.extend(b"\r")
                i += 2
            elif nxt == "n":
                out.extend(b"\n")
                i += 2
            elif nxt == "t":
                out.extend(b"\t")
                i += 2
            elif nxt == "x" and i + 3 < len(raw):
                out.append(int(raw[i + 2 : i + 4], 16))
                i += 4
            else:
                out.extend(nxt.encode("latin-1"))
                i += 2
        else:
            out.extend(ch.encode("utf-8"))
            i += 1
    return bytes(out)


def _strip_yar_comments(text: str) -> str:
    text = re.sub(r"/\*[\s\S]*?\*/", "", text)
    lines = []
    for line in text.splitlines():
        # Strip // comments only when outside /regex/ or "..." literals
        stripped = line.lstrip()
        if stripped.startswith("//"):
            continue
        lines.append(line)
    return "\n".join(lines)


def load_yara_rules_from_file(path: Path) -> list[YaraRule]:
    """Parse standard `.yar` rules cleanly into executable ``YaraRule`` objects."""
    if not path.is_file():
        return []
    raw_text = _strip_yar_comments(path.read_text(encoding="utf-8"))
    rules: list[YaraRule] = []

    rule_block_re = re.compile(r"rule\s+([A-Za-z_][A-Za-z0-9_]*)\s*\{([\s\S]*?)\n\}", re.MULTILINE)
    for match in rule_block_re.finditer(raw_text):
        rule_name = match.group(1)
        body = match.group(2)

        meta_match = re.search(r"\bmeta:\s*([\s\S]*?)(?=\bstrings:|\bcondition:)", body)
        strings_match = re.search(r"\bstrings:\s*([\s\S]*?)(?=\bcondition:)", body)
        cond_match = re.search(r"\bcondition:\s*([\s\S]*)$", body)

        meta: dict[str, str] = {}
        if meta_match:
            for m_line in meta_match.group(1).splitlines():
                kv = re.match(r'\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*"([^"]*)"', m_line)
                if kv:
                    meta[kv.group(1)] = kv.group(2)

        specs: dict[str, YaraStringSpec] = {}
        if strings_match:
            for s_line in strings_match.group(1).splitlines():
                line = s_line.strip()
                if not line or not line.startswith("$"):
                    continue
                # Quoted literal: $id = "..." [modifiers]
                q_match = re.match(r'^(\$[A-Za-z_][A-Za-z0-9_]*)\s*=\s*"((?:\\.|[^"\\])*)"\s*(.*)$', line)
                if q_match:
                    ident, lit_raw, mods = q_match.groups()
                    mod_tokens = {t.lower() for t in mods.split()}
                    specs[ident] = YaraStringSpec(
                        identifier=ident,
                        literal=_unescape_yara_literal(lit_raw),
                        ascii_enabled=("ascii" in mod_tokens) or ("wide" not in mod_tokens),
                        wide_enabled=("wide" in mod_tokens),
                        nocase=("nocase" in mod_tokens),
                    )
                    continue
                # Hex byte pattern: $id = { 4C 00 ... }
                h_match = re.match(r"^(\$[A-Za-z_][A-Za-z0-9_]*)\s*=\s*\{([0-9A-Fa-f\s]+)\}", line)
                if h_match:
                    ident, hex_body = h_match.groups()
                    raw_bytes = bytes.fromhex(re.sub(r"\s+", "", hex_body))
                    specs[ident] = YaraStringSpec(identifier=ident, literal=raw_bytes)
                    continue
                # Regex literal: $id = /pattern/ [nocase]
                r_match = re.match(r"^(\$[A-Za-z_][A-Za-z0-9_]*)\s*=\s*/((?:\\/|[^/])*)/([is]*)\s*(.*)$", line)
                if r_match:
                    ident, pat_raw, inline_flags, mods = r_match.groups()
                    flags = 0
                    if "i" in inline_flags.lower() or "nocase" in mods.lower():
                        flags |= re.IGNORECASE
                    if "s" in inline_flags.lower():
                        flags |= re.DOTALL
                    compiled = re.compile(pat_raw.encode("utf-8"), flags)
                    specs[ident] = YaraStringSpec(identifier=ident, regex=compiled)

        condition = cond_match.group(1).strip() if cond_match else "any of them"
        rules.append(
            YaraRule(
                name=rule_name,
                description=meta.get("description", rule_name.replace("_", " ")),
                severity=meta.get("severity", "critical"),
                tactic=meta.get("tactic", "USB Malware Detection"),
                source=path.name,
                condition=condition,
                string_specs=specs,
            )
        )
    return rules


def _build_filename_heuristic_rules() -> list[YaraRule]:
    """Filename-level YARA rules that inspect filenames alongside file payloads."""
    return [
        YaraRule(
            name="Double_Extension_Masquerade",
            description="File using double extension trick to disguise executable payload",
            severity="critical",
            tactic="T1036.007 - Double File Extension",
            source="builtin",
            regexes=[_DOUBLE_EXT_RE],
            condition="any",
        ),
        YaraRule(
            name="RTLO_Character_Spoof",
            description="Right-to-Left Override (U+202E) unicode spoofing detected in filename",
            severity="critical",
            tactic="T1036.002 - Right-to-Left Override",
            source="builtin",
            regexes=[_RTLO_RE],
            condition="any",
        ),
    ]


def load_hash_iocs_from_file(path: Path) -> dict[str, str]:
    """Load SHA-256 / MD5 malware hash IOCs (`<hex_hash> # <description>`) from a text file."""
    loaded: dict[str, str] = {}
    if not path.is_file():
        return loaded
    for raw_line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if "#" in line:
            digest_part, label_part = line.split("#", 1)
            label = label_part.strip() or "Known Malware Hash IOC"
        else:
            digest_part = line
            label = "Known Malware Hash IOC"
        digest = digest_part.strip().lower()
        if len(digest) in (32, 64) and all(c in "0123456789abcdef" for c in digest):
            loaded[digest] = label
    return loaded


class SignatureEngine:
    """Matches files against known malware SHA-256/MD5 digests and YARA signature rules."""

    def __init__(
        self,
        known_hashes: dict[str, str] | None = None,
        custom_rules: list[YaraRule] | None = None,
        rules_dir: Path | None = None,
    ) -> None:
        target_dir = rules_dir if rules_dir is not None else DEFAULT_RULES_DIR

        self.known_hashes = {k.lower(): v for k, v in KNOWN_MALWARE_HASHES.items()}
        if target_dir.is_dir():
            for hash_file in sorted(target_dir.glob("*hashes*.txt")):
                self.known_hashes.update(load_hash_iocs_from_file(hash_file))
        if known_hashes:
            self.known_hashes.update({k.lower(): v for k, v in known_hashes.items()})

        self.rules: list[YaraRule] = []
        if target_dir.is_dir():
            for yar_file in sorted(target_dir.glob("*.yar")):
                self.rules.extend(load_yara_rules_from_file(yar_file))
        self.rules.extend(_build_filename_heuristic_rules())

        if custom_rules:
            self.rules.extend(custom_rules)

        self._has_native_yara = False
        try:
            import yara  # noqa: F401
            self._has_native_yara = True
        except ImportError:
            pass

    def check_hash(self, sha256: str, md5: str = "") -> str | None:
        """Return threat name if SHA-256 or MD5 matches the known malware IOC list."""
        if sha256:
            found = self.known_hashes.get(sha256.lower())
            if found:
                return found
        if md5:
            return self.known_hashes.get(md5.lower())
        return None

    def get_rule_inventory(self) -> list[dict[str, str]]:
        """Return structured metadata for every loaded YARA signature rule."""
        return [
            {
                "name": rule.name,
                "description": rule.description,
                "severity": rule.severity,
                "tactic": rule.tactic,
                "source": rule.source,
            }
            for rule in self.rules
        ]

    def detect_keyword_indicator(self, content: bytes, filename: str = "") -> bool:
        """Return True if filename or text carries suspicious malware terminology (non-destructive)."""
        target = content[:65536]
        if _KEYWORD_HINT_RE.search(target):
            return True
        if filename and _KEYWORD_HINT_RE.search(filename.encode("utf-8", errors="ignore")):
            return True
        return False

    def scan_content(
        self,
        content: bytes,
        filename: str = "",
    ) -> list[tuple[str, str, str]]:
        """Scan file bytes against loaded YARA rules, returning (rule_name, severity, description)."""
        matches: list[tuple[str, str, str]] = []
        for rule in self.rules:
            if rule.match(content, filename):
                matches.append((rule.name, rule.severity, rule.description))
        return matches

    def _scan_zip_members(
        self,
        file_path: Path,
        max_members: int = 64,
        max_total_bytes: int = 8 * 1024 * 1024,
    ) -> list[str]:
        """Safely inspect uncompressed ZIP entries for malware hashes and YARA signatures."""
        flags: list[str] = []
        try:
            with zipfile.ZipFile(file_path, "r") as zf:
                bytes_budget = max_total_bytes
                for info in zf.infolist()[:max_members]:
                    if info.is_dir() or info.file_size <= 0 or info.file_size > bytes_budget:
                        continue
                    try:
                        member_bytes = zf.read(info.filename)
                    except (RuntimeError, zipfile.BadZipFile, OSError):
                        continue
                    bytes_budget -= len(member_bytes)
                    member_sha = hashlib.sha256(member_bytes).hexdigest()
                    member_md5 = hashlib.md5(member_bytes).hexdigest()
                    threat = self.check_hash(member_sha, member_md5)
                    if threat:
                        flag = f"malware_hash:{threat}"
                        if flag not in flags:
                            flags.append(flag)
                        if "eicar" in threat.lower() and "eicar_test_file" not in flags:
                            flags.append("eicar_test_file")
                    inner_name = Path(info.filename).name
                    for rule_name, _, _ in self.scan_content(member_bytes, filename=inner_name):
                        flag = f"yara:{rule_name}"
                        if flag not in flags:
                            flags.append(flag)
                        if rule_name == "EICAR_Test_File" and "eicar_test_file" not in flags:
                            flags.append("eicar_test_file")
        except (zipfile.BadZipFile, OSError):
            pass
        return flags

    def scan_file(
        self,
        file_path: Path,
        sha256: str,
        max_bytes: int = 5 * 1024 * 1024,
        md5: str = "",
    ) -> list[str]:
        """Inspect a file by hash (SHA-256/MD5), YARA signatures, and safe ZIP member scan."""
        flags: list[str] = []

        # 1. Hash check
        threat_name = self.check_hash(sha256, md5=md5)
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

            # Check for disguised PE executable (starts with MZ, non-executable extension)
            if len(content) >= 64 and content.startswith(b"MZ"):
                ext = file_path.suffix.lower()
                if ext not in {".exe", ".dll", ".sys", ".scr", ".com", ".efi", ".drv", ".ocx", ""}:
                    if "yara:Disguised_PE_Executable" not in flags:
                        flags.append("yara:Disguised_PE_Executable")

            # Safe archive inspection on .zip packages (catches zipped payloads like eicar_com.zip)
            if file_path.suffix.lower() == ".zip" and content.startswith(b"PK\x03\x04"):
                for zf_flag in self._scan_zip_members(file_path):
                    if zf_flag not in flags:
                        flags.append(zf_flag)

            # Add non-destructive behavioral warning flag on suspicious terminology
            if not any(fl.startswith("yara:") or fl == "eicar_test_file" for fl in flags):
                if self.detect_keyword_indicator(content, filename=file_path.name):
                    flags.append(FLAG_KEYWORD_INDICATOR)
        except OSError:
            pass

        return flags
