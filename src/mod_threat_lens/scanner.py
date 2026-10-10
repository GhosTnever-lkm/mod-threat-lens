from __future__ import annotations

import fnmatch
import os
import re
import stat
import zipfile
from dataclasses import asdict, dataclass
from pathlib import Path, PurePosixPath
from typing import Iterable

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
DEFAULT_IGNORES = {".git", ".hg", ".svn", "__pycache__", "node_modules"}
TEXT_SUFFIXES = {
    ".cfg", ".conf", ".cs", ".gd", ".gui", ".ini", ".js", ".json", ".lua",
    ".md", ".mod", ".po", ".ps1", ".py", ".sh", ".txt", ".xml", ".yml",
    ".yaml", ".bat", ".cmd", ".vbs", ".ts", ".toml", ".log",
}
EXECUTABLE_SUFFIXES = {".exe", ".dll", ".so", ".dylib", ".com", ".scr", ".msi", ".ps1", ".bat", ".cmd", ".sh"}
MAGIC = (b"MZ", b"\x7fELF", b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf")

RULES = [
    {
        "id": "MTL001", "title": "Shell or process execution", "severity": "high",
        "pattern": re.compile(r"\b(?:os\.execute|io\.popen|subprocess\.(?:run|Popen|call)|child_process\.(?:exec|spawn)|ProcessBuilder\s*\(|Runtime\.getRuntime\(\)\.exec)\s*\(", re.I),
        "message": "Code invokes an operating-system process API; review the command and its inputs.",
    },
    {
        "id": "MTL002", "title": "Remote content retrieval", "severity": "medium",
        "pattern": re.compile(r"\b(?:urllib\.request\.urlopen|requests\.(?:get|post)|fetch\s*\(|WebClient|HttpClient|curl\s+https?://|wget\s+https?://)", re.I),
        "message": "Code appears to retrieve remote content; verify the destination and whether execution follows.",
    },
    {
        "id": "MTL003", "title": "Dynamic code evaluation", "severity": "medium",
        "pattern": re.compile(r"\b(?:loadstring|eval|exec)\s*\(", re.I),
        "message": "Code dynamically evaluates a string; inspect the source and trust boundary.",
    },
    {
        "id": "MTL004", "title": "Encoded command or payload", "severity": "high",
        "pattern": re.compile(r"(?:powershell(?:\.exe)?\s+[^\n]{0,80}-(?:enc|encodedcommand)\b|[A-Za-z0-9+/]{160,}={0,2})", re.I),
        "message": "An encoded command or unusually long base64-like string was found; confirm it is expected.",
    },
]


@dataclass(frozen=True)
class Finding:
    rule_id: str
    title: str
    severity: str
    path: str
    message: str
    line: int | None = None

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass(frozen=True)
class ScanConfig:
    max_files: int = 20_000
    max_file_bytes: int = 2 * 1024 * 1024
    max_total_bytes: int = 256 * 1024 * 1024
    max_zip_ratio: int = 200
    ignores: tuple[str, ...] = ()


class ScanError(Exception):
    """Invalid scan input or an unreadable archive."""


def _finding(rule_id: str, title: str, severity: str, path: str, message: str, line: int | None = None) -> Finding:
    return Finding(rule_id, title, severity, path.replace("\\", "/"), message, line)


def _is_ignored(path: str, config: ScanConfig) -> bool:
    parts = PurePosixPath(path.replace("\\", "/")).parts
    return any(part in DEFAULT_IGNORES for part in parts) or any(fnmatch.fnmatch(path, pattern) for pattern in config.ignores)


def _is_executable(path: str, sample: bytes) -> bool:
    return Path(path).suffix.lower() in EXECUTABLE_SUFFIXES or any(sample.startswith(sig) for sig in MAGIC)


def _scan_text(data: bytes, path: str) -> list[Finding]:
    if b"\x00" in data:
        return []
    text = data.decode("utf-8-sig", errors="replace")
    findings: list[Finding] = []
    matched: set[str] = set()
    for number, line in enumerate(text.splitlines(), start=1):
        # Cap work on pathological single lines while still checking ordinary source.
        candidate = line[:16_384]
        for rule in RULES:
            if rule["id"] not in matched and rule["pattern"].search(candidate):
                findings.append(_finding(rule["id"], rule["title"], rule["severity"], path, rule["message"], number))
                matched.add(rule["id"])
        if len(matched) == len(RULES):
            break
    return findings


def _inspect_file(data: bytes, path: str) -> list[Finding]:
    findings: list[Finding] = []
    if _is_executable(path, data[:8]):
        findings.append(_finding("MTL005", "Executable or binary payload", "medium", path,
                                 "Executable file type or binary signature found; verify that the payload is required and trusted."))
    if Path(path).suffix.lower() in TEXT_SUFFIXES and data:
        findings.extend(_scan_text(data, path))
    return findings


def _safe_archive_name(name: str) -> bool:
    normalized = name.replace("\\", "/")
    pure = PurePosixPath(normalized)
    drive_path = bool(re.match(r"^[A-Za-z]:", normalized))
    return not pure.is_absolute() and not drive_path and ".." not in pure.parts


def _scan_zip(path: Path, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    try:
        archive = zipfile.ZipFile(path)
    except (OSError, zipfile.BadZipFile) as exc:
        raise ScanError(f"Could not read ZIP archive: {exc}") from exc
    with archive:
        infos = archive.infolist()
        if len(infos) > config.max_files:
            findings.append(_finding("MTL008", "Archive entry limit exceeded", "high", path.name,
                                     f"Archive contains more than the configured {config.max_files} entries; remaining entries were not inspected."))
        total = 0
        seen: set[str] = set()
        for info in infos[: config.max_files]:
            raw_name = info.filename
            name = raw_name.replace("\\", "/")
            if info.is_dir():
                continue
            if not _safe_archive_name(raw_name):
                findings.append(_finding("MTL006", "Unsafe archive path", "high", name,
                                         "Archive entry uses an absolute path, drive prefix, or parent traversal and was not read."))
                continue
            if _is_ignored(name, config):
                continue
            key = name.casefold()
            if key in seen:
                findings.append(_finding("MTL007", "Duplicate archive path", "medium", name,
                                         "Archive contains a duplicate path (case-insensitive comparison)."))
                continue
            seen.add(key)
            mode = (info.external_attr >> 16) & 0o170000
            if mode == stat.S_IFLNK:
                findings.append(_finding("MTL009", "Symbolic link in archive", "medium", name,
                                         "Symbolic links are not followed; review the target before installation."))
                continue
            total += info.file_size
            if info.file_size > config.max_file_bytes or total > config.max_total_bytes:
                findings.append(_finding("MTL008", "Archive scan limit exceeded", "high", name,
                                         "Entry or cumulative expanded size exceeds the configured scan limit; content was not read."))
                continue
            if info.file_size > 0 and info.file_size / max(info.compress_size, 1) > config.max_zip_ratio:
                findings.append(_finding("MTL010", "Extreme compression ratio", "medium", name,
                                         "Archive entry exceeds the configured compression-ratio limit; content was not read."))
                continue
            try:
                with archive.open(info) as entry:
                    data = entry.read(config.max_file_bytes + 1)
            except (OSError, RuntimeError, zipfile.BadZipFile) as exc:
                findings.append(_finding("MTL011", "Archive entry unreadable", "medium", name,
                                         f"Entry could not be safely read ({type(exc).__name__})."))
                continue
            if len(data) > config.max_file_bytes:
                findings.append(_finding("MTL008", "Archive scan limit exceeded", "high", name,
                                         "Entry expands beyond the configured per-file scan limit; remaining content was not read."))
                continue
            findings.extend(_inspect_file(data, name))
    return findings


def _scan_directory(path: Path, config: ScanConfig) -> list[Finding]:
    findings: list[Finding] = []
    root = path.resolve()
    stack = [path]
    seen_files = 0
    total = 0
    while stack:
        directory = stack.pop()
        try:
            entries = sorted(os.scandir(directory), key=lambda item: item.name.casefold(), reverse=True)
        except OSError as exc:
            rel = directory.relative_to(path).as_posix() or "."
            findings.append(_finding("MTL011", "Directory unreadable", "medium", rel, f"Directory could not be read ({type(exc).__name__})."))
            continue
        for entry in entries:
            rel_path = Path(entry.path).relative_to(path).as_posix()
            if _is_ignored(rel_path, config):
                continue
            try:
                if entry.is_symlink():
                    findings.append(_finding("MTL009", "Symbolic link", "medium", rel_path,
                                             "Symbolic link was not followed; review its target before use."))
                    continue
                if entry.is_dir(follow_symlinks=False):
                    stack.append(Path(entry.path))
                    continue
                if not entry.is_file(follow_symlinks=False):
                    continue
                seen_files += 1
                if seen_files > config.max_files:
                    findings.append(_finding("MTL008", "File limit exceeded", "high", ".",
                                             f"More than {config.max_files} files found; remaining files were not inspected."))
                    return findings
                size = entry.stat(follow_symlinks=False).st_size
                total += size
                if size > config.max_file_bytes or total > config.max_total_bytes:
                    findings.append(_finding("MTL008", "Scan size limit exceeded", "high", rel_path,
                                             "File or cumulative size exceeds the configured scan limit; content was not read."))
                    continue
                with open(entry.path, "rb") as stream:
                    data = stream.read(config.max_file_bytes + 1)
                if len(data) > config.max_file_bytes:
                    findings.append(_finding("MTL008", "Scan size limit exceeded", "high", rel_path,
                                             "File exceeds the configured per-file scan limit; content was not read."))
                    continue
                findings.extend(_inspect_file(data, rel_path))
            except OSError as exc:
                findings.append(_finding("MTL011", "File unreadable", "medium", rel_path, f"File could not be read ({type(exc).__name__})."))
    return findings


def scan(target: str | Path, config: ScanConfig | None = None) -> list[Finding]:
    config = config or ScanConfig()
    path = Path(target)
    if not path.exists():
        raise ScanError(f"Input does not exist: {path}")
    if path.is_symlink():
        raise ScanError("Refusing to scan a symbolic link as the top-level input.")
    if path.is_file() and zipfile.is_zipfile(path):
        findings = _scan_zip(path, config)
    elif path.is_dir():
        findings = _scan_directory(path, config)
    elif path.is_file():
        try:
            if path.stat().st_size > config.max_file_bytes:
                findings = [_finding("MTL008", "Scan size limit exceeded", "high", path.name,
                                     "File exceeds the configured per-file scan limit; content was not read.")]
            else:
                findings = _inspect_file(path.read_bytes(), path.name)
        except OSError as exc:
            raise ScanError(f"Could not read input ({type(exc).__name__}).") from exc
    else:
        raise ScanError("Input must be a regular file, ZIP archive, or directory.")
    return sorted(findings, key=lambda item: (-SEVERITY_ORDER[item.severity], item.path.casefold(), item.rule_id, item.line or 0))
