from __future__ import annotations

import json
import html
import unicodedata
from pathlib import PurePosixPath
from urllib.parse import quote

from . import __version__
from .scanner import Finding, RULES, SEVERITY_ORDER


def _visible_text(value: str) -> str:
    """Make control and formatting characters visible instead of executable."""
    escaped: list[str] = []
    readable_controls = {"\n": r"\n", "\r": r"\r", "\t": r"\t"}
    for char in value:
        if char in readable_controls:
            escaped.append(readable_controls[char])
        elif unicodedata.category(char).startswith("C"):
            codepoint = ord(char)
            if codepoint <= 0xFF:
                escaped.append(f"\\x{codepoint:02x}")
            elif codepoint <= 0xFFFF:
                escaped.append(f"\\u{codepoint:04x}")
            else:
                escaped.append(f"\\U{codepoint:08x}")
        else:
            escaped.append(char)
    return "".join(escaped)


def _markdown_cell(value: str) -> str:
    visible = html.escape(_visible_text(value), quote=False)
    markdown_chars = {ord(char): f"&#{ord(char)};" for char in r"\|`*_{}[]!#~"}
    return visible.translate(markdown_chars)


def summary(findings: list[Finding]) -> dict[str, int]:
    return {level: sum(1 for finding in findings if finding.severity == level)
            for level in ("critical", "high", "medium", "low", "info")}


def json_report(findings: list[Finding], target: str) -> str:
    payload = {
        "schema_version": 1,
        "tool": "Mod Threat Lens",
        "target": PurePosixPath(target).name,
        "summary": summary(findings),
        "findings": [finding.to_dict() for finding in findings],
    }
    return json.dumps(payload, ensure_ascii=False, indent=2) + "\n"


def markdown_report(findings: list[Finding], target: str) -> str:
    counts = summary(findings)
    lines = ["# Mod Threat Lens report", "", f"Target: {_markdown_cell(PurePosixPath(target).name)}", "",
             "This heuristic report flags review signals; it does not determine whether a mod is malware.", "",
             "| Severity | Findings |", "|:--|--:|"]
    lines.extend(f"| {level.title()} | {counts[level]} |" for level in ("critical", "high", "medium", "low", "info"))
    lines += ["", "## Findings", ""]
    if not findings:
        lines.append("No configured heuristic matched the scanned input.")
    else:
        lines += ["| Severity | Rule | File | Line | Finding |", "|:--|:--|:--|--:|:--|"]
        for item in findings:
            lines.append("| " + " | ".join((
                _markdown_cell(item.severity.title()),
                _markdown_cell(item.rule_id),
                _markdown_cell(item.path),
                _markdown_cell(str(item.line or "")),
                _markdown_cell(item.title),
            )) + " |")
    lines += ["", "No source snippets or file contents are included in this report.", ""]
    return "\n".join(lines)


def sarif_report(findings: list[Finding]) -> str:
    descriptors = [{"id": rule["id"], "name": rule["title"], "shortDescription": {"text": rule["title"]},
                    "help": {"text": rule["message"]}, "defaultConfiguration": {"level": "error" if rule["severity"] == "high" else "warning"}}
                   for rule in RULES]
    descriptors += [
        {"id": "MTL005", "name": "Executable or binary payload", "shortDescription": {"text": "Executable or binary payload"}},
        {"id": "MTL006", "name": "Unsafe archive path", "shortDescription": {"text": "Unsafe archive path"}},
        {"id": "MTL007", "name": "Duplicate archive path", "shortDescription": {"text": "Duplicate archive path"}},
        {"id": "MTL008", "name": "Scan limit exceeded", "shortDescription": {"text": "Scan limit exceeded"}},
        {"id": "MTL009", "name": "Symbolic link", "shortDescription": {"text": "Symbolic link"}},
        {"id": "MTL010", "name": "Extreme compression ratio", "shortDescription": {"text": "Extreme compression ratio"}},
        {"id": "MTL011", "name": "Unreadable input", "shortDescription": {"text": "Unreadable input"}},
    ]
    results = []
    for item in findings:
        level = "error" if SEVERITY_ORDER[item.severity] >= SEVERITY_ORDER["high"] else ("warning" if item.severity == "medium" else "note")
        physical = {"artifactLocation": {"uri": quote(item.path.replace("\\", "/"), safe="/._-"), "uriBaseId": "%SRCROOT%"}}
        if item.line:
            physical["region"] = {"startLine": item.line}
        results.append({"ruleId": item.rule_id, "level": level, "message": {"text": item.message},
                        "locations": [{"physicalLocation": physical}]})
    payload = {"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "Mod Threat Lens", "version": __version__, "rules": descriptors}},
                         "originalUriBaseIds": {"%SRCROOT%": {"uri": "./"}}, "results": results}]}
    return json.dumps(payload, ensure_ascii=False, indent=2) + "\n"
