from __future__ import annotations

import json
from pathlib import PurePosixPath
from urllib.parse import quote

from .scanner import Finding, RULES, SEVERITY_ORDER


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
    lines = ["# Mod Threat Lens report", "", f"Target: `{PurePosixPath(target).name}`", "",
             "This heuristic report flags review signals; it does not determine whether a mod is malware.", "",
             "| Severity | Findings |", "|:--|--:|"]
    lines.extend(f"| {level.title()} | {counts[level]} |" for level in ("critical", "high", "medium", "low", "info"))
    lines += ["", "## Findings", ""]
    if not findings:
        lines.append("No configured heuristic matched the scanned input.")
    else:
        lines += ["| Severity | Rule | File | Line | Finding |", "|:--|:--|:--|--:|:--|"]
        for item in findings:
            path = item.path.replace("|", "\\|").replace("`", "\\`")
            title = item.title.replace("|", "\\|")
            lines.append(f"| {item.severity.title()} | `{item.rule_id}` | `{path}` | {item.line or ''} | {title} |")
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
               "runs": [{"tool": {"driver": {"name": "Mod Threat Lens", "version": "0.1.2", "rules": descriptors}},
                         "originalUriBaseIds": {"%SRCROOT%": {"uri": "./"}}, "results": results}]}
    return json.dumps(payload, ensure_ascii=False, indent=2) + "\n"
