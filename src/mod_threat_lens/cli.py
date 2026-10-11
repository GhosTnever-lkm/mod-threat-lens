from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__
from .formats import _visible_text, json_report, markdown_report, sarif_report
from .scanner import SEVERITY_ORDER, ScanConfig, ScanError, scan


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(prog="mod-threat-lens", description="Local-first heuristic security triage for game mods.")
    root.add_argument("--version", action="version", version=f"Mod Threat Lens {__version__}")
    sub = root.add_subparsers(dest="command", required=True)
    command = sub.add_parser("scan", help="scan a folder, file, or ZIP archive")
    command.add_argument("target", help="local folder, file, or ZIP archive")
    command.add_argument("--format", choices=("text", "json", "markdown", "sarif"), default="text")
    command.add_argument("--output", help="write the report to this path; default is stdout")
    command.add_argument("--fail-on", choices=("none", "low", "medium", "high", "critical"), default="high",
                         help="exit 1 when a finding at or above this severity exists (default: high)")
    command.add_argument("--max-files", type=int, default=20_000)
    command.add_argument("--max-file-mb", type=int, default=2)
    command.add_argument("--max-total-mb", type=int, default=256)
    command.add_argument("--max-zip-ratio", type=int, default=200)
    command.add_argument("--ignore", action="append", default=[], metavar="GLOB", help="ignore a relative path glob; repeatable")
    return root


def _text_report(findings, target: str) -> str:
    from .formats import summary
    counts = summary(findings)
    parts = [f"Mod Threat Lens {__version__} — {_visible_text(Path(target).name)}",
             "Heuristic triage only; this is not a malware verdict.",
             "Findings: " + ", ".join(f"{level}={counts[level]}" for level in ("critical", "high", "medium", "low", "info"))]
    if not findings:
        parts.append("No configured heuristic matched the scanned input.")
    for finding in findings:
        location = f"{finding.path}:{finding.line}" if finding.line else finding.path
        parts.append(
            f"[{_visible_text(finding.severity.upper())}] {_visible_text(finding.rule_id)} "
            f"{_visible_text(location)} — {_visible_text(finding.title)}: {_visible_text(finding.message)}"
        )
    parts.append("No source snippets or file contents are included.")
    return "\n".join(parts) + "\n"


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    numeric = (args.max_files, args.max_file_mb, args.max_total_mb, args.max_zip_ratio)
    if any(value <= 0 for value in numeric):
        print("error: all scan limits must be positive integers", file=sys.stderr)
        return 2
    config = ScanConfig(max_files=args.max_files, max_file_bytes=args.max_file_mb * 1024 * 1024,
                        max_total_bytes=args.max_total_mb * 1024 * 1024, max_zip_ratio=args.max_zip_ratio,
                        ignores=tuple(args.ignore))
    try:
        findings = scan(args.target, config)
    except ScanError as exc:
        print(f"error: {_visible_text(str(exc))}", file=sys.stderr)
        return 2
    formats = {"text": _text_report, "json": json_report, "markdown": markdown_report, "sarif": lambda rows, _target: sarif_report(rows)}
    content = formats[args.format](findings, args.target)
    try:
        if args.output:
            output = Path(args.output)
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text(content, encoding="utf-8")
        else:
            sys.stdout.write(content)
    except OSError as exc:
        print(f"error: could not write report ({type(exc).__name__})", file=sys.stderr)
        return 2
    if args.fail_on != "none":
        threshold = SEVERITY_ORDER[args.fail_on]
        if any(SEVERITY_ORDER[item.severity] >= threshold for item in findings):
            return 1
    return 0
