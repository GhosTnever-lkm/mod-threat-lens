# Changelog

## 0.1.6 - 2026-10-11

- Escape Unicode line and paragraph separators as visible sequences in text and Markdown reports.
- Emit JSON and SARIF with Unicode escapes so bidi/C1/line-separator characters cannot spoof rendered artifacts while parsers recover the original values.
- Add cross-format hostile Unicode regression coverage.

## 0.1.5 - 2026-10-11

- Escape control and formatting characters from untrusted filenames in text and Markdown reports; prevents terminal control injection and forged Markdown table rows.
- Keep SARIF driver version synchronized with package metadata.
- Add regression coverage for newlines, ANSI escapes, bidi controls, and Markdown delimiters.

## 0.1.4 - 2026-10-11

- Add a repository-hosted preview of heuristic findings from inert synthetic test strings.
- Update the composite Action example and align the package and SARIF versions.

## 0.1.3 - 2026-10-11

- Update checkout, setup-python, and upload-artifact references to supported v7 majors.
- Bump package, SARIF, and Action example to v0.1.3.

## 0.1.2 - 2026-10-11

- Remove the empty Gumroad storefront CTA until a real paid product is available.
- Synchronize package, SARIF, CLI, Action example, and version metadata at v0.1.2.

## 0.1.1 — 2026-10-11

- Add verified Buy Me a Coffee and Gumroad support links; clarify that the free core has no paid Pro edition yet.
- Update the GitHub Action example to v0.1.1.
- Keep the SARIF tool version aligned with the package version.

## 0.1.0 — 2026-10-11

- Initial release of a local-first heuristic security triage CLI for game mods.
- Scan folders, individual files, and ZIP archives without extracting archives or uploading content.
- Flag process execution, remote retrieval, dynamic evaluation, encoded payload indicators, executable payloads, unsafe ZIP paths, symlinks, duplicate paths, and resource-limit issues.
- Export text, JSON, Markdown, and SARIF reports with bounded scanning and no source snippets.
- Add a composite GitHub Action and standard-library test suite.
