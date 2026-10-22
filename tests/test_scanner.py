import contextlib
import io
import json
import os
import tempfile
import unittest
import zipfile
from pathlib import Path

from mod_threat_lens.cli import main
from mod_threat_lens.formats import json_report, markdown_report, sarif_report
from mod_threat_lens.scanner import Finding, ScanConfig, scan


class ScannerTests(unittest.TestCase):
    def test_shell_execution_signal_has_line_number(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "common").mkdir()
            (root / "common" / "init.lua").write_text("-- example\nos.execute(command)\n", encoding="utf-8")
            findings = scan(root)
        item = next(f for f in findings if f.rule_id == "MTL001")
        self.assertEqual((item.path, item.line, item.severity), ("common/init.lua", 2, "high"))

    def test_benign_fixture_has_no_findings(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "descriptor.mod").write_text('name="Example"\nsupported_version="1.0.*"\n', encoding="utf-8")
            (root / "localisation.yml").write_text("l_english:\n key:0 \"value\"\n", encoding="utf-8")
            self.assertEqual(scan(root), [])

    def test_binary_signature_is_reported_even_with_unusual_extension(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "payload.data").write_bytes(b"MZ\x00\x00test")
            findings = scan(root)
        self.assertIn("MTL005", {f.rule_id for f in findings})

    def test_zip_traversal_is_reported_without_reading_member(self):
        with tempfile.TemporaryDirectory() as tmp:
            archive_path = Path(tmp) / "unsafe.zip"
            with zipfile.ZipFile(archive_path, "w") as archive:
                archive.writestr("../outside.lua", "os.execute('x')")
            findings = scan(archive_path)
        self.assertEqual([f.rule_id for f in findings], ["MTL006"])
        self.assertEqual(findings[0].severity, "high")

    def test_archive_scans_script_contents(self):
        with tempfile.TemporaryDirectory() as tmp:
            archive_path = Path(tmp) / "mod.zip"
            with zipfile.ZipFile(archive_path, "w") as archive:
                archive.writestr("common/init.lua", "loadstring(remote_code)()\n")
            findings = scan(archive_path)
        self.assertIn("MTL003", {f.rule_id for f in findings})

    def test_reports_do_not_include_source_contents(self):
        finding_text = "os.execute('do-not-leak-this')"
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "script.lua").write_text(finding_text, encoding="utf-8")
            findings = scan(root)
        rendered = json_report(findings, str(root)) + sarif_report(findings)
        self.assertNotIn("do-not-leak-this", rendered)
        self.assertNotIn(finding_text, rendered)
        json.loads(json_report(findings, str(root)))
        json.loads(sarif_report(findings))

    def test_cli_fail_threshold_and_sarif_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / "mod"
            target.mkdir()
            (target / "script.lua").write_text("io.popen('x')\n", encoding="utf-8")
            output = root / "report.sarif"
            result = main(["scan", str(target), "--format", "sarif", "--output", str(output)])
            self.assertEqual(result, 1)
            document = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(document["runs"][0]["results"][0]["ruleId"], "MTL001")

    @unittest.skipIf(os.name == "nt", "Windows forbids control characters in file names")
    def test_text_report_escapes_terminal_controls_in_filenames(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "mod"
            root.mkdir()
            (root / "README.md").write_text("safe", encoding="utf-8")
            (root / "evil\n\x1b[31m.lua").write_text("os.execute('synthetic')", encoding="utf-8")
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                result = main(["scan", str(root), "--fail-on", "none"])
        text = output.getvalue()
        self.assertEqual(result, 0)
        self.assertNotIn("\x1b", text)
        self.assertIn(r"evil\n\x1b[31m.lua", text)
        self.assertEqual(text.count("[HIGH]"), 1)

    def test_markdown_report_keeps_control_filename_inside_one_safe_cell(self):
        hostile_path = "evil\n| forged | ` \x1b[31m <img src=x>"
        finding = Finding("MTL001", "Process execution", "high", hostile_path, "Review the script.")
        report = markdown_report([finding], hostile_path)
        finding_table = report.split("## Findings", 1)[1]
        rows = [line for line in finding_table.splitlines() if line.startswith("|")]
        self.assertEqual(len(rows), 3)  # header, separator, and one finding
        self.assertNotIn("\x1b", report)
        self.assertNotIn("<img", report)
        self.assertNotIn("evil\n| forged", report)
        self.assertIn(r"evil&#92;n&#124; forged", report)

    def test_invisible_unicode_is_visible_or_json_escaped_in_every_format(self):
        hostile = "mod\u202eexe.zip\u2028line\u2029end\u0085tail"
        finding = Finding("MTL001", "Review\u202eTitle", "high", hostile,
                          "Message\u202evalue\u2028line\u2029end\u0085tail")
        text = __import__("mod_threat_lens.cli", fromlist=["_text_report"])._text_report([finding], hostile)
        markdown = markdown_report([finding], hostile)
        json_text = json_report([finding], hostile)
        sarif = sarif_report([finding])
        for output in (text, markdown, json_text, sarif):
            for invisible in ("\u202e", "\u2028", "\u2029", "\u0085"):
                self.assertNotIn(invisible, output.casefold())
        self.assertIn(r"\u202e", text.casefold())
        self.assertIn("2028", markdown.casefold())
        self.assertIn("2029", markdown.casefold())
        self.assertIn(r"\u202e", json_text.casefold())
        self.assertIn(r"\u2028", sarif.casefold())
        parsed = json.loads(json_text)
        self.assertEqual(parsed["target"], hostile)
        self.assertEqual(parsed["findings"][0]["path"], hostile)

    def test_sarif_tool_version_matches_package(self):
        from mod_threat_lens import __version__
        document = json.loads(sarif_report([]))
        self.assertEqual(document["runs"][0]["tool"]["driver"]["version"], __version__)

    def test_package_version_matches_release_metadata(self):
        import re
        from pathlib import Path
        from mod_threat_lens import __version__

        root = Path(__file__).resolve().parents[1]
        self.assertEqual((root / "VERSION").read_text(encoding="utf-8").strip(), __version__)
        metadata = (root / "pyproject.toml").read_text(encoding="utf-8")
        declared = re.search(r'^version\s*=\s*"([^"]+)"\s*$', metadata, re.MULTILINE)
        self.assertIsNotNone(declared)
        self.assertEqual(declared.group(1), __version__)

    def test_scan_limits_are_validated(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = main(["scan", tmp, "--max-files", "0"])
        self.assertEqual(result, 2)

    def test_single_file_obeys_total_size_limit_without_scanning_content(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "script.lua"
            target.write_text("os.execute('should not be inspected')", encoding="utf-8")
            findings = scan(target, ScanConfig(max_file_bytes=1024, max_total_bytes=4))
        self.assertEqual([finding.rule_id for finding in findings], ["MTL008"])
        self.assertIn("total scan limit", findings[0].message)

    def test_scan_respects_exclusion_glob(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "skip.lua").write_text("os.execute('x')", encoding="utf-8")
            self.assertEqual(scan(root, ScanConfig(ignores=("skip.lua",))), [])


if __name__ == "__main__":
    unittest.main()
