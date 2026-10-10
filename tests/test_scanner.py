import json
import tempfile
import unittest
import zipfile
from pathlib import Path

from mod_threat_lens.cli import main
from mod_threat_lens.formats import json_report, sarif_report
from mod_threat_lens.scanner import ScanConfig, scan


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

    def test_scan_limits_are_validated(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = main(["scan", tmp, "--max-files", "0"])
        self.assertEqual(result, 2)

    def test_scan_respects_exclusion_glob(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "skip.lua").write_text("os.execute('x')", encoding="utf-8")
            self.assertEqual(scan(root, ScanConfig(ignores=("skip.lua",))), [])


if __name__ == "__main__":
    unittest.main()
