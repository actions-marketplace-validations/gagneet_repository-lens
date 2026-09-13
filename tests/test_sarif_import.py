from __future__ import annotations

import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest

from repolens.config import Config
from repolens.report.runner import main
from repolens.report.sarif import import_sarif


class SarifTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.path = self.root / "source.sarif"
        self.doc = {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "Example Analyzer", "rules": [
            {"id": "RULE1", "defaultConfiguration": {"level": "error"}, "properties": {"security-severity": "8.1"}}]}},
            "results": [{"ruleIndex": 0, "message": {"text": "Review this input"},
                         "locations": [{"physicalLocation": {"artifactLocation": {"uri": "src/a%20b.ts"}, "region": {"startLine": 5}}}]}]}]}

    def save(self):
        self.path.write_text(json.dumps(self.doc))
        return self.path

    def test_rule_index_default_severity_and_encoded_path(self):
        [run] = import_sarif(self.save(), self.root)
        [finding] = run.findings
        self.assertEqual((finding.file, finding.line, finding.severity), ("src/a b.ts", 5, "high"))
        self.assertEqual(finding.category, "security")
        self.assertEqual(finding.confidence, "medium")

    def test_failed_producer_does_not_become_a_clean_result(self):
        self.doc["runs"][0]["invocations"] = [{"executionSuccessful": False}]
        [run] = import_sarif(self.save(), self.root)
        self.assertTrue(run.error)
        self.assertEqual(len(run.findings), 1)

    def test_missing_results_does_not_become_a_clean_result(self):
        del self.doc["runs"][0]["results"]
        [run] = import_sarif(self.save(), self.root)
        self.assertTrue(run.error)

    def test_remote_or_traversal_locations_keep_findings_without_opening_them(self):
        for uri in ("https://example.com/secret.ts", "../../etc/passwd", "file:///etc/passwd", "C:/build/main.ts"):
            self.doc["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] = uri
            [run] = import_sarif(self.save(), self.root)
            self.assertEqual(len(run.findings), 1)
            self.assertEqual(run.findings[0].file, "")

    def test_external_property_files_and_bad_versions_are_rejected(self):
        self.doc["runs"][0]["externalPropertyFileReferences"] = {"results": [{"location": {"uri": "https://example.com/results"}}]}
        with self.assertRaises(ValueError):
            import_sarif(self.save(), self.root)
        self.doc["version"] = "2.0.0"
        with self.assertRaises(ValueError):
            import_sarif(self.save(), self.root)

    def test_incomplete_import_cannot_be_baselined(self):
        self.doc["runs"][0]["invocations"] = [{"executionSuccessful": False}]
        self.save()
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            code = main(["--only", "commands", "--sarif", str(self.path), "--update-baseline"], config=Config(self.root, {}))
        self.assertEqual(code, 2)
        self.assertFalse((self.root / ".repolens/report_baseline.json").exists())

    def test_required_tool_not_selected_fails_check(self):
        profile = Config(self.root, {})
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(main(["--only", "commands", "--update-baseline"], config=profile), 0)
            self.assertEqual(main(["--only", "commands", "--require", "bandit", "--check"], config=profile), 1)

    def test_malformed_rule_and_result_scalars_are_rejected(self):
        self.doc["runs"][0]["tool"]["driver"]["rules"][0]["id"] = ["RULE1"]
        with self.assertRaises(ValueError):
            import_sarif(self.save(), self.root)
        self.doc["runs"][0]["tool"]["driver"]["rules"][0]["id"] = "RULE1"
        self.doc["runs"][0]["results"][0]["ruleId"] = ["RULE1"]
        with self.assertRaises(ValueError):
            import_sarif(self.save(), self.root)
