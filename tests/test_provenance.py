"""Every output names the build of repolens that produced it."""
from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

from repolens import __version__
from repolens.core import javascript
from repolens.core.findings import ToolRun, to_sarif
from repolens.provenance import describe_build, tool_build

HAS_STACK = javascript.available() and importlib.util.find_spec("sqlglot") is not None


class ProvenanceTests(unittest.TestCase):
    def test_build_records_version_source_hash_and_extras(self):
        build = tool_build()
        self.assertEqual(build["version"], __version__)
        self.assertRegex(build["source_sha256"], r"^[0-9a-f]{64}$")
        self.assertIn("tree-sitter", build["extras"])
        self.assertIn("sqlglot", build["extras"])
        if build["commit"] is not None:
            self.assertRegex(build["commit"], r"^[0-9a-f]{40}$")
            self.assertIsInstance(build["dirty"], bool)
        self.assertTrue(describe_build(build).startswith(f"repolens {__version__} "))

    def test_describe_build_is_stable_for_a_given_stamp(self):
        stamp = {"version": "9.9.9", "commit": "a" * 40, "dirty": True, "source_sha256": "b" * 64,
                 "extras": {"sqlglot": "1", "tree-sitter": None}}
        self.assertEqual(describe_build(stamp), f"repolens 9.9.9 {'a' * 12}+dirty source {'b' * 12} extras sqlglot")

    def test_sarif_driver_carries_the_build(self):
        sarif = json.loads(to_sarif([ToolRun("security")], __version__, build=tool_build()))
        self.assertEqual(sarif["runs"][0]["tool"]["driver"]["properties"]["repolensBuild"], tool_build())

    @unittest.skipUnless(HAS_STACK, "install repolens[stack]")
    def test_analysis_outputs_carry_the_build_and_configuration(self):
        from repolens.analysis import analyze
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "app.py").write_text("def main(): pass\n", encoding="utf-8")
            result = analyze(Path(tmp))
            payload = result.to_dict()
            self.assertEqual(payload["tool_build"], tool_build())
            self.assertRegex(payload["config_sha256"], r"^[0-9a-f]{64}$")
            self.assertIn(f"Produced by {describe_build()}", result.markdown())


if __name__ == "__main__":
    unittest.main()


class ProvenanceIsolationTests(unittest.TestCase):
    def test_the_stamp_is_a_copy(self):
        tool_build()["extras"]["tree-sitter"] = "tampered"
        self.assertNotEqual(tool_build()["extras"]["tree-sitter"], "tampered")

    def test_inherited_git_variables_do_not_redirect_git(self):
        import os
        from unittest import mock
        from repolens import provenance
        with mock.patch.dict(os.environ, {"GIT_DIR": "/nonexistent/.git", "GIT_WORK_TREE": "/"}):
            env = provenance.git_env()
            self.assertNotIn("GIT_DIR", env)
            self.assertNotIn("GIT_WORK_TREE", env)
            self.assertEqual(provenance._tool_build.__wrapped__()["commit"], tool_build()["commit"])

    @unittest.skipUnless(importlib.util.find_spec("fastapi"), "install repolens[api]")
    def test_the_api_response_model_carries_the_stamp(self):
        from repolens.api.app import AnalysisResponse
        self.assertTrue({"tool_build", "config_sha256", "incomplete_reasons"} <= set(AnalysisResponse.model_fields))
