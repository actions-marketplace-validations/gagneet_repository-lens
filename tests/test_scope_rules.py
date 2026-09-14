"""Two scope rules shared across the analyzers: test code, and files git ignores.

A "could not link" diagnostic raised by test code does not make an analysis incomplete,
in any language, and the built-in Python checks skip untracked gitignored files like the
graph scan does.
"""
from __future__ import annotations

import importlib.util
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from repolens.analysis import Analysis
from repolens.config import load_config
from repolens.core.files import is_test_code, is_test_path
from repolens.impact.config import Config
from repolens.impact.model import Graph, Issue
from repolens.scan.migrations import migration_files
from repolens.scan.python_ast import python_files
from repolens.scan.settings import from_config


def analysis_with(*issues: Issue) -> Analysis:
    return Analysis(Graph("repo", issues=list(issues)), [], Config())


def issue(code: str, evidence: str) -> Issue:
    return Issue(code, "warning", "could not link", [], evidence, "")


class TestCodeCompletenessTests(unittest.TestCase):
    def test_link_diagnostics_in_test_code_do_not_make_the_analysis_incomplete(self):
        for evidence in ("tests/test_api.py:4", "api/conftest.py:9", "web/src/orders.test.ts:1",
                         "e2e/checkout.spec.js:2", "packages/ui/__tests__/Button.tsx:3"):
            for code in ("UNRESOLVED_ROUTER_MOUNT", "UNRESOLVED_LOCAL_IMPORT", "ROUTER_MOUNT_CYCLE"):
                with self.subTest(code=code, evidence=evidence):
                    self.assertTrue(analysis_with(issue(code, evidence)).complete)

    def test_the_same_diagnostics_in_application_code_still_do(self):
        result = analysis_with(issue("UNRESOLVED_ROUTER_MOUNT", "app/main.py:4"),
                               issue("UNRESOLVED_ROUTER_MOUNT", "tests/test_api.py:4"))
        self.assertEqual(result.incomplete_reasons(), ["UNRESOLVED_ROUTER_MOUNT x1 (e.g. app/main.py:4)"])
        # A name that only contains "test" is not test code.
        self.assertFalse(analysis_with(issue("UNRESOLVED_LOCAL_IMPORT", "src/contest.ts:1")).complete)

    def test_spec_fixtures_and_testdata_outside_a_test_directory_are_application_code(self):
        for evidence in ("src/fixtures/index.ts:1", "spec/openapi.py:3", "testdata/app.py:1", "api/specs/client.ts:2"):
            with self.subTest(evidence=evidence):
                self.assertFalse(analysis_with(issue("UNRESOLVED_LOCAL_IMPORT", evidence)).complete)
        for evidence in ("tests/fixtures/seed.ts:1", "web/src/checkout.cy.ts:1", "test/helpers.js:4"):
            with self.subTest(evidence=evidence):
                self.assertTrue(analysis_with(issue("UNRESOLVED_LOCAL_IMPORT", evidence)).complete)

    def test_the_strict_test_code_rule(self):
        for path in ("tests/x.py", "Test/x.py", "__tests__/a.tsx", "e2e/a.ts", "cypress/support/e2e.ts",
                     "test_x.py", "pkg/x_test.py", "conftest.py", "src/a.spec.tsx", "src/a.test.mjs", "src/a.cy.js"):
            self.assertTrue(is_test_code(path), path)
        for path in ("spec/openapi.py", "fixtures/db.py", "src/testdata/x.ts", "src/contest.ts", "tests.py", "latest_test.ts"):
            self.assertFalse(is_test_code(path), path)

    def test_unread_test_code_still_makes_it_incomplete(self):
        for code in ("PYTHON_PARSE_ERROR", "JAVASCRIPT_PARSE_ERROR", "FILE_SKIPPED"):
            with self.subTest(code=code):
                self.assertFalse(analysis_with(issue(code, "tests/test_api.py:1")).complete)

    def test_the_shared_test_path_rule(self):
        for path in ("tests/x.py", "Tests/x.py", "test_x.py", "x_test.py", "conftest.py", "spec/a.rb",
                     "cypress/e2e/a.cy.ts", "src/a.spec.tsx", "src/a.test.mjs", "fixtures/db.sql"):
            self.assertTrue(is_test_path(path), path)
        for path in ("src/contest.ts", "latest.py", "testing_utils/app.py", "tests.py"):
            self.assertFalse(is_test_path(path), path)

    @unittest.skipUnless(importlib.util.find_spec("sqlglot") and importlib.util.find_spec("tree_sitter"),
                         "install repolens[stack]")
    def test_a_test_app_mounting_a_factory_router_leaves_the_scan_complete(self):
        from repolens.analysis import analyze
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "app").mkdir()
            (root / "tests").mkdir()
            (root / "app/__init__.py").write_text("", encoding="utf-8")
            (root / "app/main.py").write_text(
                "from fastapi import APIRouter, FastAPI\nrouter = APIRouter()\n\n"
                "@router.get('/orders')\ndef orders():\n    return []\n\n"
                "app = FastAPI()\napp.include_router(router, prefix='/api')\n", encoding="utf-8")
            (root / "tests/test_orders.py").write_text(
                "from fastapi import FastAPI\nfrom app import main\n\n"
                "def build(name):\n    return getattr(main, name)\n\n"
                "client_app = FastAPI()\nclient_app.include_router(build('router'))\n", encoding="utf-8")
            result = analyze(root)
            codes = {(i.code, i.evidence) for i in result.graph.issues}
            self.assertIn(("UNRESOLVED_ROUTER_MOUNT", "tests/test_orders.py:8"), codes)
            self.assertEqual(result.incomplete_reasons(), [])


@unittest.skipIf(shutil.which("git") is None, "needs git")
class GitignoredPythonFilesTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.root, ignore_errors=True)
        env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}

        def git(*args):
            subprocess.run(["git", "-C", str(self.root), *args], check=True, capture_output=True, env=env)
        self.git = git
        git("init", "-q")
        files = {".gitignore": "backup/\n*.local.py\n", "app.py": "x = 1\n", "backup/old.py": "x = 1\n",
                 "settings.local.py": "x = 1\n", "vendored.local.py": "x = 1\n",
                 "migrations/versions/0001_a.py": "revision = '1'\n",
                 "backup/migrations/versions/0002_b.py": "revision = '2'\n"}
        for name, text in files.items():
            (self.root / name).parent.mkdir(parents=True, exist_ok=True)
            (self.root / name).write_text(text, encoding="utf-8")
        git("add", ".gitignore", "app.py", "migrations")
        git("add", "-f", "vendored.local.py")  # tracked, although it matches an ignore rule

    def settings(self, toml: str = ""):
        (self.root / "repolens.toml").write_text(toml, encoding="utf-8")
        return from_config(load_config(self.root))

    def test_the_python_checks_skip_untracked_gitignored_files(self):
        s = self.settings()
        self.assertEqual(sorted(s.rel(p) for p in python_files(s)),
                         ["app.py", "migrations/versions/0001_a.py", "vendored.local.py"])
        self.assertEqual([s.rel(p) for p in migration_files(s)], ["migrations/versions/0001_a.py"])

    def test_respect_gitignore_false_reads_them(self):
        s = self.settings("[impact]\nrespect_gitignore = false\n")
        self.assertIn("backup/old.py", {s.rel(p) for p in python_files(s)})
        self.assertIn("settings.local.py", {s.rel(p) for p in python_files(s)})
        self.assertEqual(len(migration_files(s)), 2)

    def test_the_impact_tracer_json_layer_applies_too(self):
        (self.root / ".impact-tracer.json").write_text('{"respect_gitignore": false}', encoding="utf-8")
        s = self.settings()
        self.assertIn("backup/old.py", {s.rel(p) for p in python_files(s)})

    def test_a_non_boolean_setting_is_rejected(self):
        with self.assertRaises(ValueError):
            self.settings("[impact]\nrespect_gitignore = \"yes\"\n")

    def test_without_a_usable_repository_every_file_is_read(self):
        shutil.rmtree(self.root / ".git")
        (self.root / ".git").mkdir()  # an empty .git: git cannot list, so nothing is skipped
        s = self.settings()
        self.assertIn("backup/old.py", {s.rel(p) for p in python_files(s)})


if __name__ == "__main__":
    unittest.main()
