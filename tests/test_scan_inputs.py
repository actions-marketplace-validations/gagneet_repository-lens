"""What the scanner reads: gitignored files, oversized data files, and why a scan is incomplete."""
from __future__ import annotations

import importlib.util
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from repolens.core import javascript
from repolens.impact.config import Config
from repolens.impact.scanner import iter_source_files, repository_content_sha, scan_repository

HAS_STACK = javascript.available() and importlib.util.find_spec("sqlglot") is not None


class ScanInputTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.addCleanup(self.tmp.cleanup)

    def write(self, path, text):
        target = self.root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8")

    def git(self, *args):
        subprocess.run(["git", "-C", str(self.root), *args], check=True, capture_output=True)

    @unittest.skipUnless(shutil.which("git"), "git is not installed")
    def test_untracked_gitignored_files_are_not_read_but_tracked_ones_are(self):
        self.git("init", "-q")
        self.write(".gitignore", "backups/\n*.log.py\n")
        self.write("app.py", "def main(): pass\n")
        self.write("backups/dump.json", "{}")
        self.write("backups/old.py", "def old(): pass\n")
        self.write("debug.log.py", "x = 1\n")
        self.write("vendored.log.py", "y = 1\n")
        self.git("add", "-f", "vendored.log.py")
        files = {p.relative_to(self.root).as_posix() for p in iter_source_files(self.root, Config())}
        self.assertEqual(files - {".gitignore"}, {"app.py", "vendored.log.py"})
        self.assertNotIn("backups/old.py", files)
        config = Config()
        config.respect_gitignore = False
        everything = {p.relative_to(self.root).as_posix() for p in iter_source_files(self.root, config)}
        self.assertTrue({"backups/old.py", "backups/dump.json", "debug.log.py"} <= everything)
        # The cache fingerprint reads the same inputs as the scan.
        before = repository_content_sha(self.root, Config())
        self.write("backups/old.py", "def old(): return 2\n")
        self.assertEqual(before, repository_content_sha(self.root, Config()))

    @unittest.skipUnless(shutil.which("git"), "git is not installed")
    def test_a_subdirectory_root_and_inherited_git_variables_keep_the_checkout_rules(self):
        import os
        from unittest import mock
        self.git("init", "-q")
        self.write("svc/api/.gitignore", "backups/\nout/\n")
        self.write("svc/api/app.py", "def main(): pass\n")
        self.write("svc/api/backups/old.py", "def old(): pass\n")
        self.write("svc/api/out/keep.py", "def keep(): pass\n")
        self.git("add", "-f", "svc/api/out/keep.py")
        root = self.root / "svc/api"
        with mock.patch.dict(os.environ, {"GIT_DIR": "/nonexistent/.git", "GIT_INDEX_FILE": "/nonexistent/index"}):
            files = {p.relative_to(root).as_posix() for p in iter_source_files(root, Config())}
        self.assertEqual(files - {".gitignore"}, {"app.py", "out/keep.py"})

    @unittest.skipUnless(shutil.which("git"), "git is not installed")
    def test_a_git_failure_is_reported_and_everything_is_read(self):
        import subprocess as sp
        from unittest import mock
        self.git("init", "-q")
        self.write(".gitignore", "backups/\n")
        self.write("backups/old.py", "def old(): pass\n")
        with mock.patch("repolens.core.git.subprocess.run", side_effect=sp.CalledProcessError(128, "git")):
            graph = scan_repository(self.root, Config())
        [issue] = [i for i in graph.issues if i.code == "GITIGNORE_UNAVAILABLE"]
        self.assertEqual(issue.severity, "info")
        self.assertIn("status 128", issue.message)
        self.assertIn("backups/old.py", {n.path for n in graph.nodes.values() if n.kind == "file"})

    def test_a_directory_that_is_not_a_git_checkout_reads_everything(self):
        self.write(".gitignore", "backups/\n")
        self.write("backups/old.py", "def old(): pass\n")
        files = {p.relative_to(self.root).as_posix() for p in iter_source_files(self.root, Config())}
        self.assertIn("backups/old.py", files)

    def test_an_oversized_data_file_is_advisory_but_oversized_source_is_not(self):
        self.write("fixtures/big.json", "[" + "1," * 400 + "1]")
        self.write("big.py", "x = 1\n" * 200)
        config = Config()
        config.max_file_bytes = 500
        graph = scan_repository(self.root, config)
        levels = {(i.code, i.evidence): i.severity for i in graph.issues if i.code.endswith("FILE_SKIPPED")}
        self.assertEqual(levels, {("DATA_FILE_SKIPPED", "fixtures/big.json"): "info", ("FILE_SKIPPED", "big.py"): "warning"})
        config.extensions = config.extensions | {".cs"}
        self.write("Big.cs", "class A {}\n" * 100)
        graph = scan_repository(self.root, config)
        self.assertIn(("FILE_SKIPPED", "Big.cs"), {(i.code, i.evidence) for i in graph.issues})

    @unittest.skipUnless(HAS_STACK, "install repolens[stack]")
    def test_incomplete_analysis_names_each_cause(self):
        from repolens.analysis import analyze
        self.write("big.py", "x = 1\n" * 200)
        self.write("fixtures/big.json", "[" + "1," * 400 + "1]")
        config = Config()
        config.max_file_bytes = 500
        result = analyze(self.root, config=config)
        self.assertFalse(result.complete)
        self.assertEqual(result.incomplete_reasons(), ["FILE_SKIPPED x1 (e.g. big.py)"])
        payload = result.to_dict()
        self.assertEqual(payload["incomplete_reasons"], result.incomplete_reasons())
        self.assertIn("- Incomplete: FILE_SKIPPED x1 (e.g. big.py)", result.markdown())
        [stack] = [run for run in result.runs if run.tool == "stack"]
        self.assertEqual(stack.notes, [])


if __name__ == "__main__":
    unittest.main()
