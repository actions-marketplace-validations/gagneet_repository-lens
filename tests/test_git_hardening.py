"""A scanned repository's git config must not make repolens run a command.

`core.fsmonitor` names a program git runs on index reads, and a `filter.<name>.clean`
program runs whenever `git status` re-reads a stat-changed file. Both come from the target's
own `.git/config`, which a read-only analyzer must treat as untrusted.
"""
from __future__ import annotations

import os
import shutil
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

from repolens.core import git as core_git
from repolens.impact.scanner import _gitignored
from repolens.report import runner


@unittest.skipIf(shutil.which("git") is None or os.name == "nt", "needs git and POSIX scripts")
class HostileGitConfigTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.root = self.tmp / "repo"
        self.root.mkdir()
        self.marker = self.tmp / "ran"
        fsmonitor = self.write_script("fsmonitor.sh", f'echo fsmonitor >> "{self.marker}"\n')
        clean = self.write_script("clean.sh", f'echo clean >> "{self.marker}"\ncat\n')
        env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}

        def git(*args):
            subprocess.run(["git", "-C", str(self.root), *args], check=True, capture_output=True, env=env)

        git("init", "-q")
        (self.root / ".gitignore").write_text("backup/\n", encoding="utf-8")
        (self.root / "app.py").write_text("x = 1\n", encoding="utf-8")
        git("add", ".")
        git("-c", "user.email=t@example.com", "-c", "user.name=t", "commit", "-qm", "init")
        # Only now the hostile config: nothing above ran under it.
        (self.root / ".gitattributes").write_text("*.py filter=evil\n", encoding="utf-8")
        git("config", "filter.evil.clean", str(clean))
        git("config", "core.fsmonitor", str(fsmonitor))
        (self.root / "app.py").write_text("x = 2  # a different size, so the stat changed\n", encoding="utf-8")

    def write_script(self, name, body):
        path = self.tmp / name
        path.write_text("#!/bin/sh\n" + body, encoding="utf-8")
        path.chmod(path.stat().st_mode | stat.S_IXUSR)
        return path

    def assertNothingRan(self):
        self.assertFalse(self.marker.exists(), self.marker.read_text() if self.marker.exists() else "")

    def test_the_report_commit_stamp_reads_dirty_without_running_filters(self):
        self.assertTrue(runner._commit(self.root).endswith("+dirty"))
        self.assertNothingRan()

    def test_tracked_paths_ignored_and_modified_run_nothing(self):
        self.assertIn("app.py", core_git.tracked_paths(self.root))
        self.assertEqual(core_git.ignored(self.root, ["backup/x.py", "app.py"]), {"backup/x.py"})
        self.assertTrue(core_git.is_modified(self.root))
        self.assertNothingRan()

    def test_the_gitignore_listing_runs_nothing(self):
        (self.root / "backup").mkdir()
        (self.root / "backup" / "old.py").write_text("y = 1\n", encoding="utf-8")
        ignored, reason = _gitignored(self.root)
        self.assertEqual((ignored, reason), (frozenset({"backup"}), ""))
        self.assertNothingRan()

    def test_an_unreadable_repository_is_unknown_not_clean(self):
        shutil.rmtree(self.root / ".git" / "objects")
        self.assertIsNone(core_git.is_modified(self.root))


if __name__ == "__main__":
    unittest.main()
