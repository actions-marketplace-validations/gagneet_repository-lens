"""Function Lens: the cache stamp, and the git history it reads for churn."""
from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from repolens.config import load_config
from repolens.lens.build import _file_churn
from repolens.lens.settings import from_config

_PACKAGE_ROOT = Path(__file__).resolve().parents[1]
_GIT = ["git", "-c", "user.name=t", "-c", "user.email=t@example.invalid",
        "-c", "commit.gpgsign=false", "-c", "init.defaultBranch=main"]


class SourceStampTests(unittest.TestCase):

    def test_the_stamp_is_the_same_in_every_process(self):
        # The stamp decides whether the cached index is still good. Built from repr() of
        # a settings object holding a frozenset, it followed PYTHONHASHSEED, so a fresh
        # process never matched the stamp the index was written with.
        code = ("import sys; from repolens.config import load_config; "
                "from repolens.lens.build import source_stamp; "
                "from repolens.lens.settings import from_config; "
                "print(source_stamp(from_config(load_config(sys.argv[1]))))")
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "repolens.toml").write_text(
                '[lens]\nguard_calls = ["alpha", "bravo", "charlie", "delta", "echo", "foxtrot"]\n',
                encoding="utf-8")
            Path(tmp, "a.py").write_text("def f():\n    return 1\n", encoding="utf-8")
            stamps = {
                subprocess.run([sys.executable, "-c", code, tmp], cwd=_PACKAGE_ROOT, check=True,
                               capture_output=True, text=True,
                               env={**os.environ, "PYTHONHASHSEED": seed,
                                    "PYTHONPATH": str(_PACKAGE_ROOT)}).stdout.strip()
                for seed in ("1", "2", "3", "4")
            }
        self.assertEqual(len(stamps), 1, stamps)


class ChurnTests(unittest.TestCase):

    def test_a_path_is_counted_as_itself(self):
        # Line-split output stripped the edge spaces off " padded.py" and split
        # "two\nlines.py" in half (git also quotes that one without -z).
        names = [" padded.py", "two\nlines.py", "plain.py"]
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            subprocess.run(_GIT + ["init", "-q"], cwd=root, check=True)
            for n in (1, 2):
                for name in names:
                    (root / name).write_text(f"x = {n}\n", encoding="utf-8")
                subprocess.run(_GIT + ["add", "-A"], cwd=root, check=True)
                subprocess.run(_GIT + ["commit", "-q", "-m", f"round {n}"], cwd=root, check=True)
            churn = _file_churn(from_config(load_config(tmp)))
        self.assertEqual({name: churn.get(name, {}).get("commits") for name in names},
                         dict.fromkeys(names, 2))
        self.assertTrue(all(churn[name]["last_changed"] for name in names))


if __name__ == "__main__":
    unittest.main()
