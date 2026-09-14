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



class FrontendExtractionTests(unittest.TestCase):
    """The tree-sitter path of the lens, which runs only when [lens] javascript_parser names
    it. Skipped without the stack extra, so it needs an environment that has it."""

    def setUp(self):
        from repolens.core import javascript
        if not javascript.available():
            self.skipTest("requires repolens[stack]")

    def test_a_tree_sitter_lens_build_indexes_frontend_functions_and_their_calls(self):
        import json
        from repolens.lens.build import _extract_frontend, build
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "repolens.toml").write_text('[lens]\npython_roots = ["api"]\nfrontend_roots = ["web"]\n'
                                                'javascript_parser = "tree-sitter"\n', encoding="utf-8")
            (root / "api").mkdir()
            (root / "api" / "a.py").write_text("def f():\n    return 1\n", encoding="utf-8")
            (root / "web").mkdir()
            (root / "web" / "page.tsx").write_text(
                "import { load } from './load';\nexport function Page() {\n  load();\n  return <Card />;\n}\n", encoding="utf-8")
            (root / "web" / "load.ts").write_text("export async function load() { return fetch('/api/x'); }\n", encoding="utf-8")
            settings = from_config(load_config(root))
            data = build(settings)
            self.assertIn("web/page.tsx::Page", json.dumps(data))
            [page] = [r for r in _extract_frontend(settings, root / "web" / "page.tsx", [], None) if r["name"] == "Page"]
            self.assertEqual((page["extraction"], page["callees"]), ("tree-sitter", ["load"]))


class JavascriptParserSettingTests(unittest.TestCase):
    """The frontend parser is configured, never detected, and recorded, so an
    optional extra cannot change a committed artefact."""

    PAGE = "export function Page() {\n  load();\n}\nexport const load = () => fetch('/x');\n"

    def repo(self, lens: str = "") -> Path:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        (root / "repolens.toml").write_text(
            '[lens]\npython_roots = ["api"]\nfrontend_roots = ["web"]\n' + lens, encoding="utf-8")
        (root / "api").mkdir()
        (root / "api" / "a.py").write_text("def f():\n    return 1\n", encoding="utf-8")
        (root / "web").mkdir()
        (root / "web" / "page.ts").write_text(self.PAGE, encoding="utf-8")
        return root

    def run_main(self, root: Path, *argv: str) -> tuple[int, str]:
        import contextlib
        import io
        from repolens.lens.build import main
        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
            try:
                code = main(list(argv), config=load_config(root))
            except SystemExit as exc:  # a refusal raised before main returns
                code, out = 1, io.StringIO(str(exc))
        return code, out.getvalue()

    def test_regex_is_the_default_and_ignores_an_installed_tree_sitter(self):
        from unittest import mock
        from repolens.core import javascript
        from repolens.lens.build import build, digest
        settings = from_config(load_config(self.repo()))
        self.assertEqual(settings.javascript_parser, "regex")
        with mock.patch.object(javascript, "available", return_value=True), \
                mock.patch.object(javascript, "parse_source", side_effect=AssertionError("tree-sitter used")):
            data = build(settings)
        page = data["functions"]["web/page.ts::Page"]
        # Regex records are unchanged from before the setting existed, so the content hash of
        # an index committed then still matches.
        self.assertNotIn("extraction", page)
        self.assertEqual((page["language"], page["callees"]), ("javascript", []))
        self.assertEqual((data["javascript_parser"], digest(data)["javascript_parser"]), ("regex", "regex"))

    @unittest.skipUnless(__import__("importlib").util.find_spec("tree_sitter"), "requires repolens[stack]")
    def test_tree_sitter_is_used_when_configured(self):
        from repolens.lens.build import build, digest
        data = build(from_config(load_config(self.repo('javascript_parser = "tree-sitter"\n'))))
        page = data["functions"]["web/page.ts::Page"]
        # The index resolves callee names to the definitions they name.
        self.assertEqual((page["extraction"], page["callees"]), ("tree-sitter", ["web/page.ts::load"]))
        self.assertEqual(digest(data)["javascript_parser"], "tree-sitter")

    def test_a_configured_tree_sitter_that_is_not_installed_is_an_error_not_a_fallback(self):
        from unittest import mock
        from repolens.core import javascript
        from repolens.lens.build import build
        settings = from_config(load_config(self.repo('javascript_parser = "tree-sitter"\n')))
        with mock.patch.object(javascript, "available", return_value=False), \
                self.assertRaises(SystemExit) as caught:
            build(settings)
        self.assertIn("javascript_parser", str(caught.exception))
        self.assertIn("repolens[stack]", str(caught.exception))

    def test_an_unknown_or_auto_parser_is_refused(self):
        for value in ("auto", "typescript"):
            with self.assertRaises(SystemExit, msg=value) as caught:
                from_config(load_config(self.repo(f'javascript_parser = "{value}"\n')))
            self.assertIn("never detected", str(caught.exception))

    def test_the_parser_is_part_of_the_source_stamp(self):
        from repolens.lens.build import source_stamp
        root = self.repo()
        regex = source_stamp(from_config(load_config(root)))
        (root / "repolens.toml").write_text(
            '[lens]\npython_roots = ["api"]\nfrontend_roots = ["web"]\njavascript_parser = "tree-sitter"\n',
            encoding="utf-8")
        self.assertNotEqual(regex, source_stamp(from_config(load_config(root))))

    def test_check_refuses_a_digest_committed_with_the_other_parser(self):
        import json
        from unittest import mock
        from repolens.lens import build as lens_build
        root = self.repo('javascript_parser = "tree-sitter"\n')
        digest_path = root / ".repolens" / "function_lens_digest.json"
        digest_path.parent.mkdir()
        digest_path.write_text(json.dumps({"javascript_parser": "regex", "content_sha256": "x",
                                           "counts": {"total": 1}}), encoding="utf-8")
        with mock.patch.object(lens_build, "build", side_effect=AssertionError("built")):
            code, out = self.run_main(root, "--check")
        self.assertEqual(code, 2)
        self.assertIn("committed with regex, this run would use tree-sitter; set [lens] javascript_parser", out)
        self.assertNotIn("STALE", out)

    def test_an_old_digest_without_a_parser_counts_as_regex(self):
        import json
        root = self.repo()
        self.assertEqual(self.run_main(root)[0], 0)  # writes the digest with the regex parser
        digest_path = root / ".repolens" / "function_lens_digest.json"
        old = json.loads(digest_path.read_text(encoding="utf-8"))
        del old["javascript_parser"]
        digest_path.write_text(json.dumps(old), encoding="utf-8")
        code, out = self.run_main(root, "--check")
        self.assertEqual(code, 0, out)
        self.assertIn("OK", out)

        (root / "repolens.toml").write_text(
            '[lens]\npython_roots = ["api"]\nfrontend_roots = ["web"]\njavascript_parser = "tree-sitter"\n',
            encoding="utf-8")
        code, out = self.run_main(root, "--check")
        self.assertEqual(code, 2)
        self.assertIn("committed with regex, this run would use tree-sitter", out)


if __name__ == "__main__":
    unittest.main()
