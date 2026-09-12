from __future__ import annotations

import contextlib
import io
import tempfile
import textwrap
import unittest
from pathlib import Path

from repolens.config import load_config
from repolens.docs import build, coverage
from repolens.docs.settings import from_config


class Tree:
    def __init__(self, files: dict[str, str], docs: str = ""):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.write({"repolens.toml": "[docs]\n" + textwrap.dedent(docs), **files})

    def write(self, files: dict[str, str]) -> None:
        for path, text in files.items():
            target = self.root / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(textwrap.dedent(text), encoding="utf-8")

    @property
    def config(self):
        return load_config(str(self.root))

    @property
    def settings(self):
        return from_config(self.config)

    def close(self) -> None:
        self.tmp.cleanup()


PYTHON = '''
    """Module doc."""
    from typing import overload

    def documented():
        """Yes."""

    def bare():
        pass

    def _private():
        pass

    class Thing:
        """A thing."""
        def __init__(self):
            pass
        def method(self):
            pass
        @property
        def value(self):
            """The value."""
        @value.setter
        def value(self, v):
            pass
        def outer(self):
            """Outer."""
            def inner():
                pass

    @overload
    def f(x: int) -> int: ...
    def f(x):
        """F."""
'''

JAVASCRIPT = """
    /** Documented. */
    export function documented() {}

    export function bare() {}

    /** Decorated class. */
    @decorator
    export class Decorated {}

    function Page() {}
    export default withAuth(Page);

    const a = 1;
    const b = 2;
    export { a };
    export { b } from "./b";

    /**/
    export const empty = 1;

    /* not jsdoc */
    export const plain = 2;

    function internal() {}
"""


def _quiet(fn, *args, **kwargs):
    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
        return fn(*args, **kwargs)


class PythonCoverageTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tree = Tree({})
        self.s = self.tree.settings

    def tearDown(self) -> None:
        self.tree.close()

    def test_public_symbols_are_counted_and_stubs_dunders_and_nesting_are_not(self):
        result = coverage.python_file("m.py", textwrap.dedent(PYTHON), self.s)
        self.assertEqual([s.name for s in result.symbols],
                         ["<module>", "documented", "bare", "Thing", "Thing.method",
                          "Thing.value", "Thing.outer", "f"])
        self.assertEqual([s.name for s in result.missing], ["bare", "Thing.method"])

    def test_an_empty_module_has_nothing_to_describe(self):
        self.assertEqual(coverage.python_file("__init__.py", "", self.s).symbols, [])

    def test_a_file_that_does_not_parse_is_unmeasured_and_keeps_its_baseline_count(self):
        result = coverage.python_file("bad.py", "def (:\n", self.s)
        self.assertTrue(result.error)
        self.assertEqual(coverage.missing_counts([result], {"bad.py": 4}), {"bad.py": 4})
        self.assertEqual(coverage.missing_counts([result], None), {})


class PlaceholderTests(unittest.TestCase):
    def test_generated_boilerplate_is_not_documentation(self):
        tree = Tree({}, docs='placeholder_patterns = ["Generated inventory header"]\n')
        try:
            result = coverage.python_file(
                "m.py", '"""Generated inventory header: 12 functions."""\nx = 1\n', tree.settings)
        finally:
            tree.close()
        self.assertEqual([s.name for s in result.missing], ["<module>"])


class JavaScriptCoverageTests(unittest.TestCase):
    def test_exported_declarations_and_names_exported_later_are_counted(self):
        tree = Tree({})
        try:
            result = coverage.javascript_file("a.ts", textwrap.dedent(JAVASCRIPT), tree.settings)
        finally:
            tree.close()
        documented = [s.name for s in result.symbols if s.documented]
        self.assertEqual(documented, ["documented", "Decorated"])
        # `b` is re-exported from another module and `internal` is never exported.
        self.assertEqual([s.name for s in result.missing], ["bare", "Page", "a", "empty", "plain"])


class RatchetTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tree = Tree({"pkg/a.py": '"""A."""\ndef one():\n    pass\n'})

    def tearDown(self) -> None:
        self.tree.close()

    def _run(self, *argv: str) -> int:
        return _quiet(coverage.main, list(argv), config=self.tree.config)

    def test_a_check_with_no_baseline_fails_rather_than_passing_by_construction(self):
        self.assertEqual(self._run("--check"), 1)

    def test_a_file_may_not_gain_an_undocumented_symbol(self):
        self.assertEqual(self._run("--update-baseline"), 0)
        self.assertEqual(self._run("--check"), 0)
        self.tree.write({"pkg/a.py": '"""A."""\ndef one():\n    pass\ndef two():\n    pass\n'})
        self.assertEqual(self._run("--check"), 1)

    def test_a_new_file_must_be_fully_documented(self):
        self._run("--update-baseline")
        self.tree.write({"pkg/b.py": '"""B."""\ndef three():\n    pass\n'})
        self.assertEqual(self._run("--check"), 1)

    def test_an_improvement_fails_until_the_baseline_records_it(self):
        self._run("--update-baseline")
        self.tree.write({"pkg/a.py": '"""A."""\ndef one():\n    """Now documented."""\n'})
        self.assertEqual(self._run("--check"), 1)
        self.assertEqual(self._run("--update-baseline"), 0)
        self.assertEqual(self._run("--check"), 0)


class BuildTests(unittest.TestCase):
    def test_only_a_directory_repolens_generated_is_ever_cleared(self):
        with tempfile.TemporaryDirectory() as tmp:
            mine, theirs = Path(tmp) / "mine", Path(tmp) / "theirs"
            for target in (mine, theirs):
                target.mkdir()
                (target / "keep.html").write_text("x", encoding="utf-8")
            (mine / build.MARKER).write_text("", encoding="utf-8")
            build._clear(mine)
            build._clear(theirs)  # not ours: left exactly as it was
            self.assertTrue((theirs / "keep.html").is_file())
            self.assertFalse((mine / "keep.html").exists())

    def test_the_index_is_deterministic(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            parts = [build.Part("python", "built", "3 pages", out / "python"),
                     build.Part("typescript", "skipped", "no npx")]
            first = build.write_index(out, parts, "demo").read_text(encoding="utf-8")
            second = build.write_index(out, parts, "demo").read_text(encoding="utf-8")
        self.assertEqual(first, second)
        self.assertIn("no npx", first)

    def test_a_missing_generator_is_a_skip_and_strict_turns_a_skip_into_a_failure(self):
        # An interpreter that exists and cannot import pdoc: the same answer whether or not
        # the machine running the test has pdoc installed.
        tree = Tree({"pkg/__init__.py": '"""P."""\n', "nopdoc": "#!/bin/sh\nexit 1\n"},
                    docs='[docs.python]\nmodules = ["pkg"]\ninterpreter = "nopdoc"\n')
        (tree.root / "nopdoc").chmod(0o755)
        try:
            self.assertEqual(_quiet(build.main, ["--python", "--out", str(tree.root / "out")],
                                    config=tree.config), 0)
            self.assertEqual(_quiet(build.main, ["--python", "--strict", "--out", str(tree.root / "out")],
                                    config=tree.config), 1)
        finally:
            tree.close()

    def test_a_configured_interpreter_that_does_not_exist_is_named_not_papered_over(self):
        tree = Tree({}, docs='[docs.python]\nmodules = ["no_such_module"]\ninterpreter = "venv/bin/python3"\n')
        try:
            part = build.build_python(tree.settings, tree.root / "out")
        finally:
            tree.close()
        self.assertIn("configured interpreter venv/bin/python3 not found", part.detail)


if __name__ == "__main__":
    unittest.main()
