from __future__ import annotations

import argparse
import contextlib
import io
import tempfile
import tomllib
import unittest
from pathlib import Path

from repolens import bootstrap, rules


def _args(**overrides) -> argparse.Namespace:
    values = dict(dry_run=False, force=False, rules_dir="docs/repolens", no_rules=False,
                  agents_file=None, ci=None, install_spec="repolens[yaml,docs]")
    values.update(overrides)
    return argparse.Namespace(**values)


class InitTests(unittest.TestCase):
    FILES = {
        "backend/app/__init__.py": "",
        "backend/app/x.py": "x = 1\n",
        "frontend/src/lib/a.ts": "export const a = 1;\n",
        "frontend/src/types.d.ts": "declare const b: number;\n",
        "frontend/tsconfig.json": "{}\n",
        "frontend/node_modules/pkg/index.js": "module.exports = 1;\n",
        "tests/test_x.py": "def test_x():\n    pass\n",
        "docs/conf.py": "project = 'x'\n",
        "svc/Api.csproj": "<Project />\n",
        "svc/Program.cs": "class Program {}\n",
    }

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        for path, text in self.FILES.items():
            target = self.root / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(text, encoding="utf-8")

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _apply(self, **overrides) -> list[bootstrap.Action]:
        actions, _ = bootstrap.plan(self.root, _args(**overrides))
        bootstrap.apply(actions)
        return actions

    def test_detection_skips_tests_docs_dependencies_and_declaration_files(self):
        d = bootstrap.detect(self.root)
        self.assertEqual(d.python_roots, ["backend"])
        self.assertEqual(d.javascript_roots, ["frontend/src"])
        self.assertEqual((d.tsconfig, d.ts_entry_points), ("frontend/tsconfig.json", ["frontend/src/lib"]))
        self.assertEqual((d.pdoc_modules, d.pdoc_path), (["app"], ["backend"]))
        self.assertEqual(d.csharp_projects, ["svc/Api.csproj"])
        self.assertEqual((d.counts["javascript"], d.counts["csharp"]), (1, 1))

    def test_the_profile_parses_and_names_what_was_found(self):
        self._apply()
        profile = tomllib.loads((self.root / "repolens.toml").read_text(encoding="utf-8"))
        self.assertEqual(profile["docs"]["python_roots"], ["backend"])
        self.assertEqual(profile["docs"]["javascript_roots"], ["frontend/src"])
        self.assertIn("dotnet", (self.root / "repolens.toml").read_text(encoding="utf-8"))
        for name in rules.documents():
            self.assertTrue((self.root / "docs/repolens" / name).is_file(), name)

    def test_a_second_run_changes_nothing(self):
        self._apply(agents_file="AGENTS.md", ci="github")
        actions, _ = bootstrap.plan(self.root, _args(agents_file="AGENTS.md", ci="github"))
        self.assertEqual({a.verb for a in actions}, {"skip", "unchanged"})

    def test_an_existing_file_is_kept_unless_forced(self):
        (self.root / "repolens.toml").write_text("# mine\n", encoding="utf-8")
        self._apply()
        self.assertEqual((self.root / "repolens.toml").read_text(encoding="utf-8"), "# mine\n")
        self._apply(force=True)
        self.assertNotEqual((self.root / "repolens.toml").read_text(encoding="utf-8"), "# mine\n")

    def test_gitignore_gains_only_the_lines_it_lacks(self):
        (self.root / ".gitignore").write_text("node_modules/\n.repolens/report/\n", encoding="utf-8")
        self._apply()
        lines = (self.root / ".gitignore").read_text(encoding="utf-8").splitlines()
        self.assertEqual(lines.count(".repolens/report/"), 1)
        self.assertIn(".repolens/docs/", lines)
        self.assertEqual(lines[0], "node_modules/")

    def test_the_agents_file_is_only_edited_between_its_markers(self):
        agents = self.root / "CLAUDE.md"
        agents.write_text("# House rules\n\nKeep this.\n", encoding="utf-8")
        self._apply(agents_file="CLAUDE.md")
        text = agents.read_text(encoding="utf-8")
        self.assertTrue(text.startswith("# House rules\n\nKeep this.\n"))
        self.assertIn("<!-- repolens:rules:start -->", text)
        # A block edited by hand is refreshed in place; the text around it survives.
        agents.write_text(text.replace("<!-- repolens:rules:end -->",
                                       "stale\n<!-- repolens:rules:end -->") + "After.\n",
                          encoding="utf-8")
        self._apply(agents_file="CLAUDE.md")
        refreshed = agents.read_text(encoding="utf-8")
        self.assertNotIn("stale", refreshed)
        self.assertTrue(refreshed.endswith("After.\n"))
        self.assertEqual(refreshed.count("<!-- repolens:rules:start -->"), 1)

    def test_the_ci_workflow_pins_the_scanners_the_baseline_was_built_with(self):
        self._apply(ci="github")
        workflow = (self.root / ".github/workflows/repolens.yml").read_text(encoding="utf-8")
        for tool, version in bootstrap.SCANNER_PINS.items():
            self.assertIn(f"{tool}=={version}", workflow)
        self.assertIn("report --check", workflow)
        self.assertNotIn("@@", workflow)

    def test_a_dry_run_writes_nothing(self):
        from repolens.config import load_config
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(bootstrap.main(["--dry-run"], config=load_config(str(self.root))), 0)
        self.assertFalse((self.root / "repolens.toml").exists())

    def test_a_ci_workflow_without_an_install_spec_is_refused(self):
        # No default: a bare `repolens` resolves on PyPI, where this project does not publish.
        from repolens.config import load_config
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()), \
                self.assertRaises(SystemExit) as refused:
            bootstrap.main(["--ci", "github"], config=load_config(str(self.root)))
        self.assertEqual(refused.exception.code, 2)
        self.assertFalse((self.root / ".github").exists())
        self.assertFalse((self.root / "repolens.toml").exists())


class RulesTests(unittest.TestCase):
    def test_every_rule_has_a_title_and_the_index_names_it(self):
        index = rules.text("README")
        for name in rules.names():
            self.assertTrue(rules.text(name).startswith("# "), name)
            self.assertIn(f"{name}.md", index, name)

    def test_an_unknown_rule_is_an_error(self):
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(rules.main(["show", "no-such-rule"]), 2)
            self.assertEqual(rules.main(["show", "docstrings"]), 0)


if __name__ == "__main__":
    unittest.main()
