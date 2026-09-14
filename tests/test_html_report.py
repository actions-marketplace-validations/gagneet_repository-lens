"""The HTML report is complete, self-contained and escapes everything from the repository."""
from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path

from repolens.core import javascript
from repolens.core.findings import Finding, ToolRun
from repolens.core.html_report import ROW_CAP, render_html
from repolens.impact.model import Issue

HAS_STACK = javascript.available() and importlib.util.find_spec("sqlglot") is not None
HOSTILE = '<script>alert(1)</script><img src=x onerror=alert(2)>"'


def finding(**overrides):
    values = dict(tool="security", rule="security/x", severity="high", confidence="high", category="security",
                  file="app.py", line=3, message="bad", remedy="fix it")
    values.update(overrides)
    return Finding(**values)


class HtmlReportTests(unittest.TestCase):
    def test_repository_text_is_escaped_and_the_page_loads_nothing(self):
        page = render_html([ToolRun("security", findings=[finding(message=HOSTILE, file=HOSTILE)])],
                           title="t", repository=HOSTILE, complete=False, incomplete_reasons=[HOSTILE],
                           diagnostics=[Issue("X", "warning", HOSTILE, [], HOSTILE, HOSTILE)], linkage=HOSTILE)
        self.assertNotIn("<script", page)
        self.assertNotIn("<img", page)
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", page)
        self.assertIn("default-src 'none'", page)
        self.assertNotRegex(page, r"(?i)(src|href)=[\"']?(https?:|//)")

    def test_every_section_and_status_is_rendered(self):
        runs = [ToolRun("security", findings=[finding(), finding(rule="security/y", severity="low", confidence="low")]),
                ToolRun("ruff", skipped="ruff is not installed"), ToolRun("migrations", notes=["a.py was not examined."])]
        page = render_html(runs, title="Report", complete=False, incomplete_reasons=["FILE_SKIPPED x1 (e.g. big.py)"],
                           diagnostics=[Issue("API_METHOD_MISMATCH", "warning", "PATCH /x gets 405", [], "x.js:2", "Use GET")],
                           coverage={"python": 2}, limits=["Static only."], linkage="flowchart LR", build="repolens 0.3.0")
        for text in ("analysis incomplete", "FILE_SKIPPED x1 (e.g. big.py)", "security/x", "security/y",
                     "SKIPPED: ruff is not installed", "PARTIAL: 1 input note(s)", "a.py was not examined.",
                     "API_METHOD_MISMATCH", "PATCH /x gets 405", "Use GET", "flowchart LR", "python",
                     "Static only.", "Produced by repolens 0.3.0", 'id="findings"', 'id="diagnostics"'):
            self.assertIn(text, page)
        self.assertIn("no completeness claim", render_html([], title="r"))
        self.assertIn("No findings from the checks that ran.", render_html([], title="r"))

    def test_long_groups_are_capped_with_a_count(self):
        issues = [Issue("MANY", "info", f"m{i}", [], f"f{i}.py", "") for i in range(ROW_CAP + 7)]
        page = render_html([], title="r", complete=True, diagnostics=issues)
        self.assertIn("7 more in the JSON output.", page)
        self.assertNotIn(f"f{ROW_CAP + 1}.py", page)

    @unittest.skipUnless(HAS_STACK, "install repolens[stack]")
    def test_analyze_writes_html_next_to_markdown(self):
        from repolens.analysis import main
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "app.py").write_text("def main(): pass\n", encoding="utf-8")
            from repolens.config import load_config
            self.assertEqual(main(["--out", str(root / "out")], config=load_config(root)), 0)
            page = (root / "out/report.html").read_text(encoding="utf-8")
            self.assertTrue((root / "out/report.md").is_file())
            self.assertIn("analysis complete", page)
            self.assertIn("Repository Lens analysis", page)
            self.assertRegex((root / "out/linkage.mmd").read_text(encoding="utf-8"), r"\n%% produced by repolens \S+ .*\n$")


if __name__ == "__main__":
    unittest.main()


class HtmlBudgetTests(unittest.TestCase):
    def test_the_page_has_a_total_row_budget_and_clipped_cells(self):
        from repolens.core import html_report
        issues = [Issue(f"CODE{c}", "info", "x" * 5000, [], f"f{c}-{i}.py", "") for c in range(12) for i in range(ROW_CAP)]
        page = render_html([], title="r", complete=True, diagnostics=issues)
        self.assertLessEqual(page.count("<tr>"), html_report.TOTAL_ROWS + 40)  # plus header and summary rows
        self.assertIn("more in the JSON output.", page)
        self.assertIn("2 code(s) not shown: 1000 more in the JSON output.", page)
        self.assertNotIn("x" * (html_report.CELL_CHARS + 1), page)

    def test_a_distinct_rule_per_finding_does_not_grow_the_page_past_the_budget(self):
        from repolens.core.findings import Finding, ToolRun
        run = ToolRun("sarif", findings=[Finding("sarif", f"rule/{i}", "low", "m", file="a.py", line=i)
                                         for i in range(20_000)],
                      notes=[f"note {i}" for i in range(20_000)])
        page = render_html([run], title="r")
        self.assertIn("rule(s) not shown:", page)
        self.assertLess(page.count("<details"), 5_200)
        self.assertLess(page.count("<li>"), 600)
