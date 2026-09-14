from __future__ import annotations

import ast
import contextlib
import io
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
import textwrap
import unittest
from collections import defaultdict
from pathlib import Path

from repolens.config import load_config, merge
from repolens.core.findings import (BaselineError, Finding, ToolRun, load_baseline,
                                    load_magnitudes, mark_new, to_sarif, write_baseline)
from repolens.gates import reachability
from repolens.report import runner
from repolens.scan import performance, security
from repolens.scan.python_ast import literal_locals
from repolens.scan.settings import from_config
from repolens.scan.wiring import unreachable_route_files

CONST = re.compile(r"^[A-Z][A-Z0-9_]*$")


def _fn(source: str) -> ast.FunctionDef:
    return ast.parse(textwrap.dedent(source)).body[0]


class Repo:
    def __init__(self, files: dict[str, str]):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        files = {"repolens.toml": '[scan]\npython_roots = ["."]\n', **files}
        for path, text in files.items():
            target = self.root / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(textwrap.dedent(text), encoding="utf-8")
        self.settings = from_config(load_config(str(self.root)))

    def close(self) -> None:
        self.tmp.cleanup()


APP = """
    from fastapi import FastAPI
    from routers.live import router
    app = FastAPI()
    app.include_router(router)
"""

LIVE = """
    import time
    from fastapi import APIRouter, Depends, Request
    from sqlalchemy import text
    router = APIRouter()

    @router.post("/hook")
    async def hook(request: Request):
        body = await request.body()
        verify_hook_signature(body, request.headers.get("x-sig"))
        return {}

    @router.post("/open")
    async def open_write(request: Request):
        return {}

    @router.get("/orgs/{org_id}/projects")
    async def list_org_projects(org_id: str, current_user: dict = Depends(get_current_user)):
        return await load(org_id)

    @router.delete("/orgs/{org_id}")
    async def delete_org(org_id: str, current_user: dict = Depends(get_current_user)):
        _require_org_admin(current_user)
        return await remove(org_id)

    @router.patch("/payments/{payment_id}/reject")
    async def reject(payment_id: str, current_user: dict = Depends(get_current_user)):
        return await dispatch(handler=lambda: _reject(payment_id, current_user))

    @router.get("/rows")
    async def rows(status: str, session=None, current_user: dict = Depends(get_current_user)):
        where = ["deleted = FALSE"]
        if status:
            where.append("status = :status")
        await session.execute(text(f"SELECT * FROM t WHERE {' AND '.join(where)}"), {"status": status})
        await session.execute(text(f"SELECT * FROM t ORDER BY {status}"))
        time.sleep(1)
        return await db.t.find({}).limit(5).to_list(None)
"""

DEAD = """
    from fastapi import APIRouter
    router = APIRouter()

    @router.post("/dead")
    async def dead_write():
        return {}
"""


class FindingTests(unittest.TestCase):
    def test_priority_blends_severity_confidence_and_exposure(self):
        self.assertEqual(Finding("t", "r", "high", "m", confidence="high", exposure="unauthenticated").priority, "P0")
        self.assertEqual(Finding("t", "r", "high", "m", confidence="high", exposure="authenticated").priority, "P1")
        self.assertEqual(Finding("t", "r", "high", "m", confidence="low").priority, "P2")

    def test_dead_code_never_outranks_live_code(self):
        self.assertEqual(Finding("t", "r", "critical", "m", confidence="high", exposure="unreachable").priority, "P3")

    def test_the_fingerprint_survives_a_moved_line_and_a_changed_count(self):
        a = Finding("t", "r", "low", "3 rows", file="a.py", line=10)
        b = Finding("t", "r", "low", "4 rows", file="a.py", line=99)
        self.assertEqual(a.fingerprint, b.fingerprint)

    def test_the_json_form_carries_the_location(self):
        self.assertEqual(Finding("t", "r", "low", "m", file="a.py", line=3).to_dict()["location"], "a.py:3")

    def test_sarif_labels_a_security_rule_for_code_scanning(self):
        run = ToolRun("security", findings=[Finding("security", "s/x", "high", "m", category="security")])
        self.assertIn('"security-severity": "8.0"', to_sarif([run], "0"))

    def test_a_count_that_is_the_finding_keeps_one_fingerprint_and_records_its_size(self):
        # The count is compared through `magnitudes`, not the fingerprint: a count in the
        # fingerprint made a ratchet that FELL read as a brand-new finding.
        a = Finding("cmd:x", "check/x", "medium", "FAIL: 2 new reads", counts_matter=True)
        b = Finding("cmd:x", "check/x", "medium", "FAIL: 3 new reads", counts_matter=True)
        self.assertEqual(a.fingerprint, b.fingerprint)
        self.assertEqual((a.magnitudes, b.magnitudes), ([2], [3]))
        self.assertEqual(Finding("t", "r", "low", "3 rows").magnitudes, [])

    def test_sarif_says_a_crashed_tool_produced_no_results_rather_than_none(self):
        [run] = json.loads(to_sarif([ToolRun("bandit", error="exit 2")], "0"))["runs"]
        self.assertNotIn("results", run)
        self.assertFalse(run["invocations"][0]["executionSuccessful"])

    def test_sarif_gives_a_rule_the_severity_of_its_worst_result(self):
        run = ToolRun("security", findings=[
            Finding("security", "s/x", "high", "a", file="a.py", category="security"),
            Finding("security", "s/x", "medium", "b", file="b.py", category="security")])
        [rule] = json.loads(to_sarif([run], "0"))["runs"][0]["tool"]["driver"]["rules"]
        self.assertEqual(rule["properties"]["security-severity"], "8.0")

    def test_only_findings_missing_from_the_baseline_are_new(self):
        old, fresh = Finding("t", "old", "low", "m"), Finding("t", "fresh", "low", "m")
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "b.json"
            write_baseline(path, [old])
            findings = [old, fresh]
            mark_new(findings, load_baseline(path))
        self.assertEqual([f.new for f in findings], [False, True])


class LiteralLocalsTests(unittest.TestCase):
    def test_a_where_clause_assembled_from_literals_is_trusted(self):
        fn = _fn("""
            def f(status):
                where = ["a = 1"]
                if status:
                    where.append("status = :status")
                where_sql = "WHERE " + " AND ".join(where) if where else ""
        """)
        self.assertEqual(literal_locals(fn, CONST), {"where", "where_sql"})

    def test_one_caller_supplied_fragment_withdraws_trust_transitively(self):
        fn = _fn("""
            def f(status):
                where = ["a = 1"]
                where.append(status)
                where_sql = " AND ".join(where)
        """)
        self.assertEqual(literal_locals(fn, CONST), set())

    def test_a_loop_over_a_literal_tuple_is_trusted_and_over_anything_else_is_not(self):
        fn = _fn("""
            def f(cols):
                sets = []
                for col in ("a", "b"):
                    sets.append(f"{col} = :{col}")
                other = []
                for c in cols:
                    other.append(c)
        """)
        self.assertEqual(literal_locals(fn, CONST), {"sets", "col"})

    def test_a_reassigned_parameter_is_never_trusted(self):
        self.assertEqual(literal_locals(_fn("def f(sql):\n    sql = sql + ' x'\n"), CONST), set())

    def test_a_list_that_escapes_is_never_trusted(self):
        fn = _fn("""
            def f(status):
                where = ["a = 1"]
                w = where
                w.append(status)
                cols = ["a"]
                _add_filters(cols, status)
                kept = ["b"]
                clause = " AND ".join(kept)
        """)
        self.assertEqual(literal_locals(fn, CONST), {"kept", "clause"})

    def test_a_match_capture_is_caller_input(self):
        fn = _fn("""
            def f(q):
                match q:
                    case {"sort": col}:
                        order = col
        """)
        self.assertEqual(literal_locals(fn, CONST), set())

    def test_a_parameter_spelled_like_a_constant_is_caller_input(self):
        fn = _fn("""
            def f(ORDER):
                sql = f"SELECT 1 ORDER BY {ORDER}"
                fixed = f"SELECT 1 ORDER BY {DEFAULT_ORDER}"
        """)
        self.assertEqual(literal_locals(fn, CONST), {"fixed"})


class ScanTests(unittest.TestCase):
    def setUp(self) -> None:
        self.repo = Repo({"app.py": APP, "routers/__init__.py": "", "routers/live.py": LIVE,
                          "routers/dead.py": DEAD})
        self.findings = security.scan(self.repo.settings)

    def tearDown(self) -> None:
        self.repo.close()

    def _for(self, rule: str, path_fragment: str) -> list[Finding]:
        return [f for f in self.findings if f.rule == rule and path_fragment in f.message]

    def test_a_signature_verified_in_the_body_authenticates_a_webhook(self):
        self.assertEqual(self._for("security/unauthenticated-mutation-route", "/hook"), [])
        self.assertEqual(len(self._for("security/unauthenticated-mutation-route", "/open")), 1)

    def test_a_guarded_sibling_raises_the_confidence_of_a_bola_candidate(self):
        [finding] = self._for("security/object-route-without-ownership-check", "/projects")
        self.assertEqual(finding.confidence, "medium")
        self.assertIn("DELETE /orgs/{org_id}", finding.message)

    def test_a_pattern_matched_guard_and_an_identity_passed_in_a_lambda_both_count(self):
        self.assertEqual(self._for("security/object-route-without-ownership-check", "delete_org"), [])
        self.assertEqual(self._for("security/object-route-without-ownership-check", "/reject"), [])

    def test_literal_sql_fragments_pass_and_request_input_does_not(self):
        [finding] = [f for f in self.findings if f.rule == "security/sql-built-from-string"]
        self.assertEqual((finding.severity, finding.confidence), ("high", "high"))
        self.assertIn("REQUEST input status", finding.message)

    def test_a_route_module_the_app_never_imports_is_reported_as_unreachable(self):
        self.assertEqual(unreachable_route_files(self.repo.settings), frozenset({"routers/dead.py"}))
        [finding] = self._for("security/unauthenticated-mutation-route", "/dead")
        self.assertEqual((finding.exposure, finding.priority), ("unreachable", "P3"))

    def test_performance_sees_a_blocking_call_and_respects_an_upstream_limit(self):
        found = performance.scan(self.repo.settings)
        self.assertEqual([f.rule for f in found], ["performance/blocking-call-in-async"])


LOOKALIKES = """
    from fastapi import APIRouter, Depends, Header
    router = APIRouter()

    @router.put("/items/{item_id}")
    async def put_item(item_id: str, payload: dict, current_user: dict = Depends(get_current_user)):
        require_fields(payload, "name")
        return await save(item_id, payload)

    @router.post("/inbound")
    async def inbound(payload: dict):
        validate_webhook_payload(payload)
        return await store(payload)

    @router.post("/signed")
    async def signed(payload: dict, x_signature: str = Header(None)):
        return await store(payload)

    @router.delete("/docs/{doc_id}")
    async def delete_doc(doc_id: str, current_user: dict = Depends(get_current_user)):
        await remove(doc_id)
        await audit({"by": current_user["id"]})

    @router.get("/docs/{doc_id}")
    async def get_doc(doc_id: str, current_user: dict = Depends(get_current_user)):
        return await load(doc_id)

    async def listing():
        return await db.t.find({}).limit(0).to_list(None)
"""


class ScopeDependencyTests(unittest.TestCase):
    ROUTES = """
        from fastapi import APIRouter, Depends
        router = APIRouter()

        @router.delete("/items/{item_id}")
        async def remove_item(item_id: str, workspace: dict = Depends(get_current_workspace)):
            return await delete(item_id, workspace)
    """

    def _ownership(self, toml: str = "") -> list[Finding]:
        repo = Repo({"repolens.toml": '[scan]\npython_roots = ["."]\n' + toml, "routers/items.py": self.ROUTES})
        try:
            return [f for f in security.scan(repo.settings) if f.rule == "security/object-route-without-ownership-check"]
        finally:
            repo.close()

    def test_reading_an_authenticating_dependency_counts_as_consulting_the_caller(self):
        self.assertEqual(self._ownership(), [])

    def test_a_dependency_listed_as_a_scope_is_not_the_caller(self):
        [finding] = self._ownership('[scan.security]\nscope_dependency_patterns = ["workspace$"]\n')
        self.assertIn("has no caller-identity parameter at all", finding.message)


class LookalikeTests(unittest.TestCase):
    """Things that are spelled like a check and are not one."""

    def setUp(self) -> None:
        self.repo = Repo({"routers/edge.py": LOOKALIKES})
        self.findings = security.scan(self.repo.settings)

    def tearDown(self) -> None:
        self.repo.close()

    def _for(self, rule: str, path_fragment: str) -> list[Finding]:
        return [f for f in self.findings if f.rule == rule and path_fragment in f.message]

    def test_a_validation_helper_named_require_is_not_a_guard(self):
        self.assertEqual(len(self._for("security/object-route-without-ownership-check", "/items")), 1)

    def test_a_payload_validator_is_not_a_signature_check(self):
        self.assertEqual(len(self._for("security/unauthenticated-mutation-route", "/inbound")), 1)

    def test_a_secret_header_that_is_never_read_authenticates_nothing(self):
        self.assertEqual(len(self._for("security/unauthenticated-mutation-route", "/signed")), 1)

    def test_a_sibling_that_only_records_the_caller_is_no_contrast(self):
        [finding] = self._for("security/object-route-without-ownership-check", "GET /docs")
        self.assertEqual(finding.confidence, "low")
        self.assertNotIn("sibling", finding.message)

    def test_limit_zero_is_no_limit(self):
        rules = [f.rule for f in performance.scan(self.repo.settings)]
        self.assertIn("performance/unbounded-to-list", rules)


class RunnerTests(unittest.TestCase):
    def test_a_crashed_scanner_is_an_error_never_a_clean_run(self):
        for proc in (subprocess.CompletedProcess([], 1, stdout="", stderr="boom"),
                     subprocess.CompletedProcess([], 2, stdout="{}", stderr="fatal")):
            with self.assertRaises(RuntimeError):
                runner._json_output(proc, "x")
        self.assertEqual(runner._json_output(subprocess.CompletedProcess([], 1, stdout='{"a": 1}'), "x"),
                         {"a": 1})

    def test_a_file_bandit_could_not_parse_is_a_finding(self):
        repo = Repo({"a.py": "x = 1\n"})
        with tempfile.TemporaryDirectory() as bindir:
            fake = Path(bindir) / "bandit"
            report = {"errors": [{"filename": "a.py", "reason": "syntax error"}], "results": []}
            fake.write_text(f"#!/bin/sh\necho '{json.dumps(report)}'\nexit 0\n")
            fake.chmod(fake.stat().st_mode | stat.S_IEXEC)
            os.environ["REPOLENS_TOOLS_BIN"] = bindir
            try:
                ctx = runner.Context(load_config(str(repo.root)), merge(runner.DEFAULTS, {}))
                [finding] = runner._bandit(ctx)
            finally:
                del os.environ["REPOLENS_TOOLS_BIN"]
                repo.close()
        self.assertEqual((finding.rule, finding.file), ("bandit/could-not-scan", "a.py"))


class GateSurfaceTests(unittest.TestCase):
    def test_the_profile_counts_only_the_commands_it_runs(self):
        repo = Repo({
            "repolens.toml": textwrap.dedent("""
                [gates]
                scripts = ["checks/*.py"]
                [[artefacts.rules]]
                pattern = '^out\\.json$'
                run = ["checks/generate.py"]
                [[report.commands]]
                name = "audit"
                run = ["python3", "checks/audit.py"]
            """),
            "checks/generate.py": "", "checks/audit.py": "",
        })
        try:
            found = reachability.evaluate(reachability.from_config(load_config(str(repo.root))))
        finally:
            repo.close()
        self.assertEqual(found.unreachable, ["audit.py"])


class CountedBaselineTests(unittest.TestCase):
    """The baseline records how MANY of each fingerprint are known, not just which."""

    def test_a_second_identical_finding_in_the_same_file_is_new(self):
        first = Finding("t", "r", "low", "m", file="a.py", line=1)
        second = Finding("t", "r", "low", "m", file="a.py", line=9)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "b.json"
            write_baseline(path, [first])
            findings = [first, second]
            mark_new(findings, load_baseline(path))
        self.assertEqual([f.new for f in findings], [False, True])

    def test_the_list_format_still_loads_one_per_listed_fingerprint(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "b.json"
            path.write_text('{"fingerprints": ["x", "x", "y"]}', encoding="utf-8")
            self.assertEqual(load_baseline(path), {"x": 2, "y": 1})

    def test_an_unusable_baseline_raises_rather_than_reading_as_empty(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "b.json"
            for text in ("not json", '{"fingerprints": {"x": "1"}}', "[1, 2]"):
                path.write_text(text, encoding="utf-8")
                with self.assertRaises(BaselineError, msg=text):
                    load_baseline(path)

    def test_sarif_gives_repeated_findings_distinct_fingerprints(self):
        run = ToolRun("t", findings=[Finding("t", "r", "low", "m", file="a.py", line=1),
                                     Finding("t", "r", "low", "m", file="a.py", line=9)])
        results = json.loads(to_sarif([run], "0"))["runs"][0]["results"]
        self.assertEqual(len({json.dumps(r["partialFingerprints"]) for r in results}), 2)

    def test_the_report_refuses_an_unusable_baseline(self):
        repo = Repo({"repolens.toml": '[report]\nbaseline = "b.json"\ntools = []\n', "b.json": "{"})
        try:
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                code = runner.main(["--only", "commands", "--out", str(repo.root / "out")],
                                   config=load_config(str(repo.root)))
        finally:
            repo.close()
        self.assertEqual(code, 2)

    def test_the_report_writes_a_stamped_html_page_beside_markdown_and_sarif(self):
        repo = Repo({"repolens.toml": '[report]\ntools = []\n', "app.py": "x = 1\n"})
        try:
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                code = runner.main(["--only", "security", "--out", str(repo.root / "out")],
                                   config=load_config(str(repo.root)))
            out = repo.root / "out"
            page = (out / "report.html").read_text(encoding="utf-8")
            markdown = (out / "report.md").read_text(encoding="utf-8")
            sarif = json.loads((out / "report.sarif").read_text(encoding="utf-8"))
        finally:
            repo.close()
        self.assertEqual(code, 0)
        self.assertIn("default-src 'none'", page)
        self.assertNotIn("<script", page.lower())
        self.assertIn("no completeness claim", page)
        self.assertIn("Produced by repolens ", page)
        self.assertIn("Produced by repolens ", markdown)
        self.assertIn("repolensBuild", sarif["runs"][0]["tool"]["driver"]["properties"])

    def test_check_with_update_baseline_is_rejected(self):
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as caught:
            runner.main(["--check", "--update-baseline"])
        self.assertEqual(caught.exception.code, 2)


class RequiredToolTests(unittest.TestCase):
    """A tool the command line requires must run, in every mode, and a tool installed
    beside the interpreter running repolens is found."""

    def setUp(self):
        self.repo = Repo({"repolens.toml": '[report]\ntools = []\n'})
        self.addCleanup(self.repo.close)

    def main(self, *argv: str) -> tuple[int, str]:
        err = io.StringIO()
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(err):
            code = runner.main([*argv, "--out", str(self.repo.root / "out")],
                               config=load_config(str(self.repo.root)))
        return code, err.getvalue()

    @unittest.skipIf(os.name == "nt", "a POSIX executable bit")
    def test_a_tool_beside_the_running_interpreter_is_found_off_path(self):
        from unittest import mock
        bindir = self.repo.root / "venv" / "bin"
        bindir.mkdir(parents=True)
        tool = bindir / "faketool"
        tool.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        tool.chmod(0o755)
        ctx = runner.Context(load_config(str(self.repo.root)), merge(runner.DEFAULTS, {}))
        with mock.patch.dict(os.environ, {"PATH": "", "REPOLENS_TOOLS_BIN": ""}):
            with self.assertRaises(runner.Skip):
                ctx.executable("faketool")
            with mock.patch.object(runner.sys, "executable", str(bindir / "python")):
                self.assertEqual(ctx.executable("faketool"), str(tool))

    def test_a_required_tool_that_is_skipped_fails_without_check(self):
        # semgrep skips without a configured rules path, installed or not.
        self.assertEqual(self.main("--only", "semgrep")[0], 0)
        code, err = self.main("--only", "semgrep", "--require", "semgrep")
        self.assertEqual(code, 1)
        self.assertIn("required tool semgrep did not run: set [report] semgrep_config", err)

    def test_a_required_tool_that_is_not_selected_fails_without_check(self):
        code, err = self.main("--only", "commands", "--require", "bandit")
        self.assertEqual(code, 1)
        self.assertIn("required tool bandit did not run: not selected", err)

    def test_a_required_tool_that_errors_fails_and_is_never_baselined(self):
        from unittest import mock

        def crash(ctx):
            raise RuntimeError("boom")

        with mock.patch.dict(runner.ADAPTERS, {"security": crash}):
            code, err = self.main("--only", "security", "--require", "security")
            self.assertEqual(code, 1)
            self.assertIn("required tool security did not run: RuntimeError: boom", err)
        with mock.patch.dict(runner.ADAPTERS, {"security": lambda ctx: []}):
            code, err = self.main("--only", "security,semgrep", "--require", "semgrep", "--update-baseline")
        self.assertEqual(code, 2)
        self.assertIn("Cannot update the baseline: required tool(s) did not run: semgrep", err)
        self.assertFalse((self.repo.root / ".repolens" / "report_baseline.json").exists())


class ParseCacheTests(unittest.TestCase):
    """One parsed-module cache per run, shared by the checks, content-keyed and
    bounded by the run's own files."""

    FILES = {"app.py": APP, "routers/live.py": """
        from fastapi import APIRouter
        router = APIRouter()
        @router.post("/items")
        async def create():
            return 1
    """}

    def test_the_checks_of_one_run_parse_each_file_once(self):
        from dataclasses import replace
        from repolens.scan import migrations
        repo = Repo(self.FILES)
        self.addCleanup(repo.close)
        s = repo.settings
        security.scan(s)
        performance.scan(replace(s, admitted_python_files=("app.py", "routers/live.py")))
        migrations.scan(s)
        cache = s.parse_cache
        self.assertEqual((cache.misses, len(cache)), (2, 2))
        self.assertGreaterEqual(cache.hits, 10)
        # Fresh settings are a fresh run: nothing carries over between runs.
        self.assertEqual(len(from_config(load_config(str(repo.root))).parse_cache), 0)

    def test_a_file_edited_during_a_run_is_parsed_again(self):
        from repolens.scan.python_ast import ParseCache
        repo = Repo({"m.py": "A = 1\n"})
        self.addCleanup(repo.close)
        cache, path = ParseCache(), repo.root / "m.py"
        first = cache.parse(path, 1000)
        self.assertIs(cache.parse(path, 1000), first)
        path.write_text("B = 2\n", encoding="utf-8")
        second = cache.parse(path, 1000)
        self.assertEqual(second.body[0].targets[0].id, "B")
        self.assertEqual((cache.hits, cache.misses, len(cache)), (1, 2, 1))

    def test_the_cache_holds_no_more_than_its_run_declares(self):
        from repolens.scan.python_ast import ParseCache
        repo = Repo({f"m{i}.py": f"X = {i}\n" for i in range(4)})
        self.addCleanup(repo.close)
        paths = sorted(repo.root.glob("m*.py"))
        cache = ParseCache(capacity=2)
        for path in paths:
            cache.parse(path, 1000)
        self.assertEqual(len(cache), 2)
        cache.reserve(paths)
        for path in paths:
            cache.parse(path, 1000)
        self.assertEqual((cache.capacity, len(cache)), (4, 4))

    def test_route_exposure_and_the_mount_index_are_built_once_per_run(self):
        from unittest import mock
        from repolens.scan import mounts, wiring
        repo = Repo(self.FILES)
        self.addCleanup(repo.close)
        s = repo.settings
        with mock.patch.object(wiring, "_route_exposure", wraps=wiring._route_exposure) as exposure, \
                mock.patch.object(mounts, "MountIndex", wraps=mounts.MountIndex) as index:
            first = [(f.file, f.rule) for f in security.scan(s)]
            performance.scan(s)
            self.assertEqual((exposure.call_count, index.call_count), (1, 1))
            # An edited file is a new tree, so both are rebuilt from it.
            (repo.root / "routers" / "live.py").write_text(
                "from fastapi import APIRouter\nrouter = APIRouter()\n", encoding="utf-8")
            self.assertEqual(security.scan(s), [])
            self.assertEqual((exposure.call_count, index.call_count), (2, 2))
            # Different settings are different inputs, even sharing the cache.
            from dataclasses import replace
            security.scan(replace(s, entrypoints=("app.py",)))
            self.assertEqual((exposure.call_count, index.call_count), (3, 3))
        self.assertIn(("routers/live.py", "security/unauthenticated-mutation-route"), first)

    def test_the_source_prefilter_never_rules_out_what_it_cannot_see(self):
        from repolens.scan.python_ast import ParseCache, may_mention
        repo = Repo({"a.py": "app.include_router(r)\n", "b.py": "X = 1\n",
                     # NFKC: a fullwidth letter is the ASCII identifier to the parser.
                     "c.py": "app.\uff49nclude_router(r)\n"})
        self.addCleanup(repo.close)
        cache = ParseCache()
        a, b, c = (cache.parse(repo.root / name, 1000) for name in ("a.py", "b.py", "c.py"))
        self.assertEqual(c.body[0].value.func.attr, "include_router")
        self.assertEqual([may_mention(tree, "include_router") for tree in (a, b, c)], [True, False, True])
        self.assertTrue(may_mention(ast.parse("X = 1"), "include_router"))  # source unknown

    def test_the_report_runs_its_python_checks_on_one_parse_cache(self):
        from unittest import mock
        from repolens.scan import migrations
        repo = Repo(self.FILES)
        self.addCleanup(repo.close)
        seen = []

        def spy(real):
            return lambda s: seen.append(s.parse_cache) or real(s)

        with mock.patch.object(security, "scan", spy(security.scan)), \
                mock.patch.object(performance, "scan", spy(performance.scan)), \
                mock.patch.object(migrations, "scan", spy(migrations.scan)), \
                contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            code = runner.main(["--only", "security,performance,migrations", "--out", str(repo.root / "out")],
                               config=load_config(str(repo.root)))
        self.assertEqual(code, 0)
        self.assertEqual(len(seen), 3)
        self.assertTrue(seen[0] is seen[1] is seen[2])
        self.assertEqual(seen[0].misses, 2)

    def test_a_file_too_deep_for_the_parser_is_skipped_and_the_others_parse(self):
        from repolens.scan.python_ast import ParseCache
        repo = Repo({"deep.py": "x = " + "(" * 5000 + "1" + ")" * 5000 + "\n", "ok.py": "Y = 1\n"})
        self.addCleanup(repo.close)
        cache = ParseCache()
        self.assertIsNone(cache.parse(repo.root / "deep.py", 100_000))
        self.assertIsNotNone(cache.parse(repo.root / "ok.py", 100_000))


class CommandRunTests(unittest.TestCase):
    def _run(self, code: str) -> ToolRun:
        repo = Repo({})
        try:
            ctx = runner.Context(load_config(str(repo.root)), merge(runner.DEFAULTS, {}))
            return runner._command_run(ctx, {"name": "x", "run": [sys.executable, "-c", code]}, "cmd:x")
        finally:
            repo.close()

    def test_a_check_that_crashed_is_an_error_not_a_finding(self):
        run = self._run("raise ValueError('boom')")
        self.assertIn("crashed", run.error)
        self.assertEqual(run.findings, [])

    def test_a_check_that_failed_is_a_finding(self):
        run = self._run("import sys; print('FAIL: 3 new'); sys.exit(1)")
        self.assertEqual((run.error, [f.rule for f in run.findings]), ("", ["check/x"]))


SQL = """
    from sqlalchemy import text

    async def by_limit(session, limit):
        await session.execute(text(f"SELECT * FROM t LIMIT {int(limit)}"))

    async def by_concat(session, uid):
        await session.execute(text("SELECT * FROM t WHERE id = '" + uid + "'"))

    async def by_percent(session, uid):
        await session.execute(text("SELECT * FROM t WHERE id = '%s'" % uid))

    async def literal_concat(session):
        await session.execute(text("SELECT * " + "FROM t"))
"""

PERF = """
    async def once(db):
        return [r["id"] for r in await db.t.find({}).to_list(100)]

    async def per_item(db, ids):
        return [await db.t.find_one({"id": i}) for i in ids]

    async def bounded(db):
        return await db.t.find({}, limit=50).to_list(None)

    async def unbounded(db):
        return await db.t.find({}, limit=0).to_list(None)
"""


class DetectorEdgeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.repo = Repo({"svc/sql.py": SQL, "svc/perf.py": PERF})

    def tearDown(self) -> None:
        self.repo.close()

    def test_a_numeric_cast_cannot_carry_sql_and_a_concatenation_chain_can(self):
        flagged = sorted(f.message.split("()")[0] for f in security.scan(self.repo.settings)
                         if f.rule == "security/sql-built-from-string")
        self.assertEqual(flagged, ["by_concat", "by_percent"])

    def test_a_comprehensions_source_runs_once_and_a_limit_keyword_bounds_a_find(self):
        found = sorted((f.rule, f.message.split()[0]) for f in performance.scan(self.repo.settings))
        self.assertEqual([rule for rule, _ in found],
                         ["performance/query-in-loop", "performance/unbounded-to-list"])
        self.assertIn("per_item", found[0][1])
        self.assertIn("unbounded", found[1][1])


class JavaScriptCommentTests(unittest.TestCase):
    def test_comment_markers_inside_strings_do_not_open_a_comment(self):
        from repolens.owners.registry import OwnerRegistry
        from repolens.owners.settings import from_config as owner_settings
        repo = Repo({"web/a.tsx": (
            'const a = "image/*"; // trailing\n'
            "const b = 1;\n"
            "/* block\n"
            "still block */\n"
            "const c = `multi\n"
            "line /* not a comment\n"
            "`;\n"
            "const d = 2;\n")})
        try:
            registry = OwnerRegistry(owner_settings(load_config(str(repo.root))))
            lines = registry._javascript_code_lines(repo.root / "web/a.tsx")
        finally:
            repo.close()
        self.assertEqual([n for n, _ in lines], [1, 2, 5, 6, 7, 8])
        self.assertNotIn("trailing", lines[0][1])


class ReportCommandSurfaceTests(unittest.TestCase):
    PROFILE = textwrap.dedent("""
        [gates]
        scripts = ["checks/*.py"]
        [[report.commands]]
        name = "audit"
        run = ["python3", "checks/audit.py", "--check"]
    """)

    def _unreachable(self, workflow: str) -> list[str]:
        repo = Repo({"repolens.toml": self.PROFILE, "checks/audit.py": "",
                     ".github/workflows/ci.yml": workflow})
        try:
            return reachability.evaluate(reachability.from_config(load_config(str(repo.root)))).unreachable
        finally:
            repo.close()

    def test_report_commands_count_once_a_workflow_runs_the_report(self):
        self.assertEqual(self._unreachable("run: python tools/repolens/bin/repolens report --check\n"), [])

    def test_a_path_that_merely_mentions_the_report_runs_nothing(self):
        self.assertEqual(self._unreachable("path: .repolens/report/\n"), ["audit.py"])


class HookTests(unittest.TestCase):
    def test_an_interpreter_path_with_a_space_stays_one_word(self):
        from repolens.artefacts import hooks
        from repolens.artefacts.settings import from_config as artefact_settings
        repo = Repo({"repolens.toml": '[artefacts]\nhook_command = "{python} regen.py"\n'})
        os.environ["PYTHON"] = "/opt/my python/bin/python3"
        try:
            body = hooks.hook_body(artefact_settings(load_config(str(repo.root))))
        finally:
            del os.environ["PYTHON"]
            repo.close()
        self.assertIn("'/opt/my python/bin/python3'", body)


class RegenerateTests(unittest.TestCase):
    def test_deleting_a_marked_file_refreshes_the_map_of_the_tag_it_carried(self):
        from repolens.artefacts.regenerate import Regenerator
        from repolens.artefacts.settings import from_config as artefact_settings
        repo = Repo({"svc/a.py": "# @featuretrace:alpha\nx = 1\n"})
        git = ["git", "-C", str(repo.root), "-c", "user.email=t@example.invalid", "-c", "user.name=t"]
        try:
            subprocess.run([*git, "init", "-q"], check=True)
            subprocess.run([*git, "add", "-A"], check=True)
            subprocess.run([*git, "commit", "-qm", "one"], check=True)
            (repo.root / "svc/a.py").unlink()
            regen = Regenerator(artefact_settings(load_config(str(repo.root))))
            with_history = regen.affected_paths(["svc/a.py"], since="HEAD")
            without = regen.affected_paths(["svc/a.py"])
        finally:
            repo.close()
        self.assertTrue(any(p.endswith("alpha_flow.md") for p in with_history), with_history)
        self.assertFalse(any(p.endswith("alpha_flow.md") for p in without), without)


class NoEntrypointTests(unittest.TestCase):
    def test_without_an_app_nothing_is_guessed_dead(self):
        repo = Repo({"routers/dead.py": DEAD})
        try:
            self.assertEqual(unreachable_route_files(repo.settings), frozenset())
        finally:
            repo.close()


class ImpactLocationTests(unittest.TestCase):
    """`evidence` is not always `path:line`, so the report must not read it as one."""

    def _graph(self, *issues):
        from repolens.impact.model import Graph, Node
        graph = Graph(root=".")
        graph.add_node(Node("f:a", "function", "a", path="backend/a.py", line=7))
        graph.add_node(Node("f:b", "function", "b", path="backend/b.py", line=30))
        graph.add_node(Node("concept:x", "concept", "x"))
        graph.issues.extend(issues)
        return graph

    def _issue(self, evidence, node_ids):
        from repolens.impact.model import Issue
        return Issue("CODE", "warning", "message", node_ids, evidence, "")

    def test_a_path_and_line_on_the_issues_own_file_is_the_location(self):
        issue = self._issue("backend/a.py:12", ["f:a"])
        self.assertEqual(runner._impact_location(self._graph(issue), issue), ("backend/a.py", 12))

    def test_a_hash_that_starts_with_digits_is_not_a_line_number(self):
        issue = self._issue("python_ast_body:1234abcd5678ef90", ["f:a", "f:b"])
        self.assertEqual(runner._impact_location(self._graph(issue), issue), ("backend/a.py", 7))

    def test_a_colon_without_a_line_number_does_not_crash(self):
        issue = self._issue("backend/a.py:abc", ["concept:x"])
        self.assertEqual(runner._impact_location(self._graph(issue), issue), ("backend/a.py:abc", 0))

    def test_a_bare_path_with_no_located_node_is_reported_as_given(self):
        issue = self._issue("docs/architecture/canonical_owners.json", [])
        self.assertEqual(runner._impact_location(self._graph(issue), issue),
                         ("docs/architecture/canonical_owners.json", 0))

    def test_the_impact_tool_locates_findings_through_it(self):
        from types import SimpleNamespace
        from unittest import mock
        issue = self._issue("python_ast_body:1234abcd5678ef90", ["f:b"])
        with mock.patch("repolens.impact.scanner.scan_repository", return_value=self._graph(issue)), \
                mock.patch("repolens.impact.config.Config.load", return_value=None):
            [finding] = runner._impact(SimpleNamespace(root=Path(".")))
        self.assertEqual((finding.file, finding.line), ("backend/b.py", 30))


class CountsMatterTests(unittest.TestCase):
    """A ratchet's count is compared, not fingerprinted: falling is progress, not news."""

    def _new(self, known_message: str, current_message: str) -> bool:
        known = Finding("cmd:x", "check/x", "medium", known_message, counts_matter=True)
        now = Finding("cmd:x", "check/x", "medium", current_message, counts_matter=True)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "b.json"
            write_baseline(path, [known])
            mark_new([now], load_baseline(path), load_magnitudes(path))
        return now.new

    def test_a_count_that_fell_is_not_new(self):
        self.assertFalse(self._new("FAIL: 4 new reads", "FAIL: 2 new reads"))

    def test_a_count_that_rose_is_new(self):
        self.assertTrue(self._new("FAIL: 2 new reads", "FAIL: 4 new reads"))

    def test_an_unchanged_count_is_not_new(self):
        self.assertFalse(self._new("FAIL: 3 new reads", "FAIL: 3 new reads"))

    # A command's tail carries more numbers than its count. Each of these moved between
    # two runs of an unchanged check and reported it as a new finding.
    def test_a_timing_is_not_a_count(self):
        self.assertFalse(self._new("FAIL: 3 new reads in 0.41s", "FAIL: 3 new reads in 0.52s"))

    def test_a_duration_is_not_a_count(self):
        self.assertFalse(self._new("FAIL: 3 new reads (took 12 s)", "FAIL: 3 new reads (took 40 s)"))

    def test_a_denominator_is_not_a_count(self):
        self.assertFalse(self._new("FAIL: 3 of 148 files", "FAIL: 3 of 150 files"))
        self.assertFalse(self._new("FAIL: 3/148 files", "FAIL: 3/150 files"))

    def test_a_count_that_rose_beside_a_timing_is_new(self):
        self.assertTrue(self._new("FAIL: 3 new reads in 0.41s", "FAIL: 4 new reads in 0.30s"))

    def test_magnitudes_from_an_older_baseline_format_are_not_compared(self):
        # Format 2 counted "0.41" as two numbers. Compared with today's list it is a
        # different shape, which reads as new; ignored instead until the next rebuild.
        now = Finding("cmd:x", "check/x", "medium", "FAIL: 3 new reads", counts_matter=True)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "b.json"
            path.write_text(json.dumps({"format": 2, "fingerprints": {now.fingerprint: 1},
                                        "magnitudes": {now.fingerprint: [[3, 0, 41]]}}))
            self.assertEqual(load_magnitudes(path), {})
            mark_new([now], load_baseline(path), load_magnitudes(path))
        self.assertFalse(now.new)


MOUNT_SERVER = """
    from fastapi import APIRouter, Depends, FastAPI
    from auth import get_current_user
    from routers import open_api

    app = FastAPI()
    api_router = APIRouter(prefix="/api")
    try:
        from routers.secure import router as secure_router
        api_router.include_router(secure_router, prefix="/things",
                                  dependencies=[Depends(get_current_user)])
    except ImportError:
        pass
    api_router.include_router(open_api.router, prefix="/open")
    app.include_router(api_router)
"""

MOUNT_SECURE = """
    from fastapi import APIRouter
    router = APIRouter()

    @router.post("/{thing_id}/archive")
    async def archive(thing_id: str):
        await db.things.update_one({"id": thing_id}, {"$set": {"archived": True}})
"""

MOUNT_OPEN = """
    from fastapi import APIRouter
    router = APIRouter(prefix="/items")

    @router.post("/{item_id}")
    async def create(item_id: str):
        return {}
"""


class MountTests(unittest.TestCase):
    """Auth and prefixes set where a router is MOUNTED apply to every route on it."""

    def setUp(self) -> None:
        self.repo = Repo({"server.py": MOUNT_SERVER, "routers/__init__.py": "",
                          "routers/secure.py": MOUNT_SECURE, "routers/open_api.py": MOUNT_OPEN})
        self.found = security.scan(self.repo.settings)

    def tearDown(self) -> None:
        self.repo.close()

    def _rules(self, file: str) -> dict[str, str]:
        return {f.rule: f.message for f in self.found if f.file == file}

    def test_auth_applied_at_include_router_authenticates_the_route(self):
        rules = self._rules("routers/secure.py")
        self.assertNotIn("security/unauthenticated-mutation-route", rules)
        self.assertIn("POST /api/things/{thing_id}/archive",
                      rules["security/object-route-without-ownership-check"])

    def test_an_unauthenticated_mount_keeps_every_prefix(self):
        self.assertIn("POST /api/open/items/{item_id}",
                      self._rules("routers/open_api.py")["security/unauthenticated-mutation-route"])

    def test_a_public_route_listed_without_its_prefix_is_still_public(self):
        # Anchored, so only the path as DECLARED matches: an unanchored "/{item_id}" also
        # matches the mounted "/api/open/items/{item_id}" and proves nothing.
        profile = ('[scan]\npython_roots = ["."]\n'
                   '[scan.security.public_routes]\n"^/\\\\{item_id\\\\}$" = "signed webhook"\n')
        repo = Repo({"repolens.toml": profile, "server.py": MOUNT_SERVER, "routers/__init__.py": "",
                     "routers/secure.py": MOUNT_SECURE, "routers/open_api.py": MOUNT_OPEN})
        try:
            rules = {f.rule for f in security.scan(repo.settings) if f.file == "routers/open_api.py"}
        finally:
            repo.close()
        self.assertNotIn("security/unauthenticated-mutation-route", rules)


def _mount_rules(server: str) -> dict[str, dict[str, str]]:
    """file -> {rule: message} for the two routers mounted by `server`."""
    repo = Repo({"server.py": server, "routers/__init__.py": "",
                 "routers/secure.py": MOUNT_SECURE, "routers/open_api.py": MOUNT_OPEN})
    try:
        out: dict[str, dict[str, str]] = defaultdict(dict)
        for f in security.scan(repo.settings):
            out[f.file][f.rule] = f.message
        return out
    finally:
        repo.close()


class MountResolutionTests(unittest.TestCase):
    """Mounts the scanner used to miss, or attribute to the wrong router."""

    def test_a_router_mounted_in_a_loop_counts_as_mounted(self):
        # open_api is mounted twice: once with auth, once by the loop without. The route
        # is reachable unauthenticated, so it must be reported. Skipping the loop's mount
        # left only the authenticated one, and the route read as protected.
        rules = _mount_rules("""
            from fastapi import APIRouter, Depends, FastAPI
            from auth import get_current_user
            from routers import open_api, secure

            app = FastAPI()
            app.include_router(open_api.router, dependencies=[Depends(get_current_user)])
            for module in (open_api, secure):
                app.include_router(module.router)
        """)
        self.assertIn("security/unauthenticated-mutation-route", rules["routers/open_api.py"])
        self.assertIn("security/unauthenticated-mutation-route", rules["routers/secure.py"])

    def test_a_loop_over_a_module_level_list_is_expanded(self):
        rules = _mount_rules("""
            from fastapi import Depends, FastAPI
            from auth import get_current_user
            from routers.open_api import router as open_router
            from routers.secure import router as secure_router

            ROUTERS = [open_router, secure_router]
            app = FastAPI()
            for r in ROUTERS:
                app.include_router(r, prefix="/v1", dependencies=[Depends(get_current_user)])
        """)
        self.assertNotIn("security/unauthenticated-mutation-route", rules["routers/open_api.py"])
        self.assertIn("POST /v1/{thing_id}/archive",
                      rules["routers/secure.py"]["security/object-route-without-ownership-check"])

    def test_a_reused_alias_resolves_to_the_import_in_effect(self):
        # `r` names secure's router for the first include and open_api's for the second.
        # Resolving every use to the file's LAST import mounted open_api twice and secure
        # nowhere, so secure's authenticated route read as unauthenticated.
        rules = _mount_rules("""
            from fastapi import Depends, FastAPI
            from auth import get_current_user

            app = FastAPI()
            from routers.secure import router as r
            app.include_router(r, prefix="/a", dependencies=[Depends(get_current_user)])
            from routers.open_api import router as r
            app.include_router(r, prefix="/b")
        """)
        self.assertNotIn("security/unauthenticated-mutation-route", rules["routers/secure.py"])
        self.assertIn("POST /a/{thing_id}/archive",
                      rules["routers/secure.py"]["security/object-route-without-ownership-check"])
        self.assertIn("POST /b/items/{item_id}",
                      rules["routers/open_api.py"]["security/unauthenticated-mutation-route"])


SQL_FLOW = """
    ALLOWED = {"name", "created_at"}
    COLUMNS = {"name": "name", "date": "created_at"}

    def via_variable(cur, name):
        query = f"SELECT * FROM t WHERE name = '{name}'"
        cur.execute(query)

    def allow_listed(cur, column):
        if column not in ALLOWED:
            raise ValueError(column)
        cur.execute(f"SELECT * FROM t ORDER BY {column}")

    def reset_to_default(cur, column):
        if not column or column not in ("name", "created_at"):
            column = "name"
        cur.execute(f"SELECT * FROM t ORDER BY {column}")

    def mapped(cur, key):
        cur.execute(f"SELECT * FROM t ORDER BY {COLUMNS[key]}")

    def defaulted(cur, key):
        cur.execute(f"SELECT * FROM t ORDER BY {COLUMNS.get(key, 'name')}")

    def rebound(cur, column):
        if column not in ALLOWED:
            raise ValueError(column)
        column = column + " DESC"
        cur.execute(f"SELECT * FROM t ORDER BY {column}")
"""


class SqlFlowTests(unittest.TestCase):
    def setUp(self) -> None:
        self.repo = Repo({"svc/flow.py": SQL_FLOW})
        self.found = [f for f in security.scan(self.repo.settings)
                      if f.rule == "security/sql-built-from-string"]

    def tearDown(self) -> None:
        self.repo.close()

    def test_only_unchecked_text_is_flagged(self):
        self.assertEqual(sorted(f.message.split("()")[0] for f in self.found),
                         ["rebound", "via_variable"])

    def test_sql_built_in_a_variable_names_where_it_was_built(self):
        [finding] = [f for f in self.found if f.message.startswith("via_variable")]
        self.assertIn("(via `query`, built at line", finding.message)


SQL_FLOW_PATHS = """
    ALLOWED = {"name", "created_at"}
    BASE = "SELECT * FROM t ORDER BY "
    TEMPLATE = "SELECT * FROM t WHERE name = '{}'"

    def request_get_item(cur, request):
        cur.execute(f"SELECT * FROM t ORDER BY {request.GET['sort']}")

    def request_get_call(cur, request):
        cur.execute(f"SELECT * FROM t ORDER BY {request.GET.get('sort')}")

    def settings_constant(cur):
        cur.execute(f"SELECT * FROM {settings.TABLE_NAME}")

    def checked_in_one_branch(cur, column, strict):
        if strict:
            if column not in ALLOWED:
                raise ValueError(column)
        else:
            cur.execute(f"SELECT * FROM t ORDER BY {column}")

    def checked_where_the_failure_is_swallowed(cur, column):
        try:
            if column not in ALLOWED:
                raise ValueError(column)
        except ValueError:
            pass
        cur.execute(f"SELECT * FROM t ORDER BY {column}")

    def checked_before_a_loop(cur, column, rows):
        if column not in ALLOWED:
            raise ValueError(column)
        for row in rows:
            cur.execute(f"SELECT * FROM t ORDER BY {column}")

    def skipped_inside_a_loop(cur, columns):
        for column in columns:
            if column not in ALLOWED:
                continue
            cur.execute(f"SELECT * FROM t ORDER BY {column}")

    def appended(cur, column):
        query = "SELECT * FROM t ORDER BY "
        query += column
        cur.execute(query)

    def concatenated_constant(cur, column):
        query = BASE + column
        cur.execute(query)

    def replaced_by_safe_text(cur, name):
        query = f"SELECT * FROM t WHERE name = '{name}'"
        query = "SELECT * FROM t"
        cur.execute(query)

    def replaced_in_one_branch_only(cur, name, everything):
        query = f"SELECT * FROM t WHERE name = '{name}'"
        if everything:
            query = "SELECT * FROM t"
        cur.execute(query)

    def keyword_query(cur, name):
        cur.execute(query=f"SELECT * FROM t WHERE name = '{name}'")

    async def prepared(conn, name):
        await conn.prepare(f"SELECT * FROM t WHERE name = '{name}'")

    def template_in_a_constant(cur, name):
        cur.execute(TEMPLATE.format(name))

    def joined(cur, name):
        cur.execute(" ".join(["SELECT * FROM t WHERE name =", name]))

    def composed_safely(cur, column):
        cur.execute(sql.SQL("SELECT * FROM t ORDER BY {}").format(sql.Identifier(column)))
"""


class SqlFlowPathTests(unittest.TestCase):
    """A check guards a query only if it runs on every path to it, and a query's text is
    whatever reaches the call, not whatever was written first."""

    def test_the_flagged_set(self):
        repo = Repo({"svc/paths.py": SQL_FLOW_PATHS})
        try:
            found = {f.message.split("()")[0] for f in security.scan(repo.settings)
                     if f.rule == "security/sql-built-from-string"}
        finally:
            repo.close()
        self.assertEqual(found, {
            "request_get_item", "request_get_call",
            "checked_in_one_branch", "checked_where_the_failure_is_swallowed",
            "appended", "concatenated_constant", "replaced_in_one_branch_only",
            "keyword_query", "prepared", "template_in_a_constant", "joined",
        })


class LensStalenessTests(unittest.TestCase):
    def setUp(self) -> None:
        from repolens.lens.settings import from_config as lens_settings
        self.repo = Repo({"repolens.toml": '[lens]\npython_roots = ["."]\n',
                          "a.py": "def alpha():\n    pass\n"})
        self.settings = lens_settings(load_config(str(self.repo.root)))

    def tearDown(self) -> None:
        self.repo.close()

    def _load(self) -> tuple[set[str], str]:
        from repolens.lens.build import load_index
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            data = load_index(self.settings)
        return {r["name"] for r in data["functions"].values()}, err.getvalue()

    def test_a_lookup_after_an_edit_answers_from_the_edited_tree(self):
        first, _ = self._load()
        (self.repo.root / "b.py").write_text("def beta():\n    pass\n", encoding="utf-8")
        second, said = self._load()
        self.assertEqual((first, second), ({"alpha"}, {"alpha", "beta"}))
        self.assertIn("older than the tree", said)

    def test_an_unchanged_tree_is_served_from_the_cache(self):
        self._load()
        _, said = self._load()
        self.assertEqual(said, "")


class ResilienceTests(unittest.TestCase):
    def test_a_file_deleted_mid_run_is_skipped_and_named(self):
        from repolens.core.files import read_text_or_none
        err = io.StringIO()
        with tempfile.TemporaryDirectory() as tmp, contextlib.redirect_stderr(err):
            self.assertIsNone(read_text_or_none(Path(tmp) / "gone.py"))
        self.assertIn("gone.py", err.getvalue())

    def test_owners_without_pyyaml_says_how_to_install_it(self):
        from unittest import mock

        from repolens.owners.registry import OwnerRegistry
        from repolens.owners.settings import from_config as owner_settings
        repo = Repo({"repolens.toml": '[owners]\nregistry = "owners.yaml"\n',
                     "owners.yaml": "concepts: []\n"})
        try:
            registry = OwnerRegistry(owner_settings(load_config(str(repo.root))))
            with mock.patch.dict(sys.modules, {"yaml": None}), \
                    self.assertRaises(SystemExit) as caught:
                registry.load_registry()
        finally:
            repo.close()
        self.assertIn("pip install PyYAML", str(caught.exception.code))

    def test_git_matching_survives_a_non_ascii_path(self):
        from repolens.core.git import ignored
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            subprocess.run(["git", "init", "-q", str(root)], check=True)
            (root / ".gitignore").write_text("build/\n", encoding="utf-8")
            got = ignored(root, ["build/café.py", "src/naïve.py"])
        self.assertEqual(got, {"build/café.py"})


class PosixPathTests(unittest.TestCase):
    def test_no_relative_path_is_rendered_with_the_os_separator(self):
        """A path printed into a committed artefact must read the same on Windows:
        `str(p.relative_to(root))` gives backslashes there, `.as_posix()` never does."""
        package = Path(__file__).resolve().parents[1] / "repolens"
        pattern = re.compile(r"str\([^)\n]*\.relative_to\(")
        offenders = [f"{path.relative_to(package).as_posix()}:{number}"
                     for path in sorted(package.rglob("*.py"))
                     for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1)
                     if pattern.search(line) and "as_posix" not in line]
        self.assertEqual(offenders, [])



def _scan(files: dict[str, str], tool=security) -> list[Finding]:
    repo = Repo(files)
    try:
        return tool.scan(repo.settings)
    finally:
        repo.close()


def _rules_by_route(findings: list[Finding]) -> dict[str, set[str]]:
    """"POST /path" -> the rules reported on it."""
    out: dict[str, set[str]] = defaultdict(set)
    for f in findings:
        out[" ".join(f.message.split()[:2])].add(f.rule)
    return out


ALIAS_DEPS = """
    from typing import Annotated
    from fastapi import Depends
    from fastapi.security import HTTPBearer, OAuth2PasswordBearer
    oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")
    optional_bearer = HTTPBearer(auto_error=False)
    def get_current_user(token: str = Depends(oauth2_scheme)):
        return token
    def get_db():
        yield 1
    CurrentUser = Annotated[dict, Depends(get_current_user)]
    SessionDep = Annotated[object, Depends(get_db)]
    TokenDep = Annotated[str, Depends(oauth2_scheme)]
    type UserAlias = Annotated[dict, Depends(get_current_user)]
"""

ALIAS_ROUTES = """
    from typing import Annotated
    from fastapi import APIRouter, Depends
    from app import deps
    from app.deps import CurrentUser, SessionDep, TokenDep, UserAlias, oauth2_scheme, optional_bearer
    router = APIRouter()

    @router.post("/alias")
    def alias_route(user: CurrentUser, session: SessionDep, data: dict):
        return user

    @router.post("/module-alias")
    def module_alias(user: deps.CurrentUser, data: dict):
        return user

    @router.post("/type-alias")
    def type_alias(user: UserAlias, data: dict):
        return user

    @router.post("/scheme")
    def scheme_route(token: Annotated[str, Depends(oauth2_scheme)], data: dict):
        return token

    @router.post("/scheme-alias")
    def scheme_alias(token: TokenDep, data: dict):
        return token

    @router.post("/session-only")
    def session_only(session: SessionDep, data: dict):
        return data

    @router.post("/optional-scheme")
    def optional_scheme(creds=Depends(optional_bearer)):
        return creds
"""

ALIAS_APP = """
    from fastapi import FastAPI
    from app import routes
    app = FastAPI()
    app.include_router(routes.router)
"""


class DependencyAliasTests(unittest.TestCase):
    """`CurrentUser = Annotated[User, Depends(...)]` and security scheme instances, defined
    in one module and used in another: the shape FastAPI's docs and template teach."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.rules = _rules_by_route(_scan({"app/__init__.py": "", "app/main.py": ALIAS_APP,
                                           "app/deps.py": ALIAS_DEPS, "app/routes.py": ALIAS_ROUTES}))

    def test_an_imported_annotated_alias_authenticates_the_route(self):
        for route in ("POST /alias", "POST /module-alias", "POST /type-alias"):
            self.assertNotIn("security/unauthenticated-mutation-route", self.rules[route], route)

    def test_an_alias_that_does_not_authenticate_is_still_no_authentication(self):
        self.assertIn("security/unauthenticated-mutation-route", self.rules["POST /session-only"])

    def test_a_security_scheme_dependency_authenticates(self):
        self.assertNotIn("security/unauthenticated-mutation-route", self.rules["POST /scheme"])
        self.assertNotIn("security/unauthenticated-mutation-route", self.rules["POST /scheme-alias"])

    def test_a_scheme_that_does_not_raise_authenticates_nothing(self):
        self.assertIn("security/unauthenticated-mutation-route", self.rules["POST /optional-scheme"])

    def test_an_alias_reexported_by_a_package_resolves(self):
        rules = _rules_by_route(_scan({
            "app/__init__.py": "", "app/main.py": ALIAS_APP,
            "app/api/__init__.py": "from .deps import CurrentUser\n", "app/api/deps.py": ALIAS_DEPS,
            "app/routes.py": """
                from fastapi import APIRouter
                from app.api import CurrentUser
                router = APIRouter()
                @router.post("/reexported")
                def reexported(user: CurrentUser, data: dict):
                    return user
            """}))
        self.assertNotIn("security/unauthenticated-mutation-route", rules["POST /reexported"])


class RouteRegistrationTests(unittest.TestCase):
    """Routes registered without a plain `@router.<verb>("/path")` decorator."""

    def setUp(self) -> None:
        self.rules = _rules_by_route(_scan({"main.py": """
            from fastapi import APIRouter, Depends, FastAPI
            app = FastAPI()
            router = APIRouter()
            METHODS = ["POST"]

            @router.api_route("/multi", methods=["GET", "post"])
            def multi(data: dict):
                return data

            @router.api_route("/read-only")
            def read_only():
                return 1

            @router.api_route("/computed", methods=METHODS)
            def computed(data: dict):
                return data

            def plain(data: dict):
                return data

            def guarded(data: dict):
                return data

            router.add_api_route("/added", plain, methods=["DELETE"])
            router.add_api_route("/added-guarded", endpoint=guarded, methods=["PUT"],
                                 dependencies=[Depends(get_current_user)])

            @router.post(path="/kwpath")
            def kwpath(data: dict):
                return data

            @app.websocket("/ws/{room_id}")
            async def ws(websocket, room_id: str):
                return None

            app.include_router(router)
        """}))

    def test_api_route_is_expanded_over_its_literal_methods(self):
        self.assertIn("security/unauthenticated-mutation-route", self.rules["POST /multi"])
        self.assertNotIn("POST /read-only", self.rules)

    def test_a_method_list_that_is_not_literal_is_skipped_not_guessed(self):
        self.assertNotIn("POST /computed", self.rules)
        self.assertNotIn("GET /computed", self.rules)

    def test_add_api_route_registers_its_endpoint_with_its_dependencies(self):
        self.assertIn("security/unauthenticated-mutation-route", self.rules["DELETE /added"])
        self.assertNotIn("PUT /added-guarded", self.rules)

    def test_a_path_keyword_and_a_websocket_are_routes(self):
        self.assertIn("security/unauthenticated-mutation-route", self.rules["POST /kwpath"])
        self.assertEqual(self.rules["WEBSOCKET /ws/{room_id}"], {"security/unauthenticated-object-read"})


def _template(prefix: str) -> dict[str, str]:
    """The full-stack-fastapi-template shape under `prefix`: `from app.api.main import
    api_router`, with auth applied where the router is mounted."""
    return {
        f"{prefix}app/__init__.py": "", f"{prefix}app/api/__init__.py": "",
        f"{prefix}app/api/routes/__init__.py": "",
        f"{prefix}app/main.py": """
            from fastapi import Depends, FastAPI
            from app.api.main import api_router
            app = FastAPI()
            app.include_router(api_router, prefix="/api/v1", dependencies=[Depends(get_current_user)])
        """,
        f"{prefix}app/api/main.py": """
            from fastapi import APIRouter
            from .routes import items
            api_router = APIRouter()
            api_router.include_router(items.router)
        """,
        f"{prefix}app/api/routes/items.py": """
            from fastapi import APIRouter
            router = APIRouter(prefix="/items")
            @router.delete("/{item_id}")
            def delete_item(item_id: int):
                return remove(item_id)
        """,
    }


class LayoutTests(unittest.TestCase):
    """`backend/` and `src/` layouts, where the package root is not the repository root."""

    def test_a_backend_or_src_layout_resolves_imports_mounts_and_router_auth(self):
        for prefix in ("backend/", "src/", "services/api/"):
            with self.subTest(prefix=prefix):
                repo = Repo(_template(prefix))
                try:
                    self.assertEqual(unreachable_route_files(repo.settings), frozenset())
                    found = {f.rule: f for f in security.scan(repo.settings)}
                finally:
                    repo.close()
                self.assertNotIn("security/unauthenticated-mutation-route", found)
                finding = found["security/object-route-without-ownership-check"]
                self.assertIn("DELETE /api/v1/items/{item_id}", finding.message)
                self.assertEqual(finding.exposure, "authenticated")

    def test_a_name_two_layouts_claim_reaches_both_and_mounts_neither(self):
        # `app.api.routes.items` is both backend/app/... and src/app/...: which one runs
        # depends on sys.path. Reachability keeps both live; neither inherits the auth.
        repo = Repo({**_template("backend/"), **_template("src/")})
        try:
            self.assertEqual(unreachable_route_files(repo.settings), frozenset())
            rules = {(f.file.split("/")[0], f.rule) for f in security.scan(repo.settings)}
        finally:
            repo.close()
        self.assertIn(("backend", "security/unauthenticated-mutation-route"), rules)
        self.assertIn(("src", "security/unauthenticated-mutation-route"), rules)


FACTORY = {
    "app/__init__.py": "", "app/core/__init__.py": "", "app/routes/__init__.py": "",
    "app/core/factory.py": "from fastapi import FastAPI\ndef get_application():\n    return FastAPI(title='x')\n",
    "app/routes/items.py": "from fastapi import APIRouter\nrouter = APIRouter()\n"
                           "@router.post('/x')\ndef x(d: dict):\n    return d\n",
    "app/routes/orphan.py": "from fastapi import APIRouter\nrouter = APIRouter()\n"
                            "@router.post('/y')\ndef y(d: dict):\n    return d\n",
    "app/routes/aggregate.py": "from fastapi import APIRouter\nfrom app.routes import orphan\n"
                               "api_router = APIRouter()\napi_router.include_router(orphan.router)\n",
}


class FactoryAppTests(unittest.TestCase):
    def _dead(self, main: str) -> frozenset[str]:
        repo = Repo({**FACTORY, "app/main.py": main})
        try:
            return unreachable_route_files(repo.settings)
        finally:
            repo.close()

    def test_routers_registered_on_an_app_a_factory_built_are_live(self):
        self.assertEqual(self._dead("from app.core.factory import get_application\n"
                                    "from app.routes import items\n"
                                    "app = get_application()\napp.include_router(items.router)\n"),
                         frozenset({"app/routes/orphan.py"}))

    def test_a_factory_function_that_registers_and_returns_the_app_is_a_root(self):
        self.assertEqual(self._dead("from app.core.factory import get_application\n"
                                    "def create():\n    from app.routes import items\n"
                                    "    application = get_application()\n"
                                    "    application.include_router(items.router)\n"
                                    "    return application\n"),
                         frozenset({"app/routes/orphan.py"}))

    def test_a_router_aggregator_nothing_imports_is_not_a_root(self):
        # aggregate.py registers orphan on a ROUTER; no app mounts it, so orphan is dead.
        self.assertIn("app/routes/orphan.py", self._dead("from app.core.factory import get_application\n"
                                                         "app = get_application()\n"
                                                         "import requests\ns = requests.Session()\n"
                                                         "s.mount('https://', None)\n"))


DEEP_SUM = " + ".join(["x"] * 3000)


class RecursionIsolationTests(unittest.TestCase):
    """One pathological file must not cost the findings in every other file."""

    APP = "from fastapi import FastAPI\napp = FastAPI()\n@app.post('/x')\ndef x(d: dict):\n    return d\n"

    def test_a_very_long_concatenation_is_read_without_overflowing(self):
        found = _scan({"gen.py": f"def q(conn, x):\n    return conn.execute('SELECT 1 ' + {DEEP_SUM})\n",
                       "app.py": self.APP})
        self.assertEqual({(f.file, f.rule) for f in found},
                         {("app.py", "security/unauthenticated-mutation-route"),
                          ("gen.py", "security/sql-built-from-string")})

    def test_a_file_that_overflows_is_reported_and_the_others_are_still_scanned(self):
        from unittest import mock
        real_security, real_performance = security._model_findings, performance._file_findings

        def overflow(real):
            def run(s, rel, *args, **kwargs):
                if rel == "gen.py":
                    raise RecursionError
                return real(s, rel, *args, **kwargs)
            return run

        files = {"gen.py": "def q():\n    return 1\n", "app.py": self.APP + "import time\n"
                 "async def slow():\n    time.sleep(1)\n"}
        with mock.patch.object(security, "_model_findings", overflow(real_security)):
            found = {(f.file, f.rule, f.severity, f.confidence) for f in _scan(files)}
        self.assertEqual(found, {("app.py", "security/unauthenticated-mutation-route", "high", "medium"),
                                 ("gen.py", "security/could-not-scan", "medium", "high")})
        with mock.patch.object(performance, "_file_findings", overflow(real_performance)):
            found = {(f.file, f.rule) for f in _scan(files, performance)}
        self.assertEqual(found, {("app.py", "performance/blocking-call-in-async"),
                                 ("gen.py", "performance/could-not-scan")})

    def test_a_migration_too_deep_to_render_is_reported_and_the_others_are_read(self):
        from repolens.scan import migrations
        deep = ("revision = 'a1'\nfrom alembic import op\ndef upgrade():\n"
                f"    op.execute('CREATE TABLE t (' + {DEEP_SUM} + ')')\n")
        ok = ("revision = 'b2'\nfrom alembic import op\ndef upgrade():\n"
              "    op.execute('ALTER TABLE t ADD COLUMN c int NOT NULL')\n")
        found = {(f.file.rsplit("/", 1)[-1], f.rule)
                 for f in _scan({"alembic/versions/a1.py": deep, "alembic/versions/b2.py": ok}, migrations)}
        self.assertIn(("a1.py", "migrations/could-not-scan"), found)
        self.assertTrue(any(file == "b2.py" and rule != "migrations/could-not-scan" for file, rule in found),
                        found)


ORM_PERF = """
    import requests as rq
    import httpx
    from time import sleep
    from sqlmodel import select

    async def aliased_blocking():
        rq.get("http://x")
        sleep(1)
        httpx.get("http://x")

    async def async_client_is_fine():
        async with httpx.AsyncClient() as client:
            await client.get("http://x")
        await httpx.AsyncClient().get("http://x")

    def sync_requests_is_fine():
        rq.get("http://x")
        sleep(1)

    async def held_result(session):
        stmt = select(Item)
        result = await session.execute(stmt)
        return result.scalars().all()

    async def held_bounded_result(session):
        result = await session.execute(select(Item).limit(10))
        return result.scalars().all()

    def sqlmodel_exec(session):
        return session.exec(select(Item)).all()

    def sqlmodel_exec_paged(session, skip, limit):
        return session.exec(select(Item).offset(skip).limit(limit)).all()

    def legacy_query(db):
        return db.query(Item).filter(Item.owner == 1).all()

    def legacy_query_paged(db, skip, limit):
        return db.query(Item).offset(skip).limit(limit).all()

    def sync_loop(db, ids):
        out = []
        for i in ids:
            out.append(db.query(Item).filter(Item.id == i).first())
        return out

    async def session_get_per_item(session, ids):
        return [await session.get(Item, i) for i in ids]

    def not_round_trips(cache, lines, ids, request):
        for i in ids:
            cache.get(i, None)
            request.session.get("user", None)
        return [line.find(":") for line in lines]

    async def awaited_non_db_get(client, urls):
        return [await client.get(u) for u in urls]
"""


class OrmPerformanceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        tree = ast.parse(textwrap.dedent(ORM_PERF))
        spans = [(fn.lineno, fn.end_lineno, fn.name) for fn in tree.body
                 if isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef))]
        cls.found: dict[str, list[str]] = defaultdict(list)
        for f in _scan({"svc/items.py": ORM_PERF}, performance):
            name = next(n for start, end, n in spans if start <= f.line <= end)
            cls.found[f.rule.split("/")[1]].append(name)

    def test_import_aliases_and_httpx_are_blocking_in_async_code_only(self):
        self.assertEqual(sorted(self.found["blocking-call-in-async"]), ["aliased_blocking"] * 3)

    def test_sqlmodel_exec_legacy_query_and_a_held_result_are_unbounded_fetches(self):
        self.assertEqual(sorted(self.found["unbounded-sql-fetch"]),
                         ["held_result", "legacy_query", "sqlmodel_exec"])

    def test_a_query_per_item_in_a_sync_loop_or_a_session_get_is_n_plus_one(self):
        self.assertEqual(sorted(self.found["query-in-loop"]), ["session_get_per_item", "sync_loop"])


SERVER_APP = """
    from fastapi import FastAPI
    import uvicorn
    app = FastAPI()

    @app.post("/upload")
    async def upload(d: dict):
        return d

    if __name__ == "__main__":
        uvicorn.run(app, host="0.0.0.0", port=8000)
"""

SERVICE_UNIT = """
    [Service]
    WorkingDirectory=/srv/example/svc
    ExecStart=/srv/example/svc/venv/bin/python -m uvicorn server:app --host 0.0.0.0 --port 8000
"""

TWO_SERVERS = {"svc/__init__.py": "", "svc/server.py": SERVER_APP, "svc/server_copy.py": SERVER_APP}
#: A deployed app, an admin app a second process runs, and a copy nothing runs.
THREE_APPS = {"app/__init__.py": "", "app/main.py": SERVER_APP, "admin/__init__.py": "",
              "admin/main.py": SERVER_APP, "legacy/__init__.py": "", "legacy/server.py": SERVER_APP}


class DeploymentTests(unittest.TestCase):
    """A route file only an app no deployment manifest runs reaches is "undeployed"."""

    def _exposures(self, files: dict[str, str]) -> dict[str, tuple[str, str, str]]:
        out = {}
        for f in _scan(files):
            if f.rule == "security/unauthenticated-mutation-route":
                out[f.file] = (f.exposure, f.priority, f.message)
        return out

    def _targets(self, files: dict[str, str]):
        from repolens.scan import deploy
        from repolens.scan.wiring import ModuleMap
        repo = Repo(files)
        try:
            rels = [p for p in files if p.endswith(".py")]
            return deploy.discover(repo.settings, rels, ModuleMap(rels, repo.settings.python_roots))
        finally:
            repo.close()

    def assertDemoted(self, found, demoted: set[str]) -> None:
        self.assertGreaterEqual(len(found), 2, found)
        self.assertLessEqual(demoted, set(found))
        for rel, (exposure, priority, _) in found.items():
            if rel in demoted:
                self.assertEqual((exposure, priority), ("undeployed", "P3"), rel)
            else:
                self.assertEqual((exposure, priority), ("unauthenticated", "P1"), rel)

    def test_a_systemd_unit_running_one_of_two_apps_demotes_only_the_other(self):
        found = self._exposures({**TWO_SERVERS, "api.service": SERVICE_UNIT,
                                 "scripts/notes.sh": 'echo "   python server_copy.py"\n'})
        self.assertEqual(set(found), {"svc/server.py", "svc/server_copy.py"})
        self.assertDemoted(found, {"svc/server_copy.py"})
        self.assertIn("[not run by any deployment manifest found: api.service runs "
                      "svc/server.py]", found["svc/server_copy.py"][2])

    def test_without_a_manifest_nothing_changes(self):
        self.assertDemoted(self._exposures(TWO_SERVERS), set())

    def test_an_application_chosen_at_run_time_makes_the_deployment_unknown(self):
        dynamic = "[Service]\nExecStart=/usr/bin/uvicorn $APP_MODULE --port 9000\n"
        self.assertDemoted(self._exposures({**TWO_SERVERS, "api.service": SERVICE_UNIT,
                                            "other.service": dynamic}), set())

    def test_the_setting_turns_detection_off(self):
        files = {**TWO_SERVERS, "api.service": SERVICE_UNIT,
                 "repolens.toml": '[scan]\npython_roots = ["."]\ndeployment_detection = false\n'}
        self.assertDemoted(self._exposures(files), set())

    def test_a_dockerfile_cmd_with_a_workdir(self):
        files = {"app/__init__.py": "", "app/main.py": SERVER_APP, "legacy/server.py": SERVER_APP,
                 "Dockerfile": 'FROM python:3.12\nWORKDIR /app\nCOPY . .\n'
                               'CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0"]\n'}
        self.assertDemoted(self._exposures(files), {"legacy/server.py"})

    def test_a_package_json_script_adds_to_what_runs_but_is_not_the_deployment(self):
        files = {**TWO_SERVERS, "package.json": json.dumps({"scripts": {
            "dev": "next dev", "api": "cd svc && uvicorn server_copy:app"}})}
        self.assertEqual([(t.files, t.auxiliary) for t in self._targets(files).targets],
                         [(("svc/server_copy.py",), True)])
        self.assertDemoted(self._exposures(files), set())
        self.assertDemoted(self._exposures({**files, "api.service": SERVICE_UNIT}), set())

    def test_a_ci_test_or_dev_script_never_makes_the_deployment_known(self):
        fake = {"tests/__init__.py": "", "tests/fake.py": SERVER_APP}
        for rel, text in ((".github/scripts/e2e.sh", "uvicorn tests.fake:app &\npytest\n"),
                          ("scripts/dev.sh", "exec uvicorn tests.fake:app\n"),
                          ("svc/run_tests.sh", "uvicorn tests.fake:app\n"),
                          ("docker-compose.test.yml", "services:\n  api:\n    command: uvicorn tests.fake:app\n"),
                          ("Procfile", "web: uvicorn tests.fake:app --reload\n")):
            with self.subTest(rel):
                files = {**TWO_SERVERS, **fake, rel: text}
                targets = self._targets(files).targets
                self.assertTrue(targets and all(t.auxiliary and t.files for t in targets), targets)
                self.assertDemoted(self._exposures(files), set())

    def test_what_an_auxiliary_script_runs_is_still_live(self):
        files = {**TWO_SERVERS, "api.service": SERVICE_UNIT,
                 "scripts/run_copy.sh": "cd svc && python server_copy.py\n"}
        self.assertDemoted(self._exposures(files), set())

    def test_a_deployment_format_that_is_not_read_makes_the_deployment_unknown(self):
        unread = {
            "deploy/k8s/api.yaml": "apiVersion: apps/v1\nkind: Deployment\nspec:\n  template:\n    spec:\n"
                                   "      containers:\n        - name: api\n          image: registry/api\n",
            "charts/api/Chart.yaml": "apiVersion: v2\nname: api\n",
            "app.yaml": "runtime: python312\nentrypoint: gunicorn -k uvicorn.workers.UvicornWorker svc.server_copy:app\n",
            "fly.toml": 'app = "api"\n[processes]\n  app = "uvicorn svc.server_copy:app"\n',
            "render.yaml": "services:\n  - type: web\n    startCommand: uvicorn svc.server_copy:app\n",
            "app.json": '{"name": "api", "formation": {"web": {"quantity": 1}}}\n',
            "infra/ecs.tf": 'resource "aws_ecs_task_definition" "api" {\n  container_definitions = file("api.json")\n}\n',
            "deploy/uwsgi.conf": "[uwsgi]\nmodule = svc.server_copy:app\n",
            "deploy/api.service.j2": "[Service]\nExecStart={{ venv }}/bin/uvicorn svc.server_copy:app\n",
            "deploy/playbook.yml": "- copy:\n    content: |\n      [Service]\n"
                                  "      ExecStart=/opt/venv/bin/uvicorn svc.server_copy:app\n",
            "deploy/stack.yml": "services:\n  api:\n    image: registry/api\n",
        }
        for rel, text in unread.items():
            with self.subTest(rel):
                files = {**TWO_SERVERS, "api.service": SERVICE_UNIT, rel: text}
                self.assertEqual([t.manifest for t in self._targets(files).blocking], [rel])
                self.assertDemoted(self._exposures(files), set())

    def test_ordinary_yaml_ci_files_and_an_app_json_beside_its_procfile_do_not_block(self):
        files = {**TWO_SERVERS, "Procfile": "web: uvicorn svc.server:app\n",
                 "app.json": '{"name": "api", "formation": {"web": {"quantity": 1}}}\n',
                 "config/settings.yaml": "database:\n  pool: 5\n",
                 "openapi.yaml": "openapi: 3.1.0\npaths: {}\n",
                 ".github/workflows/ci.yml": "jobs:\n  test:\n    services:\n      db:\n        image: postgres\n",
                 "tests/k8s/api.yaml": "spec:\n  containers:\n    - name: api\n"}
        self.assertEqual(self._targets(files).blocking, ())
        self.assertDemoted(self._exposures(files), {"svc/server_copy.py"})

    def test_a_python_script_serving_an_application_by_name(self):
        procfile = "web: python run.py\nadmin: uvicorn admin.main:app\n"
        scripts = {
            "uvicorn.run": 'import uvicorn\nif __name__ == "__main__":\n    uvicorn.run("app.main:app", port=8000)\n',
            "keyword": 'import uvicorn\nuvicorn.run(app="app.main:app")\n',
            "imported run": 'from uvicorn import run as serve\nAPP = "app.main:app"\nserve(APP)\n',
            "granian": 'from granian import Granian\nGranian("app.main:app", interface="asgi").serve()\n',
        }
        for label, run in scripts.items():
            with self.subTest(label):
                files = {**THREE_APPS, "run.py": run, "Procfile": procfile}
                self.assertDemoted(self._exposures(files), {"legacy/server.py"})
                served = [t for t in self._targets(files).targets if t.command == "python run.py"]
                self.assertEqual([(t.server, t.files) for t in served],
                                 [(True, ("run.py", "app/main.py", "app/__init__.py"))])

    def test_a_python_script_serving_an_application_chosen_at_run_time_is_unknown(self):
        for run in ('import os, uvicorn\nuvicorn.run(os.environ["APP"])\n',
                    'import uvicorn\nname = "app.main"\nuvicorn.run(f"{name}:app")\n',
                    'import os, uvicorn\nuvicorn.run(os.getenv("APP", "app.main:app"))\n'):
            with self.subTest(run):
                files = {**THREE_APPS, "run.py": run, "Procfile": "web: python run.py\nadmin: uvicorn admin.main:app\n"}
                self.assertTrue(self._targets(files).blocking)
                self.assertDemoted(self._exposures(files), set())

    def test_python_dash_m_on_a_package_runs_its_main_module(self):
        for label, main in (("object", "import uvicorn\nfrom app.main import app\nuvicorn.run(app)\n"),
                            ("by name", 'import uvicorn\nuvicorn.run("app.main:app")\n')):
            with self.subTest(label):
                files = {**THREE_APPS, "app/__main__.py": main,
                         "Dockerfile": 'FROM python:3.12\nCMD ["python", "-m", "app"]\n',
                         "admin/Dockerfile": 'FROM python:3.12\nWORKDIR /srv\nCOPY . /srv\nCMD ["uvicorn", "main:app"]\n'}
                self.assertDemoted(self._exposures(files), {"legacy/server.py"})
                self.assertIn("app/__main__.py", [f for t in self._targets(files).targets for f in t.files])

    def test_an_image_that_copies_no_code_cannot_name_its_module(self):
        # Without COPY/ADD the image's working directory holds nothing from the repository
        # (a base image or a volume supplies the code), so `main` could be any main.py.
        files = {**THREE_APPS, "Procfile": "web: uvicorn app.main:app\n",
                 "admin/Dockerfile": 'FROM python:3.12\nCMD ["uvicorn", "main:app"]\n'}
        [blocking] = self._targets(files).blocking
        self.assertIn("main could be more than one file", blocking.unresolved)
        self.assertDemoted(self._exposures(files), set())

    def test_a_cmd_before_the_entrypoint_in_the_same_stage_is_kept(self):
        entrypoint = '#!/bin/sh\nset -e\nexec "$@"\n'
        files = {**THREE_APPS, "admin/Procfile": "web: uvicorn main:app\n", "docker/entrypoint.sh": entrypoint,
                 "Dockerfile": 'FROM python:3.12\nCOPY docker/entrypoint.sh /entrypoint.sh\n'
                               'CMD ["uvicorn", "app.main:app"]\nENTRYPOINT ["/entrypoint.sh"]\n'}
        self.assertDemoted(self._exposures(files), {"legacy/server.py"})
        self.assertIn(("app/main.py", "app/__init__.py"), [t.files for t in self._targets(files).targets])

    def test_an_entrypoint_the_repository_does_not_hold_blocks_demotion(self):
        # Fail closed: a script the image gets from elsewhere can start anything.
        for dockerfile in ('FROM python:3.12\nCMD ["uvicorn", "app.main:app"]\nENTRYPOINT ["/entrypoint.sh"]\n',
                           'FROM python:3.12\nENTRYPOINT ["/entrypoint.sh"]\n'):
            with self.subTest(dockerfile=dockerfile):
                files = {**THREE_APPS, "admin/Procfile": "web: uvicorn main:app\n", "Dockerfile": dockerfile}
                [blocking] = self._targets(files).blocking
                self.assertEqual(blocking.unresolved, "/entrypoint.sh is not a file in the repository")
                self.assertDemoted(self._exposures(files), set())

    def test_an_echoed_command_a_comment_and_a_heredoc_run_nothing(self):
        script = ('#!/bin/bash\n# python server.py\necho "python server.py"\n'
                  'printf "%s\\n" "uvicorn server:app"\ncat <<EOF\npython server.py\nEOF\n'
                  'echo "multi\npython server.py\n"\n')
        self.assertEqual(self._targets({**TWO_SERVERS, "svc/run.sh": script}).targets, ())
        self.assertDemoted(self._exposures({**TWO_SERVERS, "svc/run.sh": script}), set())

    def test_a_shell_script_that_does_run_a_file_counts(self):
        script = '#!/bin/bash\ncd "$(dirname "$0")"\nsource venv/bin/activate\nexec python server.py\n'
        self.assertDemoted(self._exposures({**TWO_SERVERS, "svc/run.sh": script}),
                           {"svc/server_copy.py"})

    def test_an_app_the_deployed_app_imports_is_not_demoted(self):
        main = "from admin import app as admin_app\n" + textwrap.dedent(SERVER_APP)
        files = {"main.py": main, "admin.py": SERVER_APP, "old_main.py": SERVER_APP,
                 "Procfile": "web: uvicorn main:app --port $PORT\n"}
        self.assertDemoted(self._exposures(files), {"old_main.py"})

    def test_gunicorn_with_a_uvicorn_worker_names_the_app_not_the_worker(self):
        files = {"main.py": SERVER_APP, "old_main.py": SERVER_APP,
                 "Procfile": "web: gunicorn -k uvicorn.workers.UvicornWorker -w 4 main:app\n"}
        self.assertDemoted(self._exposures(files), {"old_main.py"})

    def test_compose_and_supervisord_commands_resolve_against_their_directories(self):
        compose = ("services:\n  api:\n    build:\n      context: ../backend\n"
                   "    command:\n      - gunicorn\n      - --chdir\n      - /srv/backend\n"
                   "      - wsgi:app\n    ports:\n      - \"8000:8000\"\n")
        supervisor = ("[program:api]\ndirectory=/srv/example/worker\n"
                      "command=/opt/venv/bin/python -m flask --app service run\n")
        deployment = self._targets({"backend/wsgi.py": SERVER_APP, "worker/service.py": SERVER_APP,
                                    "deploy/docker-compose.yml": compose,
                                    "deploy/supervisord.conf": supervisor})
        self.assertEqual(sorted(f for t in deployment.targets for f in t.files),
                         ["backend/wsgi.py", "worker/service.py"])
        self.assertEqual(deployment.blocking, ())

    def test_the_note_does_not_change_the_fingerprint(self):
        live = Finding("security", "r", "high", "POST /x (x) changes state")
        demoted = Finding("security", "r", "high", live.message
                          + " [not run by any deployment manifest found: a.service runs a.py]")
        self.assertEqual(live.fingerprint, demoted.fingerprint)
        bracketed = Finding("security", "r", "high", live.message
                            + " [not run by any deployment manifest found: deploy/[prod]/Dockerfile runs a.py]")
        self.assertEqual(live.fingerprint, bracketed.fingerprint)
        self.assertNotEqual(live.fingerprint, Finding("security", "r", "high", live.message + " [other]").fingerprint)
        self.assertEqual(Finding("t", "r", "critical", "m", confidence="high", exposure="undeployed").priority, "P2")


if __name__ == "__main__":
    unittest.main()
