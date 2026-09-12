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

    @router.get("/orgs/{org_id}/buildings")
    async def list_org_buildings(org_id: str, current_user: dict = Depends(get_current_user)):
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
        [finding] = self._for("security/object-route-without-ownership-check", "/buildings")
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

    def test_check_with_update_baseline_is_rejected(self):
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as caught:
            runner.main(["--check", "--update-baseline"])
        self.assertEqual(caught.exception.code, 2)


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


if __name__ == "__main__":
    unittest.main()
