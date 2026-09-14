from __future__ import annotations

import ast
import json
import re
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from repolens.analysis import Analysis
from repolens.impact import fastapi as fastapi_pass
from repolens.impact import scanner
from repolens.impact.config import Config
from repolens.impact.model import Graph
from repolens.impact.query import impact, search
from repolens.impact.render import candidates, render_json, render_markdown, render_mermaid
from repolens.impact.scanner import repository_content_sha, scan_repository


class RepositoryFixture:
    def __init__(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def write(self, path: str, value: str) -> None:
        target = self.root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(value, encoding="utf-8")

    def close(self) -> None:
        self.tmp.cleanup()


class ImpactTracerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = RepositoryFixture()
        self.fixture.write(
            "backend/service.py",
            '''# @featuretrace:fund-balance — canonical fund calculation
# Related: frontend/src/app/funds/page.tsx
def calculate_fund_balance(opening, movements):
    """Resolve the reserve fund balance without converting missing values to zero."""
    return opening + sum(movements)
''',
        )
        self.fixture.write(
            "backend/router.py",
            '''from service import calculate_fund_balance

@router.get("/api/funds/balance")
async def get_fund_balance():
    return {"balance": calculate_fund_balance(1, [2])}
''',
        )
        self.fixture.write(
            "frontend/src/app/funds/page.tsx",
            '''// @featuretrace:fund-balance — fund balance page
export default function FundPage() {
  return api.get('/api/funds/balance');
}
''',
        )
        self.fixture.write(
            "docs/architecture/canonical_owners.json",
            json.dumps({
                "concepts": [{
                    "concept": "fund-balance-resolution",
                    "owner": "backend/service.py",
                    "symbols": ["calculate_fund_balance"],
                    "rule": "One owner computes the balance.",
                    "why": "Missing values must remain unmeasured.",
                    "tests": ["tests/test_balance.py"],
                    "consumers": [{"path": "frontend/src/app/funds/page.tsx", "relationship": "renders"}],
                    "found_violations": [],
                }]
            }),
        )

    def tearDown(self) -> None:
        self.fixture.close()

    def test_scans_page_api_handler_symbol_and_concept(self) -> None:
        graph = scan_repository(self.fixture.root)
        kinds = {node.kind for node in graph.nodes.values()}
        edge_kinds = {edge.kind for edge in graph.edges}
        self.assertTrue({"page", "endpoint", "symbol", "concept"} <= kinds)
        self.assertTrue({"CALLS_API", "HANDLES_API", "CALLS", "OWNS", "CONSUMES"} <= edge_kinds)

    def test_phrase_search_reads_source_without_storing_source_text(self) -> None:
        graph = scan_repository(self.fixture.root)
        matches = search(graph, self.fixture.root, "missing values to zero", Config())
        self.assertTrue(matches)
        self.assertEqual(graph.nodes[matches[0].node_id].path, "backend/service.py")
        serialised = json.dumps(graph.to_dict())
        self.assertNotIn("return opening + sum", serialised)

    def test_impact_keeps_policy_edges_required_and_heuristics_advisory(self) -> None:
        graph = scan_repository(self.fixture.root)
        result = impact(graph, self.fixture.root, "fund-balance-resolution", Config(), depth=2)
        classes = set(result.classifications.values())
        self.assertIn("query match", classes)
        self.assertIn("required review", classes)

    def test_dynamic_endpoint_is_not_claimed_as_exact(self) -> None:
        self.fixture.write(
            "frontend/src/dynamic.ts",
            "export const run = (id) => api.post(`/api/items/${id}/approve`);\n",
        )
        graph = scan_repository(self.fixture.root)
        dynamic = [node for node in graph.nodes.values() if node.kind == "endpoint" and node.metadata.get("dynamic")]
        self.assertEqual(len(dynamic), 1)
        edges = [edge for edge in graph.edges if edge.target == dynamic[0].id and edge.kind == "CALLS_API"]
        self.assertEqual(edges[0].resolution, "probable")

    def test_ambiguous_calls_do_not_become_exact(self) -> None:
        self.fixture.write("backend/a.py", "def normalise(value):\n    return value\n")
        self.fixture.write("backend/b.py", "def normalise(value):\n    return str(value)\n")
        self.fixture.write("backend/c.py", "def use(value):\n    return normalise(value)\n")
        graph = scan_repository(self.fixture.root)
        ambiguous = [edge for edge in graph.edges if edge.kind == "CALLS" and edge.resolution == "ambiguous"]
        self.assertTrue(ambiguous)
        self.assertTrue(any(issue.code == "AMBIGUOUS_CALL" for issue in graph.issues))

    def test_an_ambiguous_target_is_rendered_as_a_candidate_and_listed_by_name(self) -> None:
        self.fixture.write("backend/a.py", "def normalise_amount(value):\n    return value\n")
        self.fixture.write("backend/b.py", "def normalise_amount(value):\n    return str(value)\n")
        self.fixture.write(
            "backend/c.py",
            "def render_invoice_totals(value):\n    return normalise_amount(value)\n",
        )
        graph = scan_repository(self.fixture.root)
        result = impact(graph, self.fixture.root, "render invoice totals", Config(), depth=2)
        guessed = {result.nodes[n].label for n in candidates(result)}
        self.assertIn("normalise_amount", guessed)
        self.assertNotIn("render_invoice_totals", guessed)
        self.assertIn("classDef candidate", render_mermaid(result))
        markdown = render_markdown(result)
        self.assertIn("(candidate: ambiguous name", markdown)
        # The heading says names, so the entries are names — not path:line call sites.
        self.assertIn("- `normalise_amount` — ", markdown)

    def test_index_round_trip_is_deterministic(self) -> None:
        graph = scan_repository(self.fixture.root)
        index = self.fixture.root / "index.json"
        graph.save(index)
        loaded = Graph.load(index)
        self.assertEqual(graph.to_dict(), loaded.to_dict())

    def test_repository_fingerprint_changes_with_source(self) -> None:
        config = Config.load(self.fixture.root)
        before = repository_content_sha(self.fixture.root, config)
        self.fixture.write("backend/service.py", "def changed():\n    return True\n")
        after = repository_content_sha(self.fixture.root, config)
        self.assertNotEqual(before, after)

    def test_mermaid_is_bounded_and_sanitises_directives(self) -> None:
        self.fixture.write("frontend/src/app/evil/page.tsx", 'export function X() { return "``` %%{init}"; }\n')
        graph = scan_repository(self.fixture.root)
        result = impact(graph, self.fixture.root, "evil", Config(), max_nodes=12)
        diagram = render_mermaid(result)
        self.assertTrue(diagram.startswith("flowchart TD\n"))
        self.assertNotIn("```", diagram)
        self.assertNotIn("%%", diagram)

    def test_reports_are_valid_and_include_limitations(self) -> None:
        graph = scan_repository(self.fixture.root)
        result = impact(graph, self.fixture.root, "fund balance", Config(), depth=2)
        markdown = render_markdown(result)
        payload = json.loads(render_json(result))
        self.assertIn("does not prove a component is unaffected", markdown)
        self.assertEqual(payload["query"], "fund balance")

    def test_router_datastore_artifact_is_read_only_enrichment(self) -> None:
        self.fixture.write(
            "docs/architecture/router_datastore_map.json",
            json.dumps({"routers": [{
                "file": "backend/router.py",
                "wired": True,
                "classification": "hybrid",
                "routes": [{"method": "GET", "path": "/api/funds/balance", "handler": "get_fund_balance"}],
                "mongo_reads": {"annual_invoices": ["find_one"]},
                "mongo_writes": {},
                "postgres_tables": ["billing.accounts"],
                "postgres_unverified_refs": ["billing.possible_table"],
            }]})
        )
        graph = scan_repository(self.fixture.root)
        self.assertTrue(any(edge.kind == "READS_STORE" for edge in graph.edges))
        self.assertTrue(any(node.label == "billing.accounts" for node in graph.nodes.values()))
        self.assertFalse(any(
            issue.code == "API_CALL_WITHOUT_HANDLER" and "funds/balance" in issue.message
            for issue in graph.issues
        ))

    def test_identical_python_bodies_are_candidates_not_verified_duplicates(self) -> None:
        self.fixture.write("backend/x.py", "def first(value):\n    return value * 2\n")
        self.fixture.write("backend/y.py", "def second(value):\n    return value * 2\n")
        graph = scan_repository(self.fixture.root)
        edges = [edge for edge in graph.edges if edge.kind == "STRUCTURALLY_SIMILAR"]
        self.assertTrue(edges)
        self.assertTrue(all(edge.resolution == "ambiguous" and edge.origin == "heuristic" for edge in edges))


if __name__ == "__main__":
    unittest.main()


class WholeRunResilienceTests(unittest.TestCase):
    """Every failure below was found by running the scanner on a real repository and
    was invisible to the original suite, because that suite only ever fed the scanner
    inputs it had constructed. Passing isolated fixtures said nothing about whether a
    whole-repository run survives what a checkout actually contains."""

    def setUp(self) -> None:
        self.fixture = RepositoryFixture()
        self.addCleanup(self.fixture.close)

    def test_a_file_that_blows_the_recursion_limit_does_not_end_the_scan(self) -> None:
        # Real cause: sympy's polys/numberfields/resolvent_lookup.py, vendored under
        # `_archive/venv-root-stale/`. `_scan_python` caught SyntaxError only, so
        # RecursionError escaped `ast.visit` and killed the whole run — no graph, no
        # diagnostics, no partial result, on a file the repository does not own.
        # Nested brackets are refused by the PARSER (SyntaxError) and never reach
        # the visitor. A long left-nested BinOp chain parses fine and produces an
        # AST ~N deep, which is the shape that actually escaped as RecursionError.
        self.fixture.write("deep.py", "x = " + " + ".join(["1"] * 3000) + "\n")
        self.fixture.write("real.py", "def keeper():\n    return 1\n")
        graph = scan_repository(self.fixture.root, Config())
        labels = {node.label for node in graph.nodes.values()}
        self.assertIn("keeper", labels, "a later file was skipped, so the scan aborted")
        codes = {issue.code for issue in graph.issues}
        self.assertTrue(
            {"FILE_TOO_DEEPLY_NESTED", "FILE_SCAN_FAILED"} & codes,
            "the unwalkable file produced no diagnostic — it failed silently instead",
        )

    def test_a_deeply_nested_router_prefix_does_not_end_the_scan(self) -> None:
        # The visitor fails on this file; its tree used to be stored first anyway, and
        # the route pass then recursed through the same prefix outside any guard.
        chain = " + ".join(['"a"'] * 3000)
        self.fixture.write("main.py", "from fastapi import FastAPI, APIRouter\napp = FastAPI()\n"
                                      f"r = APIRouter()\nx = 1\napp.include_router(r, prefix=x + {chain})\n")
        self.fixture.write("real.py", "def keeper():\n    return 1\n")
        graph = scan_repository(self.fixture.root, Config())
        codes = {issue.code for issue in graph.issues}
        self.assertIn("keeper", {node.label for node in graph.nodes.values()})
        self.assertIn("FILE_TOO_DEEPLY_NESTED", codes)
        self.assertNotIn("ANALYSIS_PASS_FAILED", codes, "the failed file's tree reached a later pass")

    def test_a_huge_string_annotation_does_not_end_the_scan(self) -> None:
        union = "|".join(["int"] * 20000)
        self.fixture.write("main.py", "from fastapi import APIRouter\nr = APIRouter()\n"
                                      f"@r.get('/x')\ndef f(q: \"{union}\"): ...\n")
        graph = scan_repository(self.fixture.root, Config())
        codes = {issue.code for issue in graph.issues}
        self.assertNotIn("ANALYSIS_PASS_FAILED", codes)
        self.assertIn("API_HANDLER_WITHOUT_STATIC_CALLER", codes, "the route pass did not finish")

    def test_the_route_helpers_bound_what_they_parse_and_unparse(self) -> None:
        deep: ast.expr = ast.Constant("a")
        for _ in range(20000):  # no positions, so only the recursion guard can stop it
            deep = ast.BinOp(deep, ast.Add(), ast.Constant("a"))
        self.assertEqual(fastapi_pass._shown(deep), "<BinOp expression>")
        wide = ast.parse("f(" + ", ".join(['"a"'] * 2000) + ")", mode="eval").body
        self.assertEqual(fastapi_pass._shown(wide), "<Call expression>")
        self.assertEqual(fastapi_pass._shown(ast.parse("settings.prefix", mode="eval").body), "settings.prefix")
        self.assertEqual(fastapi_pass._type_names(ast.Constant("|".join(["int"] * 20000))), [])
        nested = "list[" * 400 + "int" + "]" * 400
        self.assertIsInstance(fastapi_pass._type_names(ast.Constant(nested)), list)
        self.assertIn("Item", fastapi_pass._type_names(ast.Constant("list[Item] | None")))

    def test_a_pass_that_crashes_is_reported_and_the_later_passes_still_run(self) -> None:
        self.fixture.write("x.py", "def first(value):\n    return value * 2\n")
        self.fixture.write("y.py", "def second(value):\n    return value * 2\n")
        secret = "/private/checkout/path"
        with mock.patch.object(scanner, "_resolve_calls", side_effect=RuntimeError(secret)), \
                mock.patch.object(fastapi_pass, "add_routes", side_effect=RecursionError(secret)):
            graph = scan_repository(self.fixture.root, Config())
        failed = [issue for issue in graph.issues if issue.code == "ANALYSIS_PASS_FAILED"]
        self.assertEqual(sorted(issue.subject for issue in failed), ["add_routes", "resolve_calls"])
        self.assertTrue(all(secret not in issue.message for issue in failed))
        self.assertTrue(any("RuntimeError" in issue.message for issue in failed))
        self.assertTrue(any(edge.kind == "STRUCTURALLY_SIMILAR" for edge in graph.edges),
                        "a pass after the failed ones did not run")
        analysis = Analysis(graph, [], Config())
        self.assertFalse(analysis.complete)
        self.assertTrue(any(reason.startswith("ANALYSIS_PASS_FAILED x2") for reason in analysis.incomplete_reasons()))

    def test_a_null_optional_collection_in_an_artifact_is_not_a_crash(self) -> None:
        # footgun #14: `.get(key, [])` does NOT default a key that EXISTS holding None.
        # Most entries in a real-world canonical_owners.json serialised
        # `consumers: null`, and the loader raised TypeError partway through — after
        # the AST scan, at the one step that reads declared policy.
        self.fixture.write("svc.py", "def owner_fn():\n    return 1\n")
        self.fixture.write("docs/canonical_owners.json", json.dumps({
            "concepts": [{
                "concept": "thing", "owner": "svc.py",
                "symbols": None, "tests": None, "consumers": None,
                "found_violations": None, "known_violations": None,
                "rule": "call the owner",
            }]
        }))
        config = Config()
        config.canonical_owners_json = "docs/canonical_owners.json"
        graph = scan_repository(self.fixture.root, config)   # must not raise
        self.assertIn("thing", {node.label for node in graph.nodes.values()})

    def test_an_empty_and_a_populated_collection_both_load(self) -> None:
        for value in ([], [{"path": "svc.py", "surface": "a page"}]):
            with self.subTest(consumers=value):
                self.fixture.write("svc.py", "def owner_fn():\n    return 1\n")
                self.fixture.write("docs/co.json", json.dumps({"concepts": [{
                    "concept": "thing", "owner": "svc.py", "consumers": value,
                }]}))
                config = Config()
                config.canonical_owners_json = "docs/co.json"
                scan_repository(self.fixture.root, config)


class RelevanceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = RepositoryFixture()
        self.addCleanup(self.fixture.close)

    def test_a_human_phrase_matches_a_snake_case_name(self) -> None:
        """The defect that made concept search structurally impossible.

        `TOKEN_RE` counts `_ . / -` as WORD characters, so a path normalised to
        itself as ONE token and a space-separated phrase could never be a substring
        of it. Only free prose could match. On the real repository, querying
        "expenditure volatility" scored the owner module at **0** and returned
        `backend/server.py` as the top seed — it won because it contains the literal
        `tags=["Expenditure Volatility"]`, a string with a space in it.
        """
        from repolens.impact.query import _normalise

        self.assertEqual(
            _normalise("backend/services/expenditure_volatility_profile.py"),
            "backend services expenditure volatility profile py",
        )
        self.assertEqual(_normalise("ExpenditureVolatilityPage"),
                         "expenditure volatility page")
        self.assertEqual(_normalise("settings/expenditure-volatility"),
                         "settings expenditure volatility")
        # HTTPServerError must not become h t t p server error.
        self.assertEqual(_normalise("HTTPServerError"), "http server error")

    def test_the_owner_module_outranks_a_file_that_only_mentions_it(self) -> None:
        self.fixture.write(
            "backend/services/widget_health_profile.py",
            "def resolve_widget_health():\n    return 1\n",
        )
        self.fixture.write(
            "backend/server.py",
            "\n".join(f"def handler_{i}():\n    return {i}" for i in range(80))
            + '\napi.include_router(r, tags=["Widget Health"])\n',
        )
        graph = scan_repository(self.fixture.root, Config())
        results = search(graph, self.fixture.root, "widget health", Config(), limit=5)
        top = graph.nodes[results[0].node_id]
        self.assertIn("widget_health", (top.path or top.label))

    def test_a_hub_file_cannot_dominate_a_bounded_result(self) -> None:
        """A hub file with ~1,700 symbols: expanding its CONTAINS edges flooded the budget
        alphabetically, so a query returned AccountCreate, AddressCreate, AuditCreate… and
        omitted the files that mattered."""
        self.fixture.write(
            "hub.py",
            "\n".join(f"def widget_thing_{i}():\n    return {i}" for i in range(200)),
        )
        self.fixture.write("small.py", "def widget_thing_real():\n    return 1\n")
        graph = scan_repository(self.fixture.root, Config())
        result = impact(graph, self.fixture.root, "widget thing", Config(),
                        depth=2, max_nodes=20)
        from collections import Counter
        per_file = Counter(
            (result.nodes[node_id].path or result.nodes[node_id].label)
            for node_id in result.classifications
            if result.classifications[node_id] != "query match"
        )
        for owner, count in per_file.items():
            self.assertLessEqual(
                count, max(1, int(20 * 0.25)),
                f"{owner} took {count} of a 20-node budget — a hub is crowding out the rest",
            )

    def test_an_issue_that_merely_lists_a_node_as_a_CANDIDATE_is_not_relevant(self) -> None:
        """AMBIGUOUS_CALL attaches [call_site, *six_candidate_targets]. Counting an
        issue as relevant because one of six guesses landed in the result reported
        5,315 issues for a single-file query on the real repository."""
        from repolens.impact.model import Issue
        from repolens.impact.query import _issue_is_about

        selected = {"n_target": object()}
        mentions_only = Issue("AMBIGUOUS_CALL", "info", "m",
                              ["n_caller", "n_target", "n_other", "n_more"], "e", "r")
        self.assertFalse(_issue_is_about(mentions_only, selected))
        about_it = Issue("AMBIGUOUS_CALL", "info", "m",
                         ["n_target", "n_a", "n_b", "n_c"], "e", "r")
        self.assertTrue(_issue_is_about(about_it, selected))
        self.assertFalse(_issue_is_about(Issue("X", "info", "m", [], "e", "r"), selected))

    def test_omissions_are_grouped_not_counted(self) -> None:
        from repolens.impact.query import _group_omissions

        grouped = _group_omissions([
            {"file": "hub.py", "type": "symbol", "relationship": "CONTAINS",
             "reason": "hub file collapsed"},
        ] * 12)
        self.assertEqual(len(grouped), 1)
        self.assertEqual(grouped[0]["count"], 12)
        self.assertEqual(grouped[0]["file"], "hub.py")


class StoreChainTests(unittest.TestCase):
    """A table query must reach the endpoint and page, and stay bounded doing so."""

    def graph(self) -> Graph:
        from repolens.impact.model import Edge, Node
        graph = Graph("/repo")
        chain = [("t", "postgres_table", "order_items", None), ("svc", "symbol", "load_items", "backend/service.py"),
                 ("handler", "symbol", "get_items", "backend/router.py"), ("ep", "endpoint", "GET /api/items", "backend/router.py"),
                 ("client", "symbol", "fetchItems", "web/src/client.ts"), ("page", "page", "/items", "web/src/app/items/page.tsx")]
        for node_id, kind, label, path in chain:
            graph.add_node(Node(node_id, kind, label, path=path))
        for source, target, kind in (("svc", "t", "TOUCHES_STORE"), ("handler", "svc", "CALLS"), ("ep", "handler", "HANDLES_API"),
                                     ("client", "ep", "CALLS_API"), ("page", "client", "CALLS")):
            graph.add_edge(Edge(source, target, kind, "exact", "x:1", origin="ast"))
        # Nodes sharing only a WORD with the table name.
        for index, label in enumerate(("order_total", "list_order", "items_banner", "items_footer", "order_status")):
            graph.add_node(Node(f"noise{index}", "symbol", label, path=f"web/noise{index}.ts"))
        return graph

    def test_view_default_depth_reaches_the_endpoint_and_depth_is_bounded(self) -> None:
        from repolens.analysis import Analysis
        analysis = Analysis(self.graph(), [], Config())
        self.assertNotIn("ep", analysis.view("order_items", 30, depth=2).nodes)
        self.assertIn("ep", analysis.view("order_items", 30).nodes)
        self.assertIn("page", analysis.view("order_items", 30, depth=6).nodes)
        self.assertLessEqual(len(analysis.view("order_items", 3, depth=8).nodes), 3)
        for depth in (0, 9):
            with self.assertRaises(ValueError):
                analysis.view("order_items", 30, depth=depth)

    def test_analyze_rejects_an_out_of_range_depth(self) -> None:
        import contextlib, io
        from repolens.analysis import main
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            main(["--depth", "9"])

    def test_an_exact_store_name_does_not_seed_nodes_that_only_share_a_word(self) -> None:
        graph = self.graph()
        seeds = [m.node_id for m in search(graph, Path("/repo"), "ORDER_ITEMS", Config(), search_source=False)]
        self.assertEqual(seeds, ["t"])
        # Without an exact store label, word matches still seed as before.
        self.assertIn("noise0", [m.node_id for m in search(graph, Path("/repo"), "order", Config(), search_source=False)])


class MarkdownEscapingTests(unittest.TestCase):
    def test_repository_text_cannot_split_a_table_row_or_close_a_code_span(self) -> None:
        from repolens.impact.model import Edge, Node
        from repolens.impact.query import ImpactResult, Match
        label = 'a|b`c\\'
        graph_nodes = {"s": Node("s", "symbol", "weird|fn", path="q|x.py", line=2),
                       "t": Node("t", "postgres_table", label)}
        edge = Edge("s", "t", "TOUCHES_STORE", "probable", "q|x.py:2", origin="sqlglot")
        result = ImpactResult(label, [Match("t", 100.0, ["exact label"], ["q.py:2: SELECT * FROM \"a|b`c\" <b>"])],
                              graph_nodes, [edge], [], {"s": "required review", "t": "query match"},
                              1, [{"file": "f|g.py", "type": "symbol", "relationship": "CONTAINS", "reason": "hub | cap", "count": 1}])
        markdown = render_markdown(result)
        self.assertIn("# Impact trace: `a|b'c\\`", markdown)
        header_cells = {"| Match |": 5, "| Action |": 4, "| From |": 6, "| Count |": 5}
        rows = markdown.split("## Issues")[0].splitlines()
        current = None
        for row in rows:
            for prefix, count in header_cells.items():
                if row.startswith(prefix):
                    current = count
            if current and row.startswith("|"):
                # An unescaped pipe is one not preceded by an odd run of backslashes.
                separators = re.findall(r"(?<!\\)(?:\\\\)*\|", row)
                self.assertEqual(len(separators), current + 1, row)
                self.assertEqual(row.count("`") % 2, 0, row)
            elif not row.startswith("|"):
                current = None
        self.assertNotIn("<b>", markdown)
