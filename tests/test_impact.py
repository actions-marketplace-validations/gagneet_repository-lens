from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

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
    """Resolve the sinking fund balance without converting missing values to zero."""
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
                "mongo_reads": {"annual_levies": ["find_one"]},
                "mongo_writes": {},
                "postgres_tables": ["finance.funds"],
                "postgres_unverified_refs": ["finance.possible_table"],
            }]})
        )
        graph = scan_repository(self.fixture.root)
        self.assertTrue(any(edge.kind == "READS_STORE" for edge in graph.edges))
        self.assertTrue(any(node.label == "finance.funds" for node in graph.nodes.values()))
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

    def test_a_null_optional_collection_in_an_artifact_is_not_a_crash(self) -> None:
        # footgun #14: `.get(key, [])` does NOT default a key that EXISTS holding None.
        # 58 of 65 entries in this repository's canonical_owners.json serialise
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
        """`server.py` holds ~1,700 symbols. Expanding its CONTAINS edges flooded the
        budget alphabetically, so a query returned AGMCreate, AmenityBookingCreate,
        AnnualBudgetCreate… and omitted the files that mattered."""
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
