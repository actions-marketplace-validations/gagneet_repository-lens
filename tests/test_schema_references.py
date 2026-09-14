"""A configured schema name is a table only in a SQL table position.

`billing` is a PostgreSQL schema and also a Python module, so `patch("routers.billing.db")`
and a `"billing.summary"` route key used to become tables in the default linkage map."""
from __future__ import annotations

import json
from pathlib import Path
import tempfile
import textwrap
import unittest
from unittest import mock

from repolens.analysis import Analysis
from repolens.impact import scanner
from repolens.impact.config import Config
from repolens.impact.model import Edge, Graph, Node
from repolens.impact.render import (UNVERIFIED_REASON, mark_unverified_stores, render_mermaid,
                                    unverified_stores)
from repolens.impact.scanner import scan_repository


def scan(files: dict[str, str], schemas: tuple[str, ...] = ("billing",)) -> Graph:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        files = {".impact-tracer.json": json.dumps({"pg_schemas": list(schemas)}), **files}
        for rel, body in files.items():
            path = root / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(textwrap.dedent(body).lstrip("\n"), encoding="utf-8")
        graph = scan_repository(root)
        mark_unverified_stores(graph)
        return graph


def tables(graph: Graph) -> set[str]:
    return {n.label for n in graph.nodes.values() if n.kind == "postgres_table"}


class SchemaReferenceTests(unittest.TestCase):
    def test_patch_targets_route_keys_and_import_paths_are_not_tables(self):
        graph = scan({"tests/test_billing.py": """
            from unittest.mock import patch
            ROUTES = {"billing.overview": 1}
            def test_tax():
                with patch("routers.billing.db") as mock_db:
                    pass
            def test_perms():
                with patch("routers.billing.get_user_permissions") as perms:
                    pass
            def test_comparison():
                r = ComparisonResult(account_id=1, route_key="billing.summary", matched=True)
                assert ROUTES["billing.invoice_totals"]
            def test_setattr(monkeypatch):
                monkeypatch.setattr("app.billing.cache", None)
                importlib.import_module("billing.jobs")
                exec_("from billing.models import Invoice")
        """})
        self.assertEqual(tables(graph), set())

    def test_a_dotted_path_inside_prose_without_a_table_keyword_is_not_a_table(self):
        graph = scan({"svc.py": 'MESSAGE = "call billing.summary before routers.billing.db"\n',
                      "web/x.ts": "export const k = 'billing.summary';\nexport const m = \"use billing.db here\";\n"})
        self.assertEqual(tables(graph), set())

    def test_a_schema_qualified_table_in_sql_the_parser_cannot_read_is_still_found(self):
        pattern = scanner._vocabulary(Config(pg_schemas=["billing"]))[0]
        # Not valid SQL for any parser; the regex pass does not depend on parsing.
        text = "SELECT * FROM billing.invoices WHERE {{ filter }} ???"
        found = scanner._schema_references(None, "q.sql", ".sql", text, pattern)
        self.assertEqual([name for name, _ in found], ["billing.invoices"])
        with mock.patch.object(scanner, "_sql_parser_available", return_value=False):
            graph = scan({"repo.py": """
                def load(cur):
                    cur.execute("SELECT * FROM billing.invoices")
                    cur.execute(" FROM billing.a a, billing.b AS b WHERE a.id = b.id")
                    cur.execute(" update billing.budgets set total = 0 WHERE ")
                    cur.execute("INSERT INTO billing.ledger (id) VALUES (1)")
            """})
        self.assertTrue({"billing.invoices", "billing.a", "billing.b", "billing.budgets", "billing.ledger"} <= tables(graph))
        regex = [e for e in graph.edges if e.origin == "regex" and e.kind == "TOUCHES_STORE"]
        self.assertTrue(all("unverified" in (e.detail or "") for e in regex))
        regex_only = unverified_stores(graph)
        self.assertTrue(regex_only)  # the fragments no parser reads
        self.assertTrue(all(graph.nodes[n].metadata.get("unverified") for n in regex_only))
        self.assertTrue(all(not graph.nodes[n].metadata.get("unverified")
                            for n in graph.nodes if graph.nodes[n].kind == "postgres_table" and n not in regex_only))

    def test_sql_keywords_and_non_table_objects(self):
        graph = scan({"web/q.ts": (
            "export const a = `CREATE INDEX idx ON billing.invoices (id)`;\n"
            "export const b = `DROP TABLE IF EXISTS billing.old_invoices`;\n"
            "export const c = `SELECT billing.calc(1)`;\n")})
        self.assertIn("billing.invoices", tables(graph))
        self.assertIn("billing.old_invoices", tables(graph))
        self.assertNotIn("billing.calc", tables(graph))

    def test_prose_with_a_lowercase_keyword_before_a_schema_name_is_not_sql(self):
        graph = scan({
            "svc.py": """
                import logging
                logging.info("Importing rows from billing.staging")
                COPY_HINT = "Copy billing.summary to the clipboard"
                VIEW_HINT = "Open the view billing.dashboard"
            """,
            "web/a.ts": "// don't read from billing.secret here\nexport const x = 1;\n",
            "web/b.ts": "/* it's joined from billing.later */\nexport const y = 'ok';\n",
        })
        self.assertEqual(tables(graph), set())

    def test_lowercase_sql_that_reads_as_sql_is_still_found(self):
        graph = scan({
            "repo.py": """
                def load(cur):
                    cur.execute("select id from billing.orders where id = %s")
                    cur.execute("delete from billing.carts")
                    cur.execute(" join billing.invoice_lines l on l.invoice_id = i.id WHERE ")
            """,
            "web/q.ts": (
                "// don't forget the comment above\n"
                "const home = \"http://example.test/\";\n"
                "export const a = 'SELECT * FROM billing.after_comment';\n"
                "export const b = `select *\n  from billing.stock\n  WHERE qty > 0`;\n"
            ),
        })
        self.assertEqual(tables(graph), {"billing.orders", "billing.carts", "billing.invoice_lines",
                                         "billing.after_comment", "billing.stock"})


class TestCodeAndArtifactStoreTests(unittest.TestCase):
    """Stores that only test code, fixtures or an unvalidated artifact name are not stores."""

    def test_a_pattern_match_in_test_code_links_only_to_a_store_found_elsewhere(self):
        graph = scan({
            "src/db.js": 'export const q = "SELECT id FROM billing.invoices";\n',
            "tests/queries.js": 'export const a = "SELECT id FROM billing.invoices";\n'
                                'export const b = "SELECT id FROM billing.fixture_only";\n',
            "tools/vendored-tool/tests/probe.js": 'export const c = "SELECT id FROM billing.v";\n',
        })
        self.assertEqual(tables(graph), {"billing.invoices"})
        sources = {graph.nodes[e.source].label for e in graph.edges
                   if e.kind == "TOUCHES_STORE" and graph.nodes[e.target].label == "billing.invoices"}
        self.assertEqual(sources, {"src/db.js", "tests/queries.js"})

    def test_unvalidated_artifact_names_link_only_to_tables_the_scan_found(self):
        artifact = {"routers": [
            {"file": "backend/ledger.py", "wired": True, "routes": [], "postgres_tables": ["billing.accounts"]},
            {"file": "backend/router.py", "wired": True, "routes": [],
             "postgres_unverified_refs": ["billing.accounts", "billing.view", "billing.fact_", "billing.maybe"]},
        ]}
        graph = scan({
            "docs/architecture/router_datastore_map.json": json.dumps(artifact),
            "backend/ledger.py": "def ledger():\n    return None\n",
            "backend/router.py": "def handler():\n    return None\n",
            "src/db.js": 'export const q = "SELECT id FROM billing.maybe";\n',
        })
        self.assertEqual(tables(graph), {"billing.accounts", "billing.maybe"})
        linked = {(graph.nodes[e.source].label, graph.nodes[e.target].label, e.resolution) for e in graph.edges
                  if e.kind == "TOUCHES_STORE" and e.origin == "generated_static_artifact"}
        self.assertEqual(linked, {("backend/ledger.py", "billing.accounts", "declared"),
                                  ("backend/router.py", "billing.accounts", "ambiguous")})
        [issue] = [i for i in graph.issues if i.code == "ARTIFACT_STORE_UNCONFIRMED"]
        self.assertEqual(issue.severity, "info")
        self.assertIn("3 unvalidated PostgreSQL name(s)", issue.message)
        self.assertIn("billing.fact_, billing.maybe, billing.view", issue.message)


class UnverifiedStoreTests(unittest.TestCase):
    def graph(self) -> Graph:
        graph = Graph("/repo")
        graph.add_node(Node("f", "file", "a.py", path="a.py"))
        graph.add_node(Node("real", "postgres_table", "billing.invoices", metadata={"unverified": True}))
        graph.add_node(Node("lead", "postgres_table", "billing.maybe"))
        graph.add_node(Node("art", "postgres_table", "billing.declared", metadata={"unverified": True}))
        graph.add_edge(Edge("f", "real", "TOUCHES_STORE", "probable", "a.py:1", origin="regex"))
        graph.add_edge(Edge("f", "real", "TOUCHES_STORE", "probable", "a.py:2", origin="sqlglot"))
        graph.add_edge(Edge("f", "lead", "TOUCHES_STORE", "probable", "a.py:3", origin="regex"))
        graph.add_edge(Edge("f", "art", "TOUCHES_STORE", "ambiguous", "x.json", origin="generated_static_artifact"))
        return graph

    def test_a_store_is_unverified_only_when_every_edge_is_a_regex_match(self):
        graph = self.graph()
        self.assertEqual(unverified_stores(graph), {"lead"})
        mark_unverified_stores(graph)
        self.assertNotIn("unverified", graph.nodes["real"].metadata)
        self.assertTrue(graph.nodes["lead"].metadata["unverified"])
        self.assertTrue(graph.nodes["art"].metadata["unverified"])  # the artifact's own verdict

    def test_the_default_map_leaves_unverified_tables_out_and_says_how_many(self):
        view = Analysis(self.graph(), [], Config()).view()
        self.assertNotIn("lead", view.nodes)
        self.assertIn("real", view.nodes)
        self.assertEqual([(r["type"], r["count"], r["reason"]) for r in view.omitted_breakdown],
                         [("postgres_table", 1, UNVERIFIED_REASON)])
        diagram = render_mermaid(view)
        self.assertNotIn("billing.maybe", diagram)
        self.assertIn("regex-only (unverified): 1 postgres_table", diagram)

    def test_a_query_view_labels_an_unverified_store(self):
        graph = self.graph()
        mark_unverified_stores(graph)
        view = Analysis(graph, [], Config()).view("billing.maybe")
        self.assertIn("unverified postgres_table: billing.maybe", render_mermaid(view))


if __name__ == "__main__":
    unittest.main()
