"""`repolens docs generate`: OpenAPI, schema, architecture and feature pages from the evidence graph."""
from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import re
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from repolens.analysis import Analysis, analyze
from repolens.config import load_config
from repolens.core import javascript
from repolens.docs import generate
from repolens.impact.config import Config
from repolens.impact.model import Edge, Graph, Node
from tests.stack_app import write_example_app

HAS_STACK = javascript.available() and importlib.util.find_spec("sqlglot") is not None


def run(root: Path, out: Path, *extra: str) -> tuple[int, str]:
    buffer = io.StringIO()
    with contextlib.redirect_stdout(buffer):
        code = generate.main(["--out", str(out), *extra], config=load_config(root))
    return code, buffer.getvalue()


@unittest.skipUnless(HAS_STACK, "install repolens[stack]")
class ExampleAppDocsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.root = Path(cls.tmp.name) / "app"
        write_example_app(cls.root)
        cls.out = Path(cls.tmp.name) / "docs"
        cls.code, cls.output = run(cls.root, cls.out)
        cls.openapi = json.loads((cls.out / "openapi.json").read_text(encoding="utf-8"))

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def read(self, name):
        return (self.out / name).read_text(encoding="utf-8")

    def test_a_complete_analysis_writes_every_output_and_exits_0(self):
        self.assertEqual(self.code, 0, self.output)
        for name in ("openapi.json", "schema.mmd", "schema.md", "architecture.mmd", "architecture.md", "debugging.md", "index.md",
                     "features/orders.md", "features/orders.context.json", "features/reviews.md"):
            self.assertTrue((self.out / name).is_file(), name)
        self.assertIn("produced by repolens", self.read("index.md"))

    def test_openapi_lists_served_operations_and_keeps_unserved_calls_out(self):
        paths = self.openapi["paths"]
        self.assertEqual(self.openapi["openapi"], "3.1.0")
        self.assertEqual(self.openapi["info"]["title"], "shop-app")
        self.assertTrue(self.openapi["x-repolens-complete"])
        self.assertEqual({"get", "post"}, {k for k in paths["/api/orders"] if not k.startswith("x-")})
        self.assertEqual({"get"}, {k for k in paths["/api/reviews"] if not k.startswith("x-")})
        unserved = self.openapi["x-repolens-unserved-calls"]
        self.assertEqual([("POST", "/api/reviews")], [(u["method"], u["path"]) for u in unserved])
        self.assertIn("app/products/page.tsx:5", unserved[0]["callers"])
        self.assertTrue(any("405" in message for message in unserved[0]["issues"]))

    def test_path_templates_use_source_parameter_names(self):
        paths = self.openapi["paths"]
        self.assertIn("/api/orders/{orderId}", paths)
        operation_ids = []
        for path, item in paths.items():
            for method, operation in item.items():
                if method.startswith("x-"):
                    continue
                operation_ids.append(operation["operationId"])
                declared = [p["name"] for p in operation["parameters"] if p["in"] == "path"]
                self.assertEqual(re.findall(r"\{([^}]+)\}", path), declared, path)
                self.assertTrue(all(p["required"] and p["schema"] == {} for p in operation["parameters"]))
        self.assertEqual(len(operation_ids), len(set(operation_ids)))

    def test_operations_carry_evidence_and_name_their_gaps(self):
        listing = self.openapi["paths"]["/api/orders"]["get"]
        self.assertEqual(listing["x-repolens-handler"]["file"], "app/api/orders/route.ts")
        self.assertEqual(listing["x-repolens-feature"], "orders")
        self.assertIn({"name": "orders", "kind": "postgres_table"}, listing["x-repolens-stores"])
        self.assertIn("app/orders/page.tsx:7", listing["x-repolens-callers"])
        self.assertIn("response schema", listing["x-repolens-gaps"])
        self.assertEqual(listing["responses"], {"default": {"description": "Response not inferred from source"}})
        create = self.openapi["paths"]["/api/orders"]["post"]
        self.assertIn("request body", create["x-repolens-gaps"])
        self.assertNotIn("requestBody", create)

    def test_feature_pages_list_the_group_gaps_and_unknowns(self):
        orders = self.read("features/orders.md")
        self.assertIn("SQL_INJECTION_RISK", orders)
        self.assertIn("mindmap", orders)
        self.assertIn("lib/orders.ts", orders)
        mismatch = self.read("features/reviews.md") + self.read("features/products.md")
        self.assertIn("API_METHOD_MISMATCH", mismatch)
        context = json.loads(self.read("features/orders.context.json"))
        self.assertEqual(context["group"], "orders")
        self.assertIn({"name": "orders", "kind": "postgres_table"}, context["stores"])
        self.assertTrue(any("Authorization" in item for item in context["unknowns"]))
        self.assertIn("SQL_INJECTION_RISK", {gap["code"] for gap in context["gaps"]})
        debug = context["debugging"]
        self.assertIn("repolens analyze --query orders", debug["impact_query"])
        [listing] = [trace for trace in debug["traces"] if trace["request"] == "GET /api/orders"]
        self.assertIn("app/orders/page.tsx:7", listing["caller_locations"])
        self.assertIn("app/api/orders/route.ts:4", listing["handler_locations"])
        self.assertIn("orders", listing["stores"])
        products = json.loads(self.read("features/products.context.json"))["debugging"]["traces"]
        [outbound] = [trace for trace in products if trace["request"] == "POST /api/reviews"]
        self.assertEqual(outbound["direction"], "outbound request")
        self.assertIn("app/products/page.tsx:5", outbound["caller_locations"])

    def test_debugging_guide_is_static_and_gives_bounded_runtime_advice(self):
        guide = self.read("debugging.md")
        self.assertIn("has no production runtime path", guide)
        self.assertIn("repolens analyze --query orders", guide)
        self.assertIn("sample successful requests", guide)
        self.assertIn("do not record bodies", guide)
        self.assertIn("features/orders.md#debugging-plan", guide)

    def test_schema_draws_declared_columns_relationships_and_collections(self):
        schema = self.read("schema.mmd")
        entities = dict(re.findall(r'^  (e\d+)\["([^"]+)"\] \{', schema, re.M))
        by_name = {name: entity for entity, name in entities.items()}
        self.assertTrue({"customers", "orders", "reviews"} <= set(by_name))
        self.assertIn(f'{by_name["orders"]} }}o--o| {by_name["customers"]} : "foreign key"', schema)
        self.assertRegex(schema, r"serial id PK")
        self.assertRegex(schema, r"int customer_id FK")
        self.assertIn("fields not inferred", schema)
        self.assertIn("```mermaid", self.read("schema.md"))

    def test_architecture_draws_each_group_and_its_stores(self):
        architecture = self.read("architecture.mmd")
        self.assertTrue(architecture.startswith("flowchart LR"))
        for text in ("orders: 3 endpoints", "reviews: 1 endpoint, 1 unserved", "orders (PostgreSQL table)",
                     "reviews (MongoDB collection)"):
            self.assertIn(text, architecture)
        self.assertRegex(architecture, r"f\d+ --> a\d+")
        self.assertRegex(architecture, r"c\d+ --> s\d+")

    def test_tables_with_columns_and_relationships_are_drawn_before_collections(self):
        analysis = analyze(self.root)
        with mock.patch.object(generate, "MAX_ENTITIES", 2):
            schema, md = generate.build_schema(analysis, self.root)
        drawn = set(re.findall(r'^  e\d+\["([^"]+)"\] \{', schema, re.M))
        self.assertEqual(drawn, {"customers", "orders"})
        self.assertIn('e1 }o--o| e0 : "foreign key"', schema)
        self.assertIn("1 more stores not drawn: 1 MongoDB collection", schema)
        self.assertIn("| `reviews` | MongoDB collection | not resolved |  | no |", md)


class StoreReachTests(unittest.TestCase):
    def test_a_store_reached_only_through_a_name_only_call_is_not_an_operation_store(self):
        graph = Graph("/repo")
        for node in (Node("ep", "endpoint", "GET /items", metadata={"method": "GET", "route": "/items"}),
                     Node("handler", "symbol", "list_items", path="api.py", line=3),
                     Node("service", "symbol", "load_items", path="service.py", line=1),
                     Node("guess", "symbol", "load", path="other.py", line=1),
                     Node("items", "postgres_table", "items"), Node("audit", "postgres_table", "audit")):
            graph.add_node(node)
        graph.add_edge(Edge("ep", "handler", "HANDLES_API", "exact", "api.py:3"))
        graph.add_edge(Edge("handler", "service", "CALLS", "high", "api.py:4"))
        graph.add_edge(Edge("handler", "guess", "CALLS", "probable", "api.py:5"))
        graph.add_edge(Edge("service", "items", "TOUCHES_STORE", "probable", "service.py:2"))
        graph.add_edge(Edge("guess", "audit", "TOUCHES_STORE", "probable", "other.py:2"))
        with tempfile.TemporaryDirectory() as tmp:
            analysis = Analysis(graph, [], Config.load(Path(tmp)))
            openapi = generate.build_openapi(analysis, Path(tmp), generate.feature_groups(graph))
        operation = openapi["paths"]["/items"]["get"]
        self.assertEqual(operation["x-repolens-stores"], [{"name": "items", "kind": "postgres_table"}])


class MermaidLabelTests(unittest.TestCase):
    hostile = 'x"] --> evil["y\n%% comment\nclick x call alert()`[z]'

    def test_repository_text_cannot_leave_a_label(self):
        for label in (generate.flow_label(self.hostile), generate.leaf_label(self.hostile)):
            self.assertNotIn('"', label)
            self.assertNotIn("[", label)
            self.assertNotIn("]", label)
            self.assertNotIn("\n", label)
        self.assertNotIn("%", generate.flow_label(self.hostile))
        self.assertNotIn("`", generate.leaf_label(self.hostile))

    def test_path_names_are_unique_template_parameters(self):
        from repolens.impact.model import Node
        node = Node("e", "endpoint", "GET /a/{dynamic}/b/{dynamic}", metadata={"method": "GET", "route": "/a/{dynamic}/b/{dynamic}"})
        self.assertEqual(generate.openapi_path(node), ("/a/{param1}/b/{param2}", ["param1", "param2"]))
        named = Node("e", "endpoint", "GET x", metadata={"path": "/a/{id}/b/{id}"})
        self.assertEqual(generate.openapi_path(named), ("/a/{id}/b/{id2}", ["id", "id2"]))


@unittest.skipUnless(HAS_STACK, "install repolens[stack]")
class CommandBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def write(self, name, text):
        target = self.root / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8")

    def test_an_incomplete_analysis_still_writes_and_exits_2(self):
        self.write("broken.py", "def broken(:\n")
        self.write("app/api/health/route.ts", "export async function GET() { return Response.json({}); }\n")
        code, output = run(self.root, self.root / "out")
        self.assertEqual(code, 2, output)
        openapi = json.loads((self.root / "out/openapi.json").read_text(encoding="utf-8"))
        self.assertFalse(openapi["x-repolens-complete"])
        self.assertTrue(any("PYTHON_PARSE_ERROR" in r for r in openapi["x-repolens-incomplete-reasons"]))
        self.assertIn("Analysis complete: **no**", (self.root / "out/index.md").read_text(encoding="utf-8"))

    def test_files_it_did_not_write_are_never_replaced_or_removed(self):
        self.write("app/api/health/route.ts", "export async function GET() { return Response.json({}); }\n")
        self.write("out/features/notes.md", "# Hand-written notes\n")
        self.write("out/features/retired.md", "<!-- produced by repolens 0.2.0 -->\n# retired group\n")
        code, output = run(self.root, self.root / "out")
        self.assertEqual(code, 0, output)
        self.assertEqual((self.root / "out/features/notes.md").read_text(encoding="utf-8"), "# Hand-written notes\n")
        self.assertFalse((self.root / "out/features/retired.md").exists())
        # Its own outputs carry the stamp, so a second run replaces them.
        code, output = run(self.root, self.root / "out")
        self.assertEqual(code, 0, output)
        self.write("out/openapi.json", '{"openapi": "3.0.0"}\n')
        code, output = run(self.root, self.root / "out")
        self.assertEqual(code, 2, output)
        self.assertIn("not written by repolens docs generate", output)
        self.assertEqual((self.root / "out/openapi.json").read_text(encoding="utf-8"), '{"openapi": "3.0.0"}\n')

    def test_a_file_that_only_quotes_the_stamp_is_not_its_output(self):
        self.write("app/api/health/route.ts", "export async function GET() { return Response.json({}); }\n")
        quoted = "# Notes\nThe index is produced by repolens docs generate.\n"
        self.write("out/index.md", quoted)
        code, output = run(self.root, self.root / "out")
        self.assertEqual(code, 2, output)
        self.assertEqual((self.root / "out/index.md").read_text(encoding="utf-8"), quoted)
        (self.root / "out/index.md").unlink()
        self.write("out/features/README.md", '{"build": "repolens 0.1"}\n<!-- produced by repolens 0.1 -->\n')
        code, output = run(self.root, self.root / "out")
        self.assertEqual(code, 0, output)
        self.assertTrue((self.root / "out/features/README.md").exists())

    @unittest.skipUnless(hasattr(Path, "symlink_to"), "needs symlinks")
    def test_it_never_writes_through_a_symlink(self):
        self.write("app/api/health/route.ts", "export async function GET() { return Response.json({}); }\n")
        elsewhere = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: __import__("shutil").rmtree(elsewhere))
        (self.root / "out").mkdir()
        try:
            (self.root / "out/features").symlink_to(elsewhere, target_is_directory=True)
        except OSError:
            self.skipTest("symlinks unavailable")
        code, output = run(self.root, self.root / "out")
        self.assertEqual(code, 2, output)
        self.assertIn("symlink", output)
        self.assertEqual(list(elsewhere.iterdir()), [])

    def test_a_route_only_test_code_calls_is_neither_a_group_nor_an_unserved_call(self):
        self.write("app/api/health/route.ts", "export async function GET() { return Response.json({}); }\n")
        self.write("tests/gone.test.ts", 'test("gone", async () => { await fetch("/api/gone"); });\n')
        code, output = run(self.root, self.root / "out")
        self.assertEqual(code, 0, output)
        openapi = json.loads((self.root / "out/openapi.json").read_text(encoding="utf-8"))
        self.assertEqual(openapi["x-repolens-unserved-calls"], [])
        self.assertFalse((self.root / "out/features/gone.md").exists())

    @unittest.skipUnless(HAS_STACK, "install repolens[stack]")
    def test_the_schema_is_what_the_migrations_leave(self):
        self.write("db/001_init.sql", (
            "CREATE TABLE owners (id int PRIMARY KEY);\n"
            "CREATE TABLE pets (id int PRIMARY KEY, name text, legacy_code text, owner_id int REFERENCES owners (id),\n"
            "  vet_id int NOT NULL REFERENCES owners (id));\n"
            "CREATE TABLE temp_import (id int);\n"))
        self.write("db/002_change.sql", (
            "ALTER TABLE pets DROP COLUMN legacy_code;\n"
            "ALTER TABLE pets RENAME COLUMN name TO display_name;\n"
            "DROP TABLE temp_import;\n"))
        analysis = analyze(self.root)
        schema, md = generate.build_schema(analysis, self.root)
        self.assertNotIn("legacy_code", schema)
        self.assertNotIn("text name", schema)
        self.assertIn("text display_name", schema)
        self.assertNotIn('"temp_import"', schema)
        self.assertIn("| `temp_import` | dropped in db/002_change.sql |", md)
        # owner_id may be NULL and vet_id may not: zero-or-one parent unless every column is required.
        self.assertRegex(schema, r'e\d+ \}o--o\| e\d+ : "foreign key"')
        self.assertEqual(len(re.findall(r"\}o--", schema)), 1)

    def test_the_architecture_map_stays_under_the_mermaid_edge_limit(self):
        graph = Graph(str(self.root))
        groups = {}
        for g in range(40):
            group = generate.FeatureGroup(f"g{g}", files={f"lib/g{g}.ts": "service"})
            for s in range(20):
                store = f"t{g}_{s}"
                graph.add_node(Node(store, "postgres_table", store))
                group.stores.append(store)
            groups[group.name] = group
        analysis = Analysis(graph, [], Config.load(self.root))
        with mock.patch.object(generate, "MAX_STORES_DRAWN", 800):
            mermaid, _md = generate.build_architecture(analysis, groups, 40)
        self.assertEqual(mermaid.count(" --> "), generate.MAX_EDGES)
        self.assertIn("more edges not drawn", mermaid)

    def test_a_mindmap_section_is_capped(self):
        group = generate.FeatureGroup("big", files={f"lib/f{i}.ts": "service" for i in range(40)})
        with tempfile.TemporaryDirectory() as tmp:
            analysis = Analysis(Graph(tmp), [], Config.load(Path(tmp)))
            md, _context = generate.build_feature(analysis, group)
        mindmap = md.split("```mermaid", 1)[1].split("```", 1)[0]
        self.assertEqual(mindmap.count("lib/f"), generate.MAX_LEAVES)
        self.assertIn("15 more in the tables below", mindmap)
        self.assertEqual(md.count("| lib/f"), 40)

    def test_an_endpoint_an_artifact_declares_is_an_operation_not_an_unserved_call(self):
        artifact = {"routers": [{"file": "backend/items.py", "wired": True,
                                 "routes": [{"method": "GET", "path": "/api/items/{item_id}"}],
                                 "postgres_tables": ["items"]}]}
        self.write("docs/architecture/router_datastore_map.json", json.dumps(artifact))
        self.write("backend/items.py", "def items():\n    return []\n")
        code, output = run(self.root, self.root / "out")
        self.assertEqual(code, 0, output)
        openapi = json.loads((self.root / "out/openapi.json").read_text(encoding="utf-8"))
        self.assertEqual(openapi["x-repolens-unserved-calls"], [])
        operation = openapi["paths"]["/api/items/{item_id}"]["get"]
        self.assertEqual(operation["x-repolens-resolution"], ["declared"])
        self.assertEqual(operation["x-repolens-handler"]["file"], "backend/items.py")
        self.assertIn(generate.DECLARED_HANDLER_GAP, operation["x-repolens-gaps"])
        self.assertIn({"name": "items", "kind": "postgres_table"}, operation["x-repolens-stores"])

    def test_a_call_matched_to_a_served_route_is_listed_on_that_operation(self):
        self.write("app/api/orders/[orderId]/route.ts", "export async function GET() { return Response.json({}); }\n")
        self.write("app/orders/page.tsx", 'export default function Orders() {\n  fetch("/api/orders/42");\n  return null;\n}\n')
        code, output = run(self.root, self.root / "out")
        self.assertEqual(code, 0, output)
        openapi = json.loads((self.root / "out/openapi.json").read_text(encoding="utf-8"))
        self.assertEqual(openapi["x-repolens-unserved-calls"], [])
        self.assertNotIn("/api/orders/42", openapi["paths"])
        self.assertEqual(openapi["paths"]["/api/orders/{orderId}"]["get"]["x-repolens-callers"], ["app/orders/page.tsx:2"])
        page = (self.root / "out/features/orders.md").read_text(encoding="utf-8")
        self.assertNotIn("/api/orders/42", page)

    def test_the_root_is_not_an_output_directory(self):
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            generate.main(["--out", str(self.root)], config=load_config(self.root))

    def test_a_fastapi_model_is_named_not_invented(self):
        self.write("main.py", (
            "from fastapi import FastAPI\n"
            "from pydantic import BaseModel\n"
            "app = FastAPI()\n"
            "class ItemIn(BaseModel):\n"
            "    name: str\n"
            "class ItemOut(BaseModel):\n"
            "    id: int\n"
            "@app.post('/items/{item_id}', response_model=ItemOut)\n"
            "def create(item_id: int, item: ItemIn):\n"
            "    return ItemOut(id=item_id)\n"))
        code, output = run(self.root, self.root / "out")
        self.assertEqual(code, 0, output)
        paths = json.loads((self.root / "out/openapi.json").read_text(encoding="utf-8"))["paths"]
        [path] = [p for p in paths if p.startswith("/items/")]
        operation = paths[path]["post"]
        self.assertEqual(["ItemIn"], [m["symbol"] for m in operation["x-repolens-request-models"]])
        self.assertEqual(["ItemOut"], [m["symbol"] for m in operation["x-repolens-response-models"]])
        self.assertNotIn("requestBody", operation)
        self.assertNotIn("request body", operation["x-repolens-gaps"])
        self.assertNotIn("response schema", operation["x-repolens-gaps"])
        self.assertIn("ItemOut", operation["responses"]["default"]["description"])


if __name__ == "__main__":
    unittest.main()
