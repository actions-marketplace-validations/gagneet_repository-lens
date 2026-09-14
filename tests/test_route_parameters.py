"""Source route parameter names on endpoints and pages, and functions defined inside JS/TS components."""
from __future__ import annotations

import importlib.util
from pathlib import Path
import tempfile
import unittest

from repolens.core import javascript
from repolens.impact.scanner import scan_repository
from repolens.impact.state import route_path_and_parameters
from tests.stack_app import write_example_app

HAS_STACK = javascript.available() and importlib.util.find_spec("sqlglot") is not None


def scan(files: dict[str, str]):
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        for name, text in files.items():
            (root / name).parent.mkdir(parents=True, exist_ok=True)
            (root / name).write_text(text, encoding="utf-8")
        return scan_repository(root)


def spelled(graph, kind: str) -> dict[str, tuple[str | None, list[str] | None]]:
    return {n.label: (n.metadata.get("path"), n.metadata.get("parameters"))
            for n in graph.nodes.values() if n.kind == kind}


class RoutePathTests(unittest.TestCase):
    def test_declared_parameter_spellings_become_openapi_names(self):
        cases = {
            "/api/orders/[orderId]": ("/api/orders/{orderId}", ["orderId"]),
            "/docs/[...slug]": ("/docs/{slug}", ["slug"]),
            "/docs/[[...slug]]": ("/docs/{slug}", ["slug"]),
            "/users/:userId": ("/users/{userId}", ["userId"]),
            "/users/:id?": ("/users/{id}", ["id"]),
            "/notes/:id(\\d+)": ("/notes/{id}", ["id"]),
            "/files/{file_path:path}": ("/files/{file_path}", ["file_path"]),
            "/items/{item_id}.json": ("/items/{item_id}.json", ["item_id"]),
            "/x/:id{[0-9]+}": ("/x/{id}", ["id"]),
            "/range/:from-:to": ("/range/{from}-{to}", ["from", "to"]),
            "/files/:name.:ext": ("/files/{name}.{ext}", ["name", "ext"]),
            "/v1:batch": ("/v1:batch", []),
            "/a/{[0-9]+}": ("/a/{[0-9]+}", []),
            "//a//b/": ("/a/b", []),
            "/": ("/", []),
        }
        for route, expected in cases.items():
            with self.subTest(route=route):
                self.assertEqual(route_path_and_parameters(route), expected)


@unittest.skipUnless(HAS_STACK, "install repolens[stack]")
class EndpointPathTests(unittest.TestCase):
    def test_next_routes_and_pages_keep_their_parameter_names(self):
        graph = scan({
            "package.json": "{}",
            "app/api/orders/[orderId]/route.ts": "export async function GET() { return Response.json({}); }\n",
            "app/api/docs/[...slug]/route.ts": "export async function GET() { return Response.json({}); }\n",
            "app/shop/[[...filters]]/page.tsx": "export default function Shop() { return <p/>; }\n",
            "pages/api/users/[userId].ts": "export default function handler(req, res) { res.json({}); }\n",
        })
        endpoints = spelled(graph, "endpoint")
        self.assertEqual(endpoints["GET /api/orders/{dynamic}"], ("/api/orders/{orderId}", ["orderId"]))
        self.assertEqual(endpoints["GET /api/docs/{dynamic}"], ("/api/docs/{slug}", ["slug"]))
        self.assertEqual(endpoints["ANY /api/users/{dynamic}"], ("/api/users/{userId}", ["userId"]))
        pages = spelled(graph, "page")
        self.assertEqual(pages["/shop/{dynamic}"], ("/shop/{filters}", ["filters"]))
        # The optional catch-all also serves its parent, which has no parameter.
        self.assertEqual(pages["/shop"], ("/shop", []))

    def test_a_listening_express_server_keeps_colon_parameter_names(self):
        graph = scan({
            "server.js": (
                'const express = require("express");\n'
                "const app = express();\n"
                'app.get("/users/:userId", (req, res) => res.json({}));\n'
                "app.listen(3000);\n"
            ),
        })
        self.assertEqual(spelled(graph, "endpoint")["GET /users/{dynamic}"], ("/users/{userId}", ["userId"]))

    def test_two_spellings_of_one_route_keep_the_first_names(self):
        graph = scan({
            "package.json": "{}",
            "app/api/a/[id]/route.ts": "export async function GET() { return Response.json({}); }\n",
            "server.js": (
                'const express = require("express");\n'
                "const app = express();\n"
                'app.get("/api/a/:other", (req, res) => res.json({}));\n'
                "app.listen(3000);\n"
            ),
        })
        # The walk reads a directory's own files before its subdirectories: `server.js` before `app/`.
        self.assertEqual(spelled(graph, "endpoint")["GET /api/a/{dynamic}"], ("/api/a/{other}", ["other"]))

    def test_a_caller_only_endpoint_has_no_declared_path(self):
        graph = scan({"client.ts": 'export const load = () => fetch("/api/missing/42");\n'})
        self.assertTrue(all(path is None for path, _ in spelled(graph, "endpoint").values()))


@unittest.skipUnless(importlib.util.find_spec("sqlglot"), "the stack extra provides sqlglot")
class FastApiPathTests(unittest.TestCase):
    def test_a_prefixed_router_keeps_names_and_drops_converters(self):
        graph = scan({
            "app/main.py": (
                "from fastapi import APIRouter, FastAPI\n"
                "\n"
                'router = APIRouter(prefix="/files/{owner_id}")\n'
                "\n"
                '@router.get("/{file_path:path}")\n'
                "def read_file(owner_id: int, file_path: str):\n"
                "    return {}\n"
                "\n"
                "app = FastAPI()\n"
                "app.include_router(router)\n"
            ),
        })
        endpoints = spelled(graph, "endpoint")
        self.assertEqual(endpoints["GET /files/{dynamic}/{dynamic}"],
                         ("/files/{owner_id}/{file_path}", ["owner_id", "file_path"]))


@unittest.skipUnless(HAS_STACK, "install repolens[stack]")
class ExampleApplicationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.root = Path(cls.tmp.name)
        write_example_app(cls.root)
        from repolens.analysis import analyze
        cls.analysis = analyze(cls.root)
        cls.graph = cls.analysis.graph

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_the_order_route_is_documented_with_its_parameter_name(self):
        self.assertEqual(spelled(self.graph, "endpoint")["GET /api/orders/{dynamic}"],
                         ("/api/orders/{orderId}", ["orderId"]))
        self.assertEqual(spelled(self.graph, "page")["/orders/{dynamic}"], ("/orders/{orderId}", ["orderId"]))

    def test_functions_and_inline_callbacks_are_defined_by_their_component(self):
        nodes = self.graph.nodes
        defines = {(nodes[e.source].label, nodes[e.target].label): e.detail
                   for e in self.graph.edges if e.kind == "DEFINES"}
        self.assertEqual(defines[("OrdersPage", "OrdersPage.load")], "`load` is defined inside `OrdersPage`")
        on_click = next(n for n in nodes.values() if n.kind == "symbol" and n.metadata.get("lexical_role") == "onClick")
        self.assertEqual(defines[("OrdersPage", on_click.label)], "inline `onClick` callback defined inside `OrdersPage`")
        self.assertEqual(next(n.metadata.get("lexical_role") for n in nodes.values()
                              if n.label.startswith("ProductsPage.anonymous@")), "onSubmit")



@unittest.skipUnless(HAS_STACK, "install repolens[stack]")
class DefinesTraversalTests(unittest.TestCase):
    def test_an_endpoint_view_reaches_the_page_not_the_siblings_of_its_callback(self):
        helpers = "".join(f"  const h{i} = () => {i};\n" for i in range(65))
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            files = {
                "package.json": '{"dependencies": {"next": "15.0.0"}}',
                "app/api/save/route.ts": "export async function POST() { return Response.json({}); }\n",
                "app/checkout/page.tsx": (
                    '"use client";\nexport default function Screen() {\n' + helpers
                    + '  return <button onClick={() => fetch("/api/save", { method: "POST" })}>Save</button>;\n}\n'),
            }
            for name, text in files.items():
                (root / name).parent.mkdir(parents=True, exist_ok=True)
                (root / name).write_text(text, encoding="utf-8")
            from repolens.analysis import analyze
            labels = {n.label for n in analyze(root).view("POST /api/save", 30, 6).nodes.values()}
        self.assertIn("/checkout", labels)
        self.assertFalse(any(label.startswith("Screen.h") for label in labels), labels)


@unittest.skipUnless(importlib.util.find_spec("sqlglot"), "the stack extra provides sqlglot")
class ForeignKeyTests(unittest.TestCase):
    def test_foreign_keys_in_application_ddl_link_tables_and_fixtures_declare_nothing(self):
        ddl = "CREATE TABLE parent (id int PRIMARY KEY);\nCREATE TABLE child (parent_id int REFERENCES parent (id));\n"
        graph = scan({"db/schema.sql": ddl, "tests/fixtures/schema.sql": ddl.replace("parent", "fx_parent")
                      .replace("child", "fx_child")})
        edges = {(graph.nodes[e.source].label, graph.nodes[e.target].label) for e in graph.edges if e.kind == "REFERENCES"}
        self.assertEqual(edges, {("child", "parent")})


if __name__ == "__main__":
    unittest.main()
