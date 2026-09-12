from __future__ import annotations

import json
import importlib.util
from pathlib import Path
import tempfile
import unittest

from repolens.core import javascript
from repolens.impact.config import Config
from repolens.impact.scanner import repository_content_sha, scan_repository


STACK = {
    "web/tsconfig.json": '{"compilerOptions": {"baseUrl": ".", "paths": {"@/*": ["src/*"]}}}',
    "web/src/app/items/page.tsx": 'import {submit as send} from "@/client";\nexport const Items = () => { send("1"); return <p>Items</p>; };',
    "web/src/client.ts": 'export function submit(id: string) { return fetch(`/api/items/${id}`, {method: "POST"}); }',
    "backend/app.py": 'from fastapi import FastAPI\nfrom backend.router import router as items\napp=FastAPI()\napp.include_router(items, prefix="/api")\n',
    "backend/router.py": 'from fastapi import APIRouter\nfrom backend.service import save_item as save\nrouter=APIRouter(prefix="/items")\n@router.post("/{item_id}")\nasync def create(item_id: str):\n    return await save(item_id)\n',
    "backend/service.py": 'async def save_item(item_id):\n    return await conn.fetch("SELECT id FROM inventory.items WHERE id = $1", item_id)\n',
}


class Fixture(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.addCleanup(self.tmp.cleanup)

    def write(self, path, text):
        target = self.root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8")
        return target

    def stack(self):
        for path, text in STACK.items():
            self.write(path, text)


class DiscoveryTests(Fixture):
    def test_malformed_impact_config_is_rejected_before_scan(self):
        (self.root / ".impact-tracer.json").write_text('{"max_files": true}', encoding="utf-8")
        with self.assertRaises(ValueError):
            Config.load(self.root)

    def test_artifact_paths_cannot_escape_repository(self):
        (self.root / ".impact-tracer.json").write_text(
            '{"artifacts": {"canonical_owners": "../owners.json"}}', encoding="utf-8"
        )
        with self.assertRaises(ValueError):
            Config.load(self.root)

    def test_oversized_file_is_not_parsed_and_cache_uses_same_input(self):
        self.write("large.py", "def oversized(): pass\n" + "#" * 100)
        self.write("ok.py", "x = 1\n")
        config = Config(max_file_bytes=50)
        graph = scan_repository(self.root, config)
        self.assertFalse(any(n.label == "oversized" for n in graph.nodes.values()))
        self.assertTrue(any(i.code == "FILE_SKIPPED" for i in graph.issues))
        self.assertEqual(graph.metadata["content_sha256"], repository_content_sha(self.root, config))

    def test_generated_outputs_and_symlinks_are_excluded(self):
        self.write(".repolens/analysis/derived.py", "def phantom(): pass")
        self.write("node_modules/pkg/a.py", "def phantom(): pass")
        target = self.write("external.txt", "def outside(): pass")
        try:
            (self.root / "link.py").symlink_to(target)
        except OSError:
            self.skipTest("symlinks unavailable")
        graph = scan_repository(self.root)
        self.assertEqual(len(graph.nodes), 0)

    def test_invalid_utf8_is_reported_instead_of_dropping_bytes(self):
        (self.root / "bad.py").write_bytes(b"def f(): pass\n\xff")
        graph = scan_repository(self.root)
        self.assertEqual(graph.metadata["skipped_file_count"], 1)
        self.assertFalse(any(n.kind == "symbol" for n in graph.nodes.values()))

    def test_ast_cache_is_content_keyed(self):
        from repolens.scan.python_ast import parse
        path = self.write("a.py", "def first(): pass")
        self.assertEqual(parse(str(path)).body[0].name, "first")
        path.write_text("def other(): pass")
        self.assertEqual(parse(str(path)).body[0].name, "other")

    def test_unique_name_is_not_a_resolved_object_call(self):
        self.write("a.py", "def save(): pass")
        self.write("b.py", "def work(client):\n    client.save()")
        graph = scan_repository(self.root)
        self.assertTrue(all(e.resolution != "exact" for e in graph.edges if e.kind == "CALLS"))

    def test_file_limit_is_explicit(self):
        for i in range(3):
            self.write(f"a{i}.py", "x = 1")
        graph = scan_repository(self.root, Config(max_files=2))
        self.assertEqual(graph.metadata["file_count"], 2)
        self.assertIn("SCAN_FILE_LIMIT", {i.code for i in graph.issues})

    def test_query_seed_matches_obey_the_node_limit(self):
        from repolens.impact.query import impact
        self.write("items.py", "\n".join(f"def item_{i}(): pass" for i in range(12)))
        config = Config()
        result = impact(scan_repository(self.root, config), self.root, "item", config, max_nodes=1)
        self.assertEqual(len(result.nodes), 1)

    @unittest.skipUnless(importlib.util.find_spec("sqlglot") and javascript.available(), "install repolens[stack]")
    def test_custom_migration_root_survives_bounded_analysis(self):
        (self.root / "repolens.toml").write_text(
            '[scan.migrations]\nroots = ["db/versions"]\n', encoding="utf-8"
        )
        self.write("db/versions/0001_init.py", f'revision = "{"x" * 33}"\n')
        from repolens.analysis import analyze
        result = analyze(self.root)
        self.assertEqual(result.runs[-1].error, "")
        self.assertIn("migrations/revision-id-too-long", {f.rule for f in result.runs[-1].findings})

    @unittest.skipUnless(importlib.util.find_spec("sqlglot") and javascript.available(), "install repolens[stack]")
    def test_default_alembic_directory_is_checked_by_analysis(self):
        from repolens.analysis import analyze
        self.write("alembic/versions/0001_init.py", f'revision = "{"x" * 33}"\n')
        result = analyze(self.root)
        self.assertIn("migrations/revision-id-too-long", {f.rule for f in result.runs[-1].findings})

    @unittest.skipUnless(importlib.util.find_spec("sqlglot") and javascript.available(), "install repolens[stack]")
    def test_malformed_declared_artifact_marks_analysis_incomplete(self):
        from repolens.analysis import analyze
        self.write("docs/architecture/canonical_owners.json", "{invalid")
        self.assertFalse(analyze(self.root).complete)

    def test_orm_class_argument_links_the_calling_service_to_its_table(self):
        self.write("service.py", "def list_lots(session):\n    return session.query(Lot).all()\n")
        self.write("models.py", 'class Lot(Base):\n    __tablename__ = "lots"\n')
        graph = scan_repository(self.root)
        service = next(n.id for n in graph.nodes.values() if n.label == "list_lots")
        table = next(n.id for n in graph.nodes.values() if n.label == "lots")
        self.assertTrue(any(e.source == service and e.target == table and e.kind == "TOUCHES_STORE" for e in graph.edges))


@unittest.skipUnless(javascript.available(), "install repolens[stack]")
class StackTests(Fixture):
    def test_full_client_router_service_table_chain(self):
        self.stack()
        graph = scan_repository(self.root)
        by_label = {n.label: n.id for n in graph.nodes.values()}
        edges = {(e.source, e.target, e.kind) for e in graph.edges}
        self.assertIn((by_label["Items"], by_label["submit"], "CALLS"), edges)
        endpoint = by_label["POST /api/items/{dynamic}"]
        self.assertIn((by_label["submit"], endpoint, "CALLS_API"), edges)
        self.assertIn((endpoint, by_label["create"], "HANDLES_API"), edges)
        self.assertIn((by_label["create"], by_label["save_item"], "CALLS"), edges)
        self.assertIn((by_label["save_item"], by_label["inventory.items"], "TOUCHES_STORE"), edges)
        self.assertNotIn("API_CALL_WITHOUT_HANDLER", {i.code for i in graph.issues})

    def test_comments_strings_and_outside_function_calls(self):
        self.write("main.ts", '// function fake() {}\nconst text="function imagined() {}";\nfunction one(){ inside(); }\noutside();\nfunction inside(){}\nfunction outside(){}')
        graph = scan_repository(self.root)
        self.assertFalse({"fake", "imagined"} & {n.label for n in graph.nodes.values()})
        outside = next(n.id for n in graph.nodes.values() if n.label == "outside")
        callers = [graph.nodes[e.source] for e in graph.edges if e.kind == "CALLS" and e.target == outside]
        self.assertEqual([n.kind for n in callers], ["file"])

    def test_typed_arrow_tsx_methods_and_default_import(self):
        self.write("main.ts", 'import work from "./lib.js";\nexport const go = async (x: number): Promise<number> => work(x);')
        self.write("lib.ts", 'export default function job(x:number){ return x; }')
        self.write("view.tsx", 'export function View(){ return <div/>; }\nclass A { run(){ return 1; } }')
        graph = scan_repository(self.root)
        self.assertTrue({"go", "job", "View", "A.run"} <= {n.label for n in graph.nodes.values()})
        self.assertTrue(any(e.origin == "import_binding" and graph.nodes[e.target].label == "job" for e in graph.edges))

    def test_next_handler_and_fetch_method_match(self):
        self.write("app/api/items/[id]/route.ts", 'export async function DELETE(){ return new Response(); }')
        self.write("client.ts", 'export function remove(id: string){ return fetch(`/api/items/${id}`, {method:"DELETE"}); }')
        graph = scan_repository(self.root)
        endpoint = next(n for n in graph.nodes.values() if n.label == "DELETE /api/items/{dynamic}")
        self.assertTrue(any(e.target == endpoint.id and e.kind == "CALLS_API" for e in graph.edges))
        self.assertTrue(any(e.source == endpoint.id and e.kind == "HANDLES_API" for e in graph.edges))

    def test_next_handler_exported_through_a_local_export_clause(self):
        self.write("app/api/health/route.ts", 'async function GET(){ return Response.json({ok:true}); }\nexport { GET };')
        graph = scan_repository(self.root)
        self.assertIn("GET /api/health", {n.label for n in graph.nodes.values() if n.kind == "endpoint"})

    def test_two_fastapi_mounts_and_receiver_specific_prefixes(self):
        self.stack()
        self.write("backend/app.py", STACK["backend/app.py"] + 'app.include_router(items, prefix="/v2")\n')
        self.write("backend/router.py", STACK["backend/router.py"] + 'other=APIRouter(prefix="/other")\n@other.get("/all")\ndef separate(): return []\n')
        graph = scan_repository(self.root)
        labels = {n.label for n in graph.nodes.values() if n.kind == "endpoint"}
        self.assertTrue({"POST /api/items/{dynamic}", "POST /v2/items/{dynamic}", "GET /other/all"} <= labels)

    def test_cte_is_not_a_physical_table_and_quotes_are_preserved(self):
        self.write("query.sql", 'WITH recent AS (SELECT * FROM "Sales"."Orders") SELECT * FROM recent JOIN public.users ON true;')
        graph = scan_repository(self.root)
        self.assertEqual({n.label for n in graph.nodes.values() if n.kind == "postgres_table"}, {"Sales.Orders", "public.users"})

    def test_javascript_query_and_dynamic_sql_are_distinguished(self):
        self.write("db.ts", 'export function find(id: string){ return pool.query("select * from inventory.items where id=$1", [id]); }\nexport function unsafe(t: string){ return pool.query(`select * from ${t}`); }')
        graph = scan_repository(self.root)
        self.assertIn("inventory.items", {n.label for n in graph.nodes.values()})
        self.assertIn("DYNAMIC_SQL", {i.code for i in graph.issues})
        self.assertNotIn("dynamic", {n.label for n in graph.nodes.values() if n.kind == "postgres_table"})

    def test_invalid_tsconfig_and_parse_error_are_visible(self):
        self.write("tsconfig.json", '{"extends":"./tsconfig.json"}')
        self.write("bad.ts", 'export const broken = ( => ;')
        graph = scan_repository(self.root)
        self.assertTrue({"IMPORT_CONFIG_ERROR", "JAVASCRIPT_PARSE_ERROR"} <= {i.code for i in graph.issues})

    def test_unresolved_alias_is_reported_and_external_package_is_not_a_local_gap(self):
        self.write("tsconfig.json", '{"compilerOptions":{"paths":{"@/*":["src/*"]}}}')
        self.write("main.ts", 'import x from "@/missing"; import React from "react";')
        graph = scan_repository(self.root)
        gaps = [i for i in graph.issues if i.code == "UNRESOLVED_LOCAL_IMPORT"]
        self.assertEqual(len(gaps), 1)
        self.assertIn("@/missing", gaps[0].message)

    def test_query_on_snapshot_does_not_read_current_source(self):
        from repolens.analysis import analyze
        from unittest.mock import patch
        self.stack()
        result = analyze(self.root)
        with patch.object(Path, "read_text", side_effect=AssertionError("source should not be read")):
            self.assertTrue(result.view("save_item").seeds)
