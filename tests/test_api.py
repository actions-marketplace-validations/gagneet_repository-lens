from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import importlib.util
import json
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch

HAS_API = all(importlib.util.find_spec(module) for module in ("fastapi", "httpx", "tree_sitter", "sqlglot"))


@unittest.skipUnless(HAS_API, "install repolens[stack,api,test]")
class ApiTests(unittest.TestCase):
    def setUp(self):
        from fastapi.testclient import TestClient
        from repolens.api.app import create_app
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        (self.root / "app.py").write_text('def list_items():\n    return 42\n')
        self.token = "unit-test-token-" + "x" * 32
        self.client = TestClient(create_app(self.root, self.token), base_url="http://127.0.0.1")
        self.auth = {"Authorization": "Bearer " + self.token}

    def test_swagger_and_openapi_describe_real_operations_and_bearer_auth(self):
        self.assertEqual(self.client.get("/docs").status_code, 200)
        schema = self.client.get("/openapi.json").json()
        self.assertIn("HTTPBearer", schema["components"]["securitySchemes"])
        self.assertIn("security", schema["paths"]["/v1/analysis"]["post"])
        self.assertIn("AnalysisResponse", schema["components"]["schemas"])
        self.assertNotIn(self.token, json.dumps(schema))
        self.assertNotIn(str(self.root), json.dumps(schema))

    def test_requests_cannot_select_paths_plugins_or_commands(self):
        self.assertEqual(self.client.post("/v1/analysis", json={}).status_code, 401)
        for key in ("root", "repository_url", "plugin", "command"):
            response = self.client.post("/v1/analysis", json={key: "/etc/passwd"}, headers=self.auth)
            self.assertEqual(response.status_code, 422)
        self.assertEqual(self.client.get("/health", headers={"Host": "malicious.example"}).status_code, 400)

    def test_workflow_scan_query_and_all_exports(self):
        self.assertEqual(self.client.get("/v1/analysis", headers=self.auth).status_code, 409)
        result = self.client.post("/v1/analysis", json={}, headers=self.auth)
        self.assertEqual(result.status_code, 200, result.text)
        self.assertTrue(result.json()["complete"])
        self.assertNotIn(str(self.root), result.text)
        query = self.client.post("/v1/impact", json={"query": "list_items"}, headers=self.auth)
        self.assertEqual(query.status_code, 200, query.text)
        self.assertTrue(query.json()["seeds"])
        for kind, start in (("mermaid", "flowchart TD"), ("markdown", "# Repository Lens"), ("sarif", "{")):
            response = self.client.get("/v1/report", params={"format": kind}, headers=self.auth)
            self.assertEqual(response.status_code, 200)
            self.assertTrue(response.text.startswith(start))

    def test_second_scan_reads_changed_code_and_reports_incomplete_input(self):
        first = self.client.post("/v1/analysis", json={}, headers=self.auth).json()
        (self.root / "app.py").write_text("def replacement(): pass\n")
        second = self.client.post("/v1/analysis", json={}, headers=self.auth).json()
        self.assertNotEqual(first["graph"]["metadata"]["content_sha256"], second["graph"]["metadata"]["content_sha256"])
        third = self.client.post("/v1/analysis", json={"max_file_bytes": 5}, headers=self.auth).json()
        self.assertFalse(third["complete"])
        self.assertTrue(any(i["code"] == "FILE_SKIPPED" for i in third["graph"]["issues"]))

    def test_scan_uses_repository_impact_policy_before_request_bounds(self):
        (self.root / "repolens.toml").write_text(
            '[impact]\nbackend_api_prefix = "/configured"\n', encoding="utf-8"
        )
        (self.root / "api.py").write_text(
            'from fastapi import APIRouter\nrouter = APIRouter()\n'
            '@router.get("/items")\ndef list_items():\n    return []\n', encoding="utf-8"
        )
        result = self.client.post("/v1/analysis", json={}, headers=self.auth)
        self.assertEqual(result.status_code, 200, result.text)
        self.assertIn("GET /configured/items", {n["label"] for n in result.json()["graph"]["nodes"]})

    def test_concurrent_scan_rejected_while_health_stays_available(self):
        from repolens.analysis import analyze
        started, finish = threading.Event(), threading.Event()
        def slow(root, **kwargs):
            started.set()
            if not finish.wait(5):
                raise RuntimeError("test coordination timeout")
            return analyze(root, **kwargs)
        with patch("repolens.api.app.analyze", side_effect=slow), ThreadPoolExecutor(max_workers=2) as pool:
            pending = pool.submit(self.client.post, "/v1/analysis", json={}, headers=self.auth)
            try:
                self.assertTrue(started.wait(3))
                self.assertEqual(self.client.get("/health").status_code, 200)
                self.assertEqual(self.client.get("/v1/analysis", headers=self.auth).status_code, 409)
                self.assertEqual(self.client.post("/v1/analysis", json={}, headers=self.auth).status_code, 409)
            finally:
                finish.set()
            self.assertEqual(pending.result().status_code, 200)

    def test_generated_postman_requests_work_in_order(self):
        from repolens.api.export import contracts
        schema, collection, environment = contracts()
        endpoint_count = sum(method in {"get", "post", "put", "patch", "delete"}
                             for methods in schema["paths"].values() for method in methods)
        self.assertEqual(len(collection["item"]), endpoint_count)
        for item in collection["item"]:
            request = item["request"]
            payload = json.loads(request["body"]["raw"]) if "body" in request else None
            response = self.client.request(request["method"], request["url"].replace("{{base_url}}", ""),
                                           json=payload, headers=self.auth)
            self.assertEqual(response.status_code, 200, item["name"] + response.text)
        self.assertEqual(next(v["value"] for v in environment["values"] if v["key"] == "api_token"), "")
