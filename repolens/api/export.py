"""Export reviewable API contracts from the same application used by `serve`."""
from __future__ import annotations

import argparse
import json
from pathlib import Path


def contracts(root: Path | None = None) -> tuple[dict, dict, dict]:
    """The OpenAPI schema, Postman collection and Postman environment for the API."""
    from .app import create_app
    # Contract generation never starts a server or scans the current directory.
    schema = create_app((root or Path.cwd()).resolve(), "contract-generation-only-" + "0" * 32).openapi()
    items = []
    order = {"health": 0, "capabilities": 1, "scan_repository": 2, "get_analysis": 3,
             "query_impact": 4, "export_report": 5}
    operations = [(path, method, operation) for path, methods in schema["paths"].items()
                  for method, operation in methods.items() if method in {"get", "post", "put", "delete", "patch"}]
    for path, method, operation in sorted(operations, key=lambda row: order[row[2]["operationId"]]):
        request = {"method": method.upper(), "header": [], "url": "{{base_url}}" + path,
                   "description": operation.get("description", "")}
        if not operation.get("security"):
            request["auth"] = {"type": "noauth"}
        if method == "post":
            example = ({"query": "list_items", "max_nodes": 30, "depth": 6} if operation["operationId"] == "query_impact"
                       else {"max_file_bytes": 2000000, "max_files": 10000})
            request["header"] = [{"key": "Content-Type", "value": "application/json"}]
            request["body"] = {"mode": "raw", "raw": json.dumps(example, indent=2),
                               "options": {"raw": {"language": "json"}}}
        if operation["operationId"] == "export_report":
            request["url"] += "?format=mermaid&max_nodes=30&depth=6"
        items.append({"name": operation.get("summary", operation["operationId"]), "request": request,
                      "event": [{"listen": "test", "script": {"type": "text/javascript", "exec": [
                          "pm.test('Request succeeds', function () { pm.response.to.have.status(200); });"
                      ]}}]})
    collection = {"info": {"name": "Repository Lens API", "description": "Start repolens serve, set base_url and api_token in the environment, then run requests in order. No source path or credential is embedded.",
                           "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"},
                  "auth": {"type": "bearer", "bearer": [{"key": "token", "value": "{{api_token}}", "type": "string"}]},
                  "item": items}
    environment = {"name": "Repository Lens local", "values": [
        {"key": "base_url", "value": "http://127.0.0.1:8765", "enabled": True, "type": "default"},
        {"key": "api_token", "value": "", "enabled": True, "type": "secret"}], "_postman_variable_scope": "environment"}
    return schema, collection, environment


def main(argv=None, *, config=None, prog=None) -> int:
    """Write the three contract documents under `--out` (relative to the repository root)."""
    parser = argparse.ArgumentParser(prog=prog, description=__doc__)
    parser.add_argument("--out", type=Path, default=Path("docs/api"))
    args = parser.parse_args(argv)
    root = config.root if config else Path.cwd()
    out = args.out if args.out.is_absolute() else root / args.out
    try:
        documents = contracts(root)
    except ImportError:
        parser.error("install the API dependencies: pip install 'repolens[api]'")
    out.mkdir(parents=True, exist_ok=True)
    for name, document in zip(("openapi.json", "repository-lens.postman_collection.json", "local.postman_environment.json"), documents):
        (out / name).write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote OpenAPI and Postman contracts to {out}")
    return 0
