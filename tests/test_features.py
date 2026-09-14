"""Feature groups built from the evidence graph: the grouping both generated docs and proposed markers use."""
from __future__ import annotations

import importlib.util
from pathlib import Path
import tempfile
import unittest

from repolens.core import javascript
from repolens.impact.features import feature_groups, group_name

STACK = javascript.available() and importlib.util.find_spec("sqlglot") is not None


class GroupNameTests(unittest.TestCase):
    def test_the_first_static_segment_names_the_group(self):
        self.assertEqual(group_name("/api/v1/orders/{orderId}", page=False), "orders")
        self.assertEqual(group_name("/api/[slug]/items", page=False), "items")
        self.assertEqual(group_name("/Order_Items/:id", page=True), "order-items")
        self.assertEqual(group_name("/", page=True), "home")
        self.assertEqual(group_name("/api/{dynamic}", page=False), "api")


@unittest.skipUnless(STACK, "requires repolens[stack]")
class FeatureGroupTests(unittest.TestCase):
    def setUp(self):
        from repolens.impact.scanner import scan_repository
        from tests.stack_app import write_example_app

        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        write_example_app(root)
        (root / "tests").mkdir()
        (root / "tests/orders.test.ts").write_text('test("lists", async () => { await fetch("/api/orders"); });\n',
                                                   encoding="utf-8")
        self.graph = scan_repository(root)
        self.groups = feature_groups(self.graph)

    def labels(self, ids):
        return sorted(self.graph.nodes[node].label for node in ids)

    def test_route_areas_collect_their_pages_code_and_stores_by_layer(self):
        self.assertEqual(sorted(self.groups), ["orders", "products", "reviews"])
        orders = self.groups["orders"]
        self.assertEqual(orders.files, {
            "app/orders/page.tsx": "frontend",
            "app/orders/[orderId]/page.tsx": "frontend",
            "app/api/orders/route.ts": "router",
            "app/api/orders/[orderId]/route.ts": "router",
            "lib/orders.ts": "service",
            "db/schema.sql": "model",
        })
        self.assertEqual(self.labels(orders.stores), ["orders"])
        self.assertEqual(self.labels(self.groups["reviews"].stores), ["reviews"])
        self.assertEqual(self.groups["reviews"].files, {"app/api/reviews/route.ts": "router"})

    def test_a_page_calls_another_area_through_an_inline_callback(self):
        # The POST sits in an anonymous `onSubmit` arrow inside the page component.
        self.assertEqual(self.labels(self.groups["products"].calls_out), ["POST /api/reviews"])

    def test_a_name_only_call_is_not_followed_to_another_files_store(self):
        from repolens.impact.features import reach
        from repolens.impact.model import Edge, Graph, Node

        graph = Graph("/")
        for node_id in ("handler", "helper", "maybe"):
            graph.add_node(Node(node_id, "symbol", node_id))
        graph.add_edge(Edge("handler", "helper", "CALLS", "high", "a.py:1"))
        graph.add_edge(Edge("handler", "maybe", "CALLS", "probable", "a.py:2"))
        outgoing = {"handler": list(graph.edges)}
        self.assertEqual(reach(outgoing, "handler", 4), {"handler", "helper"})

    def test_a_call_matched_to_a_served_route_leaves_no_placeholder_group(self):
        from repolens.impact.features import edge_index, endpoint_status

        statuses = endpoint_status(self.graph, *edge_index(self.graph))
        by_label = {self.graph.nodes[node].label: status for node, status in statuses.items()}
        self.assertEqual(by_label["GET /api/orders"], "served")
        self.assertEqual(by_label["POST /api/reviews"], "unserved")
        matched = [label for label, status in by_label.items() if status == "matched"]
        self.assertTrue(all(not any(label in self.labels(g.endpoints) for g in self.groups.values()) for label in matched))

    def test_a_url_too_open_to_link_is_neither_a_group_endpoint_nor_unserved(self):
        from repolens.impact.features import edge_index, endpoint_status
        from repolens.impact.model import Edge, Graph, Node

        graph = Graph("/")
        graph.add_node(Node("page", "symbol", "Page", path="app/page.tsx", language="typescript"))
        graph.add_node(Node("wrapper", "endpoint", "GET /api/{dynamic}",
                            metadata={"method": "GET", "route": "/api/{dynamic}", "matched_handler_count": 40}))
        graph.add_edge(Edge("page", "wrapper", "CALLS_API", "probable", "app/page.tsx:3"))
        self.assertEqual(endpoint_status(graph, *edge_index(graph)), {"wrapper": "open"})
        self.assertEqual(feature_groups(graph), {})

    def test_a_route_only_test_code_calls_is_not_a_group(self):
        from repolens.impact.features import edge_index, endpoint_status
        from repolens.impact.model import Edge, Graph, Node

        graph = Graph("/")
        graph.add_node(Node("spec", "symbol", "spec", path="tests/gone.test.ts", language="typescript"))
        graph.add_node(Node("gone", "endpoint", "GET /api/gone", metadata={"method": "GET", "route": "/api/gone"}))
        graph.add_edge(Edge("spec", "gone", "CALLS_API", "exact", "tests/gone.test.ts:1"))
        self.assertEqual(endpoint_status(graph, *edge_index(graph)), {"gone": "uncalled"})
        self.assertEqual(feature_groups(graph), {})

    def test_stores_an_artifact_router_reads_belong_to_its_group(self):
        from repolens.impact.model import Edge, Graph, Node

        graph = Graph("/")
        graph.add_node(Node("ep", "endpoint", "GET /api/events", metadata={"method": "GET", "route": "/api/events"}))
        graph.add_node(Node("router", "file", "backend/events.py", path="backend/events.py"))
        graph.add_node(Node("events", "mongo_collection", "events"))
        graph.add_edge(Edge("ep", "router", "IMPLEMENTED_BY", "declared", "docs/map.json"))
        graph.add_edge(Edge("router", "events", "READS_STORE", "declared", "docs/map.json"))
        [events] = feature_groups(graph).values()
        self.assertEqual(events.stores, ["events"])
        self.assertEqual(events.files, {"backend/events.py": "router"})

    def test_test_code_is_never_a_group_file(self):
        self.assertFalse(any(path.startswith("tests/") for g in self.groups.values() for path in g.files))


if __name__ == "__main__":
    unittest.main()
