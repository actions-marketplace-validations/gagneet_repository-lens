"""Python evidence-graph regressions: routes, mounts, dependencies, models and stores."""
from __future__ import annotations

import importlib.util
from pathlib import Path
import tempfile
import textwrap
import unittest
import warnings

from repolens.impact.model import Graph
from repolens.impact.scanner import scan_repository


def scan(files: dict[str, str]) -> Graph:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        for rel, body in files.items():
            path = root / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(textwrap.dedent(body).lstrip("\n"), encoding="utf-8")
        return scan_repository(root)


def labelled(graph: Graph, kind: str) -> set[tuple[str, str]]:
    return {(graph.nodes[e.source].label, graph.nodes[e.target].label)
            for e in graph.edges if e.kind == kind}


def edges(graph: Graph, kind: str) -> list[tuple[str, str, str, str | None]]:
    return [(graph.nodes[e.source].label, graph.nodes[e.target].label, e.resolution, e.detail)
            for e in graph.edges if e.kind == kind]


def endpoints(graph: Graph) -> dict[str, dict]:
    return {n.label: n.metadata for n in graph.nodes.values() if n.kind == "endpoint"}


def stores(graph: Graph, store_kind: str) -> list[tuple[str, str, str, str | None]]:
    return [(graph.nodes[e.source].label, graph.nodes[e.target].label, e.resolution, e.detail)
            for e in graph.edges
            if e.kind == "TOUCHES_STORE" and graph.nodes[e.target].kind == store_kind]


def codes(graph: Graph) -> list[str]:
    return [issue.code for issue in graph.issues]


class RouteDecoratorTests(unittest.TestCase):
    def test_a_route_decorator_is_not_a_call_the_handler_makes(self):
        graph = scan({
            "crud.py": "class CRUDBase:\n    def get(self, db, id):\n        return db\n",
            "routes.py": """
                from fastapi import APIRouter
                router = APIRouter()
                def compute_default():
                    return 1
                @router.get("/items")
                def read_items(limit: int = compute_default()):
                    return []
            """,
        })
        calls = labelled(graph, "CALLS")
        self.assertFalse({pair for pair in calls if pair[1] == "CRUDBase.get"})
        # A default is evaluated where the `def` runs: the module, not the handler.
        self.assertIn(("routes.py", "compute_default"), calls)
        self.assertNotIn(("read_items", "compute_default"), calls)


class DependencyTests(unittest.TestCase):
    def test_dependencies_from_defaults_aliases_decorators_and_routers(self):
        graph = scan({
            "deps.py": """
                from typing import Annotated
                from fastapi import Depends
                def get_db():
                    yield 1
                def get_current_user(db=Depends(get_db)):
                    return 1
                def audit():
                    return 1
                def tenant():
                    return 1
                CurrentUser = Annotated[dict, Depends(get_current_user)]
            """,
            "routes.py": """
                from typing import Annotated
                from fastapi import APIRouter, Depends, Security
                from deps import CurrentUser, audit, get_db, tenant
                def verify():
                    return 1
                router = APIRouter(dependencies=[Depends(tenant)])
                LocalDb = Annotated[object, Depends(get_db)]
                @router.get("/a", dependencies=[Depends(audit)])
                def a(user: CurrentUser, db: LocalDb, v: Annotated[int, Security(verify)]):
                    return 1
            """,
            "main.py": "from fastapi import FastAPI\nfrom routes import router\napp = FastAPI()\napp.include_router(router)\n",
        })
        self.assertEqual(set(endpoints(graph)["GET /a"]["dependencies"]),
                         {"tenant", "audit", "get_current_user", "get_db", "verify"})
        calls = labelled(graph, "CALLS")
        for target in ("tenant", "audit", "get_current_user", "get_db", "verify"):
            self.assertIn(("a", target), calls)
        # A dependency's own dependency is part of the chain impact must cross.
        self.assertIn(("get_current_user", "get_db"), calls)
        imported_alias = [e for e in edges(graph, "CALLS") if e[:2] == ("a", "get_current_user")]
        self.assertEqual(imported_alias[0][2], "high")


class RouteDeclarationTests(unittest.TestCase):
    def test_api_route_add_api_route_websocket_and_keyword_paths(self):
        graph = scan({
            "handlers.py": "def health():\n    return 1\n",
            "main.py": """
                from fastapi import APIRouter, FastAPI
                from handlers import health
                app = FastAPI()
                router = APIRouter(prefix="/r")
                @router.api_route("/multi", methods=["POST", "PUT"])
                def multi():
                    return 1
                @router.api_route("/default")
                def default_get():
                    return 1
                def plain():
                    return 1
                router.add_api_route("/added", plain, methods=["DELETE"])
                def register():
                    router.add_api_route("/inner", plain)
                app.add_api_route("/health", health)
                @app.websocket("/ws")
                async def ws(websocket):
                    return 1
                @router.post(path="/kwpath")
                def kw():
                    return 1
                METHODS = compute()
                @router.api_route("/dyn", methods=METHODS)
                def dynamic_methods():
                    return 1
                @router.get(build_path())
                def dynamic_path():
                    return 1
                app.include_router(router)
            """,
        })
        self.assertEqual(set(endpoints(graph)), {
            "POST /r/multi", "PUT /r/multi", "GET /r/default", "DELETE /r/added", "GET /r/inner",
            "GET /health", "WEBSOCKET /ws", "POST /r/kwpath",
        })
        handles = labelled(graph, "HANDLES_API")
        self.assertIn(("GET /health", "health"), handles)
        self.assertIn(("GET /r/inner", "plain"), handles)
        dynamic = [i for i in graph.issues if i.code == "DYNAMIC_ROUTE_DECLARATION"]
        self.assertEqual(len(dynamic), 2)
        self.assertEqual({i.severity for i in dynamic}, {"info"})


class ImportIndexTests(unittest.TestCase):
    def test_candidates_resolve_against_the_admitted_inventory_without_the_filesystem(self):
        from unittest import mock
        from repolens.impact.resolution import ImportIndex
        root = Path(tempfile.mkdtemp())
        self.addCleanup(__import__("shutil").rmtree, root, ignore_errors=True)
        files = [root / "app" / "__init__.py", root / "app" / "models.py", root / "web" / "lib" / "api.ts"]
        for path in files:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("", encoding="utf-8")
        (root / "outside.py").write_text("", encoding="utf-8")  # on disk, but not admitted
        index = ImportIndex(root, files, 1000)
        with mock.patch.object(Path, "resolve", side_effect=AssertionError("filesystem consulted")):
            self.assertEqual(index.python("app/views.py", "models", 1), "app/models.py")
            self.assertEqual(index.python("app/views.py", "app.models"), "app/models.py")
            self.assertEqual(index.javascript("web/page.ts", "./lib/api"), ("web/lib/api.ts", True))
            self.assertIsNone(index.python("app/views.py", "outside"))
            self.assertIsNone(index.python("app/views.py", "..outside", 1))


class MountTests(unittest.TestCase):
    def test_a_router_built_from_an_aliased_import_is_mounted(self):
        graph = scan({
            "routers/accounts.py": """
                from fastapi import APIRouter as _APIRouter
                _listing = _APIRouter()
                @_listing.get("/accounts/visible")
                def visible():
                    return []
            """,
            "main.py": """
                from fastapi import FastAPI
                from routers.accounts import _listing
                app = FastAPI()
                app.include_router(_listing, prefix="/api")
            """,
        })
        self.assertIn("GET /api/accounts/visible", endpoints(graph))
        self.assertNotIn("UNRESOLVED_ROUTER_MOUNT", codes(graph))

    def test_an_aliased_router_import_survives_a_local_file_named_like_the_framework(self):
        # A vendored tool's `fastapi.py` makes `from fastapi import ...` look local, which
        # leaves the import unbound; the alias must still construct a router.
        graph = scan({
            "tools/vendored/analyzer/fastapi.py": "def describe():\n    return None\n",
            "routers/accounts.py": """
                from fastapi import APIRouter as _APIRouter
                _listing = _APIRouter()
                @_listing.get("/accounts/visible")
                def visible():
                    return []
            """,
            "main.py": """
                from fastapi import FastAPI
                from routers.accounts import _listing
                app = FastAPI()
                try:
                    app.include_router(_listing, prefix="/api")
                except ImportError:
                    pass
            """,
        })
        self.assertIn("GET /api/accounts/visible", endpoints(graph))
        self.assertNotIn("UNRESOLVED_ROUTER_MOUNT", codes(graph))

    def test_a_string_annotation_with_an_invalid_escape_prints_no_warning(self):
        # "error" would turn the warning into a SyntaxError the scanner already catches.
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            graph = scan({"main.py": '''
                from fastapi import FastAPI
                app = FastAPI()
                @app.get("/items")
                def items(q: "Annotated[str, '\\d']" = ""):
                    return q
            '''})
        self.assertEqual([str(w.message) for w in caught if issubclass(w.category, SyntaxWarning)], [])
        self.assertIn("GET /items", endpoints(graph))

    def test_a_mounted_sub_application_serves_routes_under_the_mount_path(self):
        graph = scan({"main.py": """
            from fastapi import FastAPI
            from fastapi.staticfiles import StaticFiles
            app = FastAPI()
            sub = FastAPI()
            @sub.get("/ping")
            def ping():
                return 1
            app.mount("/sub", sub)
            app.mount("/static", StaticFiles(directory="static"))
        """})
        self.assertEqual(set(endpoints(graph)), {"GET /sub/ping"})
        self.assertNotIn("UNRESOLVED_ROUTER_MOUNT", codes(graph))

    def test_settings_and_constant_prefixes_resolve_through_imports(self):
        graph = scan({
            "app/__init__.py": "",
            "app/core/__init__.py": "",
            "app/core/config.py": """
                from pydantic_settings import BaseSettings
                class Settings(BaseSettings):
                    API_V1_STR: str = "/api/v1"
                settings = Settings()
            """,
            "app/constants.py": 'PREFIX = "/v2"\n',
            "app/routes.py": """
                from fastapi import APIRouter
                api_router = APIRouter()
                other = APIRouter()
                @api_router.get("/items")
                def items():
                    return []
                @other.get("/things")
                def things():
                    return []
            """,
            "app/main.py": """
                from fastapi import FastAPI
                from app.constants import PREFIX
                from app.core.config import settings
                from app.routes import api_router, other
                app = FastAPI()
                app.include_router(api_router, prefix=settings.API_V1_STR)
                app.include_router(other, prefix=PREFIX + "/x")
            """,
        })
        self.assertEqual(set(endpoints(graph)), {"GET /api/v1/items", "GET /v2/x/things"})

    def test_an_unresolvable_prefix_is_reported_and_its_routes_still_register(self):
        graph = scan({"main.py": """
            import os
            from fastapi import APIRouter, FastAPI
            app = FastAPI()
            router = APIRouter()
            @router.get("/items")
            def items():
                return []
            app.include_router(router, prefix=os.environ["API_PREFIX"])
        """})
        self.assertEqual(set(endpoints(graph)), {"GET /items"})
        [issue] = [i for i in graph.issues if i.code == "DYNAMIC_ROUTER_PREFIX"]
        self.assertEqual(issue.severity, "info")
        self.assertIn('os.environ["API_PREFIX"]'.replace('"', "'"), issue.message.replace('"', "'"))
        self.assertNotIn("UNRESOLVED_ROUTER_MOUNT", codes(graph))

    def test_factories_loops_try_imports_and_router_subclasses(self):
        graph = scan({
            "app/__init__.py": "",
            "app/base.py": "from fastapi import APIRouter\nclass MyRouter(APIRouter):\n    pass\n",
            "app/factory.py": "from fastapi import FastAPI\ndef get_application():\n    return FastAPI(title='x')\n",
            "app/routes/__init__.py": "",
            "app/routes/a.py": "from fastapi import APIRouter\nrouter = APIRouter()\n@router.get('/a')\ndef ra():\n    pass\n",
            "app/routes/b.py": "from app.base import MyRouter\nrouter = MyRouter(prefix='/bb')\n@router.get('/b')\ndef rb():\n    pass\n",
            "app/routes/c.py": "from fastapi import APIRouter\nrouter = APIRouter()\n@router.get('/c')\ndef rc():\n    pass\n",
            "app/routes/d.py": "from fastapi import APIRouter\nrouter = APIRouter()\n@router.get('/d')\ndef rd():\n    pass\n",
            "app/main.py": """
                from fastapi import FastAPI
                from app.factory import get_application
                from app.routes import a, b, d
                try:
                    from app.routes import c
                except ImportError:
                    c = None
                def create_app():
                    app = FastAPI()
                    for mod in (a, b):
                        app.include_router(mod.router, prefix="/x")
                    return app
                app = create_app()
                app.include_router(c.router, prefix="/c")
                public = get_application()
                public.include_router(d.router, prefix="/public")
            """,
            "app/plugins.py": "from app.routes import a\ndef register(app):\n    app.include_router(a.router)\n",
        })
        self.assertEqual(set(endpoints(graph)), {"GET /x/a", "GET /x/bb/b", "GET /c/c", "GET /public/d"})
        # Only the include on a function parameter is truly unresolved.
        self.assertEqual([i.evidence for i in graph.issues if i.code == "UNRESOLVED_ROUTER_MOUNT"],
                         ["app/plugins.py:3"])


class ImportResolutionTests(unittest.TestCase):
    def test_monorepo_absolute_import_uses_the_files_own_package_root(self):
        graph = scan({
            "services/api/app/__init__.py": "",
            "services/api/app/routes/__init__.py": "",
            "services/api/app/routes/items.py": "from app.services.items import create_item\ndef post_item():\n    return create_item()\n",
            "services/api/app/services/__init__.py": "",
            "services/api/app/services/items.py": "def create_item():\n    return 1\n",
            "services/worker/app/__init__.py": "",
            "services/worker/app/services/__init__.py": "",
            "services/worker/app/services/items.py": "def create_item():\n    return 2\n",
        })
        [call] = [e for e in graph.edges if e.kind == "CALLS" and graph.nodes[e.source].label == "post_item"]
        self.assertEqual(graph.nodes[call.target].path, "services/api/app/services/items.py")
        self.assertEqual(call.resolution, "high")

    def test_a_standard_library_import_is_not_name_matched_to_a_local_function(self):
        graph = scan({
            "utils.py": "def loads(text):\n    return text\ndef join(*parts):\n    return parts\n",
            "svc.py": "import json\nfrom os.path import join\ndef parse(text):\n    return json.loads(join(text))\n",
        })
        self.assertFalse({pair for pair in labelled(graph, "CALLS") if pair[0] == "parse"})
        self.assertFalse([n for n in graph.nodes.values() if n.label.startswith("external:")])


class OrmTests(unittest.TestCase):
    def test_a_reference_follows_the_import_not_the_class_name(self):
        graph = scan({
            "models.py": "class User(Base):\n    __tablename__ = 'users'\n",
            "legacy/models.py": "class User(Base):\n    __tablename__ = 'legacy_users'\n",
            "schemas.py": "from pydantic import BaseModel\nclass User(BaseModel):\n    name: str\n",
            "svc.py": "from sqlalchemy import select\nfrom models import User\ndef list_users(session):\n    return session.execute(select(User)).all()\n",
            "api.py": "from schemas import User\ndef to_public(data):\n    return User(name=data)\n",
            "guess.py": "def anything(session):\n    return session.query(User).all()\n",
            "local.py": "User = 3\ndef show():\n    print(User)\ndef shadow(session):\n    User = 4\n    session.add(User)\n",
        })
        found = stores(graph, "postgres_table")
        by_source = {}
        for source, table, resolution, _detail in found:
            by_source.setdefault(source, set()).add((table, resolution))
        self.assertEqual(by_source["list_users"], {("users", "high")})
        self.assertEqual(by_source["anything"], {("users", "ambiguous"), ("legacy_users", "ambiguous")})
        for source in ("to_public", "show", "shadow"):
            self.assertNotIn(source, by_source)
        [detail] = [d for s, _, _, d in found if s == "list_users"]
        self.assertIn("(reads)", detail)

    def test_table_sqlmodel_declared_tables_and_foreign_keys(self):
        graph = scan({
            "models.py": """
                from sqlalchemy import Column, ForeignKey, Integer, MetaData, Table
                from sqlalchemy.orm import DeclarativeBase, mapped_column
                from sqlmodel import Field, SQLModel
                metadata = MetaData()
                class Base(DeclarativeBase):
                    pass
                class User(Base):
                    __tablename__ = "users"
                    __table_args__ = ({"schema": "auth"},)
                class Order(Base):
                    __tablename__ = "orders"
                    user_id = mapped_column(ForeignKey("auth.users.id"))
                tags = Table("tags", metadata, Column("id", Integer), schema="meta")
                class Hero(SQLModel, table=True):
                    id: int = Field(primary_key=True)
                class Named(SQLModel, table=True):
                    __tablename__ = "named_heroes"
                class HeroCreate(SQLModel):
                    name: str
                class Declared(Base):
                    __table__ = Table("declared_tbl", metadata)
            """,
            "svc.py": """
                from sqlalchemy import insert, select
                from models import Hero, Order, tags
                def add_tag(conn):
                    conn.execute(tags.insert())
                def read_tags(conn):
                    return conn.execute(select(tags)).all()
                def heroes(session):
                    return session.exec(select(Hero)).all()
                def add_order(session):
                    session.execute(insert(Order).values(user_id=1))
            """,
        })
        declared = {(s, t) for s, t, _, d in stores(graph, "postgres_table") if d and "declares" in d}
        self.assertTrue({("models.py", "meta.tags"), ("Hero", "hero"), ("Named", "named_heroes"),
                         ("Declared", "declared_tbl"), ("User", "auth.users"), ("Order", "orders")} <= declared)
        self.assertNotIn("HeroCreate", {s for s, _ in declared})
        uses = {(s, t, d.split("(")[1].split(")")[0]) for s, t, _, d in stores(graph, "postgres_table")
                if d and d.startswith("ORM class reference")}
        self.assertTrue({("add_tag", "meta.tags", "writes"), ("read_tags", "meta.tags", "reads"),
                         ("heroes", "hero", "reads"), ("add_order", "orders", "writes")} <= uses)
        self.assertIn(("orders", "auth.users", "exact", "foreign key"), edges(graph, "REFERENCES"))


class MongoTests(unittest.TestCase):
    def test_a_sqlalchemy_session_named_db_is_not_a_collection(self):
        graph = scan({"deps.py": """
            def get_user(db, user_id):
                obj = db.query(User).filter(User.id == user_id).first()
                db.add(obj)
                db.commit()
                db.refresh(obj)
                db.session.add(obj)
                return obj
        """})
        self.assertFalse([n for n in graph.nodes.values() if n.kind == "mongo_collection"])

    def test_driver_calls_through_clients_aliases_and_pipelines(self):
        graph = scan({
            "repo.py": """
                from motor.motor_asyncio import AsyncIOMotorClient
                client = AsyncIOMotorClient()
                async def a():
                    return await db.items.find_one({})
                async def b():
                    return await db["orders"].insert_one({})
                async def c():
                    return await db.get_collection("carts").find({})
                async def d():
                    return await client.appdb.invoices.find({})
                async def e():
                    collection = db.payments
                    await collection.insert_one({})
                async def f():
                    await db.items.aggregate([{"$lookup": {"from": "reviews", "localField": "a"}}])
                async def g():
                    return await client["appdb"]["refunds"].find({})
                db = client.appdb
            """,
            "plain.py": "def listing(db):\n    return db.things.find({})\n",
            "service.py": """
                from pymongo import MongoClient
                class Repository:
                    def __init__(self):
                        self.client = MongoClient()
                        self.database = self.client.shop
                    def list(self):
                        return self.database.baskets.find({})
            """,
        })
        found = {(s, t, r, d) for s, t, r, d in stores(graph, "mongo_collection")}
        self.assertTrue({
            ("a", "items", "high", "MongoDB driver call (reads)"),
            ("b", "orders", "high", "MongoDB driver call (writes)"),
            ("c", "carts", "high", "MongoDB driver call (reads)"),
            ("d", "invoices", "high", "MongoDB driver call (reads)"),
            ("e", "payments", "high", "MongoDB driver call (writes)"),
            ("g", "refunds", "high", "MongoDB driver call (reads)"),
            ("listing", "things", "probable", "MongoDB driver call (reads)"),
            ("Repository.list", "baskets", "high", "MongoDB driver call (reads)"),
        } <= found)
        self.assertIn(("f", "reviews"), {(s, t) for s, t, _, _ in found})
        self.assertNotIn("appdb", {t for _, t, _, _ in found})

    def test_odm_models_declare_collections_and_references_read_or_write(self):
        graph = scan({"models.py": """
            from beanie import Document
            from mongoengine import Document as MEDocument
            from odmantic import Model
            class Product(Document):
                name: str
                class Settings:
                    name = "products"
            class Review(Document):
                text: str
            class Page(MEDocument):
                meta = {"collection": "pages"}
            class BlogPost(MEDocument):
                pass
            class Car(Model):
                model_config = {"collection": "cars"}
            async def list_products():
                return await Product.find_all().to_list()
            async def add_product():
                await Product(name="x").insert()
            async def one(pid):
                return await Product.get(pid)
        """})
        found = stores(graph, "mongo_collection")
        declared = {(s, t, r) for s, t, r, d in found if d and "declares" in d}
        self.assertEqual(declared, {("Product", "products", "exact"), ("Review", "Review", "probable"),
                                    ("Page", "pages", "exact"), ("BlogPost", "blog_post", "probable"),
                                    ("Car", "cars", "exact")})
        uses = {(s, t, d.split("(")[1].split(")")[0]) for s, t, _, d in found if d and d.startswith("ODM class reference")}
        self.assertTrue({("list_products", "products", "reads"), ("add_product", "products", "writes"),
                         ("one", "products", "reads")} <= uses)


@unittest.skipUnless(importlib.util.find_spec("sqlglot"), "the stack extra provides sqlglot")
class SqlTextTests(unittest.TestCase):
    def test_constant_concatenation_is_literal_sql_not_dynamic(self):
        graph = scan({"r.py": """
            BASE = "SELECT * FROM named_tbl"
            def a(cur):
                cur.execute("SELECT * " + "FROM concat_tbl")
            def b(cur):
                cur.execute(f"SELECT * FROM fstring_tbl")
            def c(cur):
                cur.execute(BASE + " WHERE id = 1")
            def d(cur, table):
                cur.execute("SELECT * FROM " + table)
        """})
        tables = {(s, t) for s, t, _, _ in stores(graph, "postgres_table")}
        self.assertTrue({("a", "concat_tbl"), ("b", "fstring_tbl"), ("c", "named_tbl")} <= tables)
        dynamic = [i.evidence for i in graph.issues if i.code == "DYNAMIC_SQL"]
        self.assertEqual(dynamic, ["r.py:9"])


class AlembicTests(unittest.TestCase):
    def test_alembic_operations_declare_their_tables(self):
        graph = scan({
            "alembic/versions/0001_init.py": """
                from alembic import op
                import sqlalchemy as sa
                def upgrade():
                    op.create_table("products", sa.Column("id", sa.Integer), schema="shop")
                    op.add_column("products", sa.Column("sku", sa.String), schema="shop")
                    op.create_index("ix_orders_sku", "orders", ["sku"])
                    op.rename_table("old_name", "new_name")
                    op.create_foreign_key("fk", "orders", "customers", ["cid"], ["id"], source_schema="shop")
                    op.create_unique_constraint("uq", "invoices", ["number"])
                    op.alter_column("invoices", "number", nullable=False)
                def downgrade():
                    op.drop_column("invoices", "note")
                    op.drop_table("products", schema="shop")
            """,
            "tools/migrate.py": "from alembic import op\ndef upgrade():\n    op.drop_table('elsewhere')\n",
            "unrelated.py": "def upgrade(op):\n    op.create_table('not_alembic')\n",
        })
        found = {(s, t) for s, t, r, d in stores(graph, "postgres_table") if d == "Alembic migration (declares)"}
        self.assertEqual(found, {
            ("upgrade", "shop.products"), ("upgrade", "orders"), ("upgrade", "old_name"), ("upgrade", "new_name"),
            ("upgrade", "shop.orders"), ("upgrade", "customers"), ("upgrade", "invoices"),
            ("downgrade", "invoices"), ("downgrade", "shop.products"), ("upgrade", "elsewhere"),
        })


class ModelEdgeTests(unittest.TestCase):
    def test_endpoints_link_to_request_and_response_models(self):
        graph = scan({
            "models.py": """
                from pydantic import BaseModel
                class ItemIn(BaseModel):
                    name: str
                class ItemOut(BaseModel):
                    id: int
                class Tag(BaseModel):
                    label: str
                class Filter(BaseModel):
                    q: str
            """,
            "routes.py": """
                from enum import Enum
                from typing import Annotated, Optional
                from fastapi import APIRouter, Body, Depends, Query
                from pydantic import BaseModel
                from models import Filter, ItemIn, ItemOut, Tag
                class Local(BaseModel):
                    x: int
                class Status(str, Enum):
                    A = "a"
                router = APIRouter()
                def dep():
                    return 1
                @router.post("/items", response_model=list[ItemOut])
                def create(item: Annotated[ItemIn, Body()], tags: Optional[list[Tag]] = None,
                           local: Local | None = None, f: Annotated[Filter, Query()] = None,
                           d: ItemOut = Depends(dep), status: Status = Status.A, n: int = 1) -> "ItemOut":
                    return item
            """,
        })
        accepts = {(t, r) for s, t, r, _ in edges(graph, "ACCEPTS_MODEL") if s == "POST /items"}
        self.assertEqual(accepts, {("ItemIn", "high"), ("Tag", "high"), ("Local", "exact")})
        returns = {(t, r) for s, t, r, _ in edges(graph, "RETURNS_MODEL") if s == "POST /items"}
        self.assertEqual(returns, {("ItemOut", "high")})

    def test_dead_router_prefix_helper_is_not_used(self):
        from repolens.impact import fastapi
        self.assertFalse(hasattr(fastapi, "router_prefix"))



class ApiPrefixTests(unittest.TestCase):
    """`backend_api_prefix` predates mount resolution. Once the scanner resolves
    `APIRouter(prefix="/api")` itself, adding the setting again produced `/api/api/...`."""

    def test_a_configured_prefix_is_not_added_to_routes_that_already_resolve_it(self):
        import tempfile
        from pathlib import Path
        from repolens.impact.scanner import scan_repository
        files = {
            ".impact-tracer.json": '{"backend_api_prefix": "/api"}',
            "main.py": "from fastapi import FastAPI\nfrom routers import api_router\napp = FastAPI()\napp.include_router(api_router)\n",
            "routers/__init__.py": "from fastapi import APIRouter\nfrom routers.items import router as items_router\n"
                                   "api_router = APIRouter(prefix='/api')\napi_router.include_router(items_router)\n",
            "routers/items.py": "from fastapi import APIRouter\nrouter = APIRouter(prefix='/items')\n"
                                "@router.get('/{item_id}')\ndef get_item(item_id: int):\n    return {}\n",
            "loose.py": "from fastapi import APIRouter\nrouter = APIRouter()\n@router.post('/loose')\ndef loose():\n    return {}\n",
        }
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for name, body in files.items():
                (root / name).parent.mkdir(parents=True, exist_ok=True)
                (root / name).write_text(body, encoding="utf-8")
            graph = scan_repository(root)
        routes = {n.label for n in graph.nodes.values() if n.kind == "endpoint"}
        self.assertIn("GET /api/items/{dynamic}", routes)
        self.assertIn("POST /api/loose", routes)  # an unmounted router still gets the configured prefix
        self.assertFalse([route for route in routes if "/api/api" in route], routes)
        [note] = [i for i in graph.issues if i.code == "API_PREFIX_ALREADY_RESOLVED"]
        self.assertEqual(note.severity, "info")

if __name__ == "__main__":
    unittest.main()
