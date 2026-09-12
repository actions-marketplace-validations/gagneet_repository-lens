"""PostgreSQL coverage: the migrations checks, unbounded SQL fetches, SQL and ORM tables in
the lens and the impact graph, and `repolens init` finding a migrations directory."""
from __future__ import annotations

import argparse
import ast
import contextlib
import io
import tempfile
import textwrap
import tomllib
import unittest
from pathlib import Path

from repolens import bootstrap
from repolens.config import load_config
from repolens.impact.scanner import scan_repository
from repolens.lens.build import _orm_table, _sql_tables
from repolens.scan import migrations, performance
from repolens.scan.settings import from_config


class Repo:
    def __init__(self, files: dict[str, str]):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        files = {"repolens.toml": '[scan]\npython_roots = ["."]\n', **files}
        for path, text in files.items():
            target = self.root / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(textwrap.dedent(text), encoding="utf-8")

    @property
    def settings(self):
        return from_config(load_config(str(self.root)))

    def close(self) -> None:
        self.tmp.cleanup()


CLEAN = '''
    revision = "0002_clean"
    down_revision = "0001"
    TABLES = ["accounts", "ledgers"]

    def upgrade():
        """ALTER TABLE core.x ENABLE ROW LEVEL SECURITY -- a docstring runs nothing."""
        op.create_table("widgets", sa.Column("id", sa.Integer()), schema="core")
        op.create_index("ix_widgets_id", "widgets", ["id"], schema="core")
        op.add_column("orders", sa.Column("note", sa.Text(), nullable=False, server_default=""))
        for table in TABLES:
            op.execute(f"ALTER TABLE core.{table} ENABLE ROW LEVEL SECURITY")
            op.execute(f"ALTER TABLE core.{table} FORCE ROW LEVEL SECURITY")
        op.execute("CREATE VIEW core.v_ok WITH (security_invoker = true) AS SELECT 1")

    def downgrade():
        op.execute("ALTER TABLE core.accounts DISABLE ROW LEVEL SECURITY")
        op.add_column("orders", sa.Column("gone", sa.Text(), nullable=False))
'''

BROKEN = '''
    revision = "0003_a_revision_id_far_too_long_for_it"
    down_revision = "0002_clean"
    VIEW_SQL = """CREATE OR REPLACE VIEW core.v_members AS SELECT * FROM core.users"""

    def upgrade():
        op.add_column("users", sa.Column("tier", sa.Text(), nullable=False), schema="core")
        op.execute("ALTER TABLE core.payouts ENABLE ROW LEVEL SECURITY")
        op.execute(VIEW_SQL)
        op.create_index("ix_users_tier", "users", ["tier"], schema="core")
        op.execute("CREATE INDEX CONCURRENTLY ix_users_email ON core.users (email)")

    def downgrade():
        pass
'''


class MigrationTests(unittest.TestCase):
    def _found(self, files: dict[str, str]) -> set[tuple[str, str]]:
        repo = Repo(files)
        self.addCleanup(repo.close)
        return {(f.rule.split("/", 1)[1], Path(f.file).name) for f in migrations.scan(repo.settings)}

    def test_each_rule_fires_once_on_the_broken_migration_and_never_on_the_clean_one(self):
        found = self._found({"db/alembic/versions/0002_clean.py": CLEAN,
                             "db/alembic/versions/0003_broken.py": BROKEN})
        self.assertEqual(found, {
            ("revision-id-too-long", "0003_broken.py"),
            ("not-null-column-without-default", "0003_broken.py"),
            ("rls-without-force", "0003_broken.py"),
            ("view-without-security-invoker", "0003_broken.py"),
            ("index-not-concurrent", "0003_broken.py"),
        })

    def test_configured_roots_replace_detection(self):
        files = {"repolens.toml": '[scan]\npython_roots = ["."]\n[scan.migrations]\nroots = ["live/versions"]\n',
                 "live/versions/0003_broken.py": BROKEN,
                 "stale/alembic/versions/0003_broken.py": BROKEN}
        self.assertEqual({file for _, file in self._found(files)}, {"0003_broken.py"})
        repo = Repo(files)
        self.addCleanup(repo.close)
        self.assertEqual([p.parent.as_posix() for p in migrations.migration_files(repo.settings)],
                         [(repo.root / "live/versions").as_posix()])

    def test_views_are_checked_only_where_row_level_security_is_used(self):
        plain = '''
            revision = "0001_views"
            def upgrade():
                op.execute("CREATE VIEW reporting.v_totals AS SELECT 1")
        '''
        self.assertEqual(self._found({"alembic/versions/0001_views.py": plain}), set())

    def test_require_rls_names_a_table_no_migration_secures(self):
        created = '''
            revision = "0001_tables"
            def upgrade():
                op.create_table("secrets", sa.Column("id", sa.Integer()), schema="core")
                op.create_table("lookups", sa.Column("id", sa.Integer()), schema="reference")
        '''
        found = self._found({
            "repolens.toml": '[scan]\npython_roots = ["."]\n[scan.migrations]\n'
                             'require_rls = true\nrls_schemas = ["core"]\n',
            "alembic/versions/0001_tables.py": created,
        })
        self.assertEqual(found, {("table-without-rls", "0001_tables.py")})

    def test_migrations_under_a_test_tree_are_not_the_schema(self):
        self.assertEqual({file for _, file in self._found({
            "alembic/versions/0003_broken.py": BROKEN,
            "tests/fixtures/alembic/versions/0004_fixture.py": BROKEN})}, {"0003_broken.py"})


def _migration(body: str, revision: str = "0001_a") -> str:
    return f'revision = "{revision}"\n' + textwrap.dedent(body)


class MigrationWalkTests(unittest.TestCase):
    """Each case is one the previous reader got wrong, named in the test."""

    def _scan(self, files: dict[str, str], profile: str = "") -> list:
        repo = Repo({"repolens.toml": '[scan]\npython_roots = ["."]\n' + profile,
                     **{f"alembic/versions/{name}": text for name, text in files.items()}})
        self.addCleanup(repo.close)
        return migrations.scan(repo.settings)

    def _rule(self, found: list, rule: str) -> list[tuple[str, str, str]]:
        return sorted((Path(f.file).name, f.message.split(" ", 1)[0], f.confidence)
                      for f in found if f.rule == f"migrations/{rule}")

    # ── row-level security ───────────────────────────────────────────────────
    def test_enable_and_force_in_one_statement_is_forced(self):
        found = self._scan({"0001_a.py": _migration('''
            def upgrade():
                op.execute("ALTER TABLE core.a ENABLE ROW LEVEL SECURITY, FORCE ROW LEVEL SECURITY")
        ''')})
        self.assertEqual(self._rule(found, "rls-without-force"), [])

    def test_force_in_another_schema_does_not_cover_a_table(self):
        found = self._scan({"0001_a.py": _migration('''
            def upgrade():
                op.execute("ALTER TABLE audit.users ENABLE ROW LEVEL SECURITY")
                op.execute("ALTER TABLE core.users ENABLE ROW LEVEL SECURITY")
                op.execute("ALTER TABLE core.users FORCE ROW LEVEL SECURITY")
        ''')})
        self.assertEqual(self._rule(found, "rls-without-force"), [("0001_a.py", "audit.users", "medium")])

    def test_a_later_no_force_and_a_later_enable_decide(self):
        found = self._scan({
            "0001_a.py": _migration('''
                def upgrade():
                    op.execute("ALTER TABLE core.a ENABLE ROW LEVEL SECURITY")
                    op.execute("ALTER TABLE core.a FORCE ROW LEVEL SECURITY")
                    op.execute("ALTER TABLE core.b DISABLE ROW LEVEL SECURITY")
            '''),
            "0002_b.py": _migration('''
                def upgrade():
                    op.execute("ALTER TABLE core.a NO FORCE ROW LEVEL SECURITY")
                    op.execute("ALTER TABLE core.b ENABLE ROW LEVEL SECURITY")
            ''', "0002_b"),
        })
        self.assertEqual([t for _, t, _ in self._rule(found, "rls-without-force")], ["core.a", "core.b"])

    def test_a_computed_force_in_the_same_file_does_not_hide_a_literal_enable(self):
        found = self._scan({"0001_a.py": _migration('''
            def upgrade():
                for table in load_tables():
                    op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
                    op.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY")
                op.execute("ALTER TABLE core.payouts ENABLE ROW LEVEL SECURITY")
        ''')})
        self.assertEqual(self._rule(found, "rls-without-force"), [("0001_a.py", "core.payouts", "low")])

    def test_a_computed_force_in_an_earlier_file_keeps_full_confidence(self):
        found = self._scan({
            "0001_a.py": _migration('''
                def upgrade():
                    for table in load_tables():
                        op.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY")
            '''),
            "0002_b.py": _migration('''
                def upgrade():
                    op.execute("ALTER TABLE core.payouts ENABLE ROW LEVEL SECURITY")
            ''', "0002_b"),
        })
        self.assertEqual(self._rule(found, "rls-without-force"), [("0002_b.py", "core.payouts", "medium")])

    def test_sql_built_with_plus_is_read(self):
        found = self._scan({"0001_a.py": _migration('''
            TABLE = "core.payouts"
            def upgrade():
                op.execute("ALTER TABLE " + TABLE + " ENABLE ROW LEVEL SECURITY")
        ''')})
        self.assertEqual(self._rule(found, "rls-without-force"), [("0001_a.py", "core.payouts", "medium")])

    def test_messages_comments_and_downgrade_helpers_are_not_sql(self):
        found = self._scan({"0001_a.py": _migration('''
            def _undo(table):
                op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")

            def upgrade():
                print("ALTER TABLE core.x ENABLE ROW LEVEL SECURITY")
                op.create_table("t", sa.Column("id", sa.Integer(),
                                comment="CREATE VIEW core.v AS SELECT 1"), schema="core")
                op.execute("ALTER TABLE core.t ENABLE ROW LEVEL SECURITY, FORCE ROW LEVEL SECURITY")

            def downgrade():
                _undo("core.x")
        ''')})
        self.assertEqual([f.rule for f in found], [])

    def test_a_helper_called_in_a_loop_is_read_per_table(self):
        # The shape that printed "{}.{} gets ENABLE ...": the helper is now read with each
        # literal it was given, and the one table the later FORCE misses is named.
        found = self._scan({
            "0001_a.py": _migration('''
                def _enable(schema_name, table_name):
                    op.execute(f'ALTER TABLE "{schema_name}"."{table_name}" ENABLE ROW LEVEL SECURITY')

                def upgrade():
                    for table_name in ("inboxes", "threads", "notes"):
                        _enable("comms", table_name)
            '''),
            "0002_b.py": _migration('''
                _TABLES = [("comms", "inboxes"), ("comms", "threads")]

                def upgrade():
                    for schema, table in _TABLES:
                        op.execute(f"ALTER TABLE {schema}.{table} FORCE ROW LEVEL SECURITY")
            ''', "0002_b"),
        })
        self.assertEqual(self._rule(found, "rls-without-force"), [("0001_a.py", "comms.notes", "medium")])

    def test_a_computed_name_is_named_by_its_source(self):
        found = self._scan({"0001_a.py": _migration('''
            def upgrade():
                for schema, table in discover():
                    op.execute(f"ALTER TABLE {schema}.{table} ENABLE ROW LEVEL SECURITY")
        ''')})
        [finding] = [f for f in found if f.rule == "migrations/rls-without-force"]
        self.assertTrue(finding.message.startswith("`{schema}.{table}`, a table name computed"))

    # ── indexes ──────────────────────────────────────────────────────────────
    def test_index_targets_in_every_spelling(self):
        found = self._scan({"0001_a.py": _migration('''
            def upgrade():
                op.create_table("users", sa.Column("id", sa.Integer()), schema="audit")
                op.create_index("ix_users_a", table_name="users", columns=["a"], schema="core")
                with op.batch_alter_table("orders", schema="core") as batch_op:
                    batch_op.create_index("ix_orders_b", ["b"])
                op.execute("CREATE MATERIALIZED VIEW core.mv AS SELECT 1 AS a")
                op.execute("CREATE INDEX ix_mv_a ON core.mv (a)")
                op.execute("CREATE TEMP TABLE scratch (a int); CREATE INDEX ix_scratch ON scratch (a)")
        ''')})
        self.assertEqual({f.message.split(" ")[3].rstrip(",") for f in found
                          if f.rule == "migrations/index-not-concurrent"}, {"core.users", "core.orders"})

    # ── NOT NULL columns ─────────────────────────────────────────────────────
    def test_not_null_columns_that_can_and_cannot_fail(self):
        found = self._scan({"0001_a.py": _migration('''
            def upgrade():
                op.create_table("fresh", sa.Column("id", sa.Integer()), schema="core")
                op.add_column("fresh", sa.Column("a", sa.Text(), nullable=False), schema="core")
                op.add_column("old", sa.Column("n", sa.BigInteger(), sa.Identity(), nullable=False),
                              schema="core")
                op.execute("ALTER TABLE core.old ADD COLUMN b text NOT NULL")
                op.execute("ALTER TABLE core.old ADD COLUMN c text NOT NULL DEFAULT '', "
                           "ADD CONSTRAINT c_ck CHECK (c <> 'x')")
        ''')})
        self.assertEqual([f.message.split(" ")[2] for f in found
                          if f.rule == "migrations/not-null-column-without-default"], ["core.old.b"])

    # ── table-without-rls ────────────────────────────────────────────────────
    def test_an_unsecured_table_is_reported_where_it_is_created(self):
        text = _migration('''
            def upgrade():
                op.create_table("secrets", sa.Column("id", sa.Integer()), schema="core")
        ''')
        found = self._scan({"0001_a.py": text},
                           '[scan.migrations]\nrequire_rls = true\nrls_schemas = ["core"]\n')
        [finding] = [f for f in found if f.rule == "migrations/table-without-rls"]
        self.assertEqual(finding.line, 1 + text.splitlines().index(
            next(line for line in text.splitlines() if "create_table" in line)))


FETCHES = '''
    from sqlalchemy import select, text

    async def everything(conn):
        return await conn.fetch("SELECT id, name FROM core.lots")

    async def one_page(conn):
        return await conn.fetch("SELECT id FROM core.lots ORDER BY id LIMIT 50")

    async def a_total(conn):
        return await conn.fetch("SELECT count(*) FROM core.lots")

    async def per_scheme(conn):
        return await conn.fetch("SELECT scheme_id, count(*) FROM core.lots GROUP BY scheme_id")

    async def orm_every_row(session):
        stmt = select(Lot).where(Lot.scheme_id == 1)
        return (await session.execute(stmt)).scalars().all()

    async def orm_one_page(session):
        return (await session.execute(select(Lot).limit(10))).scalars().all()

    async def text_every_row(session):
        return (await session.execute(text("SELECT * FROM core.lots"))).fetchall()

    def not_a_query(values):
        return all(values)
'''


class UnboundedFetchTests(unittest.TestCase):
    def test_a_select_with_no_limit_is_flagged_and_a_bounded_or_aggregate_one_is_not(self):
        repo = Repo({"svc/lots.py": FETCHES})
        self.addCleanup(repo.close)
        tree = ast.parse(textwrap.dedent(FETCHES))
        spans = [(fn.lineno, fn.end_lineno, fn.name) for fn in tree.body
                 if isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef))]
        found = [f for f in performance.scan(repo.settings) if f.rule == "performance/unbounded-sql-fetch"]
        flagged = {name for f in found for start, end, name in spans if start <= f.line <= end}
        self.assertEqual(flagged, {"everything", "per_scheme", "orm_every_row", "text_every_row"})
        self.assertEqual({f.confidence for f in found}, {"low"})


class _LensSettings:
    sql_call = "text"


class LensTableTests(unittest.TestCase):
    def test_sql_tables_reads_bare_and_qualified_names_and_skips_what_is_not_a_table(self):
        source = '''
            async def f(conn, session):
                await conn.fetch("SELECT a FROM finance.receipts r JOIN core.lots l ON l.id = r.lot_id")
                await conn.execute(f"UPDATE levy_items SET paid = 1 WHERE id = {item}")
                await conn.execute("INSERT INTO audit (a) VALUES (1) ON CONFLICT (a) DO UPDATE SET a = 2")
                await session.execute(text("WITH recent AS (SELECT 1) SELECT * FROM recent JOIN users u ON TRUE"))
                await conn.fetch("SELECT EXTRACT(YEAR FROM created_at) FROM orders FOR UPDATE SKIP LOCKED")
                await conn.fetch("SELECT * FROM unnest($1::int[]) AS x")
        '''
        self.assertEqual(_sql_tables(_LensSettings(), ast.parse(textwrap.dedent(source))),
                         ["audit", "core.lots", "finance.receipts", "levy_items", "orders", "users"])

    def test_orm_table_reads_the_schema_from_table_args(self):
        def table(body: str) -> str | None:
            return _orm_table(ast.parse(textwrap.dedent(body)).body[0])
        self.assertEqual(table('''
            class Receipt(Base):
                __tablename__ = "receipts"
                __table_args__ = (Index("ix"), {"schema": "finance"})
        '''), "finance.receipts")
        self.assertEqual(table('class Note(Base):\n    __tablename__ = "notes"\n'), "notes")
        self.assertIsNone(table("class Plain:\n    pass\n"))

    def test_a_function_naming_a_mapped_class_touches_its_table(self):
        from repolens.lens.build import load_index
        from repolens.lens.settings import from_config as lens_settings
        repo = Repo({
            "repolens.toml": '[lens]\npython_roots = ["."]\n',
            "models.py": 'class Lot(Base):\n    __tablename__ = "lots"\n    __table_args__ = {"schema": "core"}\n',
            "svc.py": "def list_lots(session):\n    return session.query(Lot).all()\n",
        })
        self.addCleanup(repo.close)
        with contextlib.redirect_stderr(io.StringIO()):
            data = load_index(lens_settings(load_config(str(repo.root))))
        [record] = [r for r in data["functions"].values() if r["name"] == "list_lots"]
        self.assertEqual(record["postgres_tables"], ["core.lots"])
        self.assertNotIn("_names", record)


class ImpactTableTests(unittest.TestCase):
    def test_orm_tables_are_exact_and_sql_text_is_probable_without_a_schema_list(self):
        repo = Repo({
            "backend/models.py": 'class Lot(Base):\n    __tablename__ = "lots"\n'
                                 '    __table_args__ = {"schema": "core"}\n',
            "backend/repo.py": 'from x import y\n'
                               'SQL = "SELECT * FROM finance.receipts r JOIN levy_items l ON TRUE"\n',
        })
        self.addCleanup(repo.close)
        graph = scan_repository(repo.root)
        tables = {graph.nodes[e.target].label: e.resolution for e in graph.edges
                  if e.kind == "TOUCHES_STORE" and graph.nodes[e.target].kind == "postgres_table"}
        self.assertEqual(tables, {"core.lots": "exact", "finance.receipts": "probable",
                                  "levy_items": "probable"})


class InitMigrationTests(unittest.TestCase):
    def _root(self, files: dict[str, str]) -> Path:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        for path, text in files.items():
            (root / path).parent.mkdir(parents=True, exist_ok=True)
            (root / path).write_text(text, encoding="utf-8")
        return root

    def test_init_writes_the_migrations_section_it_detected(self):
        root = self._root({"backend/app.py": "x = 1\n", "backend/alembic/env.py": "",
                           "backend/alembic/versions/0001_init.py": 'revision = "0001_init"\n'})
        self.assertEqual(bootstrap.detect(root).migration_roots, ["backend/alembic/versions"])
        args = argparse.Namespace(dry_run=False, force=False, rules_dir="docs/repolens", no_rules=True,
                                  agents_file=None, ci=None, install_spec="repolens")
        actions, _ = bootstrap.plan(root, args)
        bootstrap.apply(actions)
        profile = tomllib.loads((root / "repolens.toml").read_text(encoding="utf-8"))
        self.assertEqual(profile["scan"]["migrations"]["roots"], ["backend/alembic/versions"])

    def test_a_migrations_directory_inside_a_test_tree_is_not_a_root(self):
        root = self._root({"backend/app.py": "x = 1\n",
                           "backend/alembic/versions/0001_init.py": 'revision = "0001_init"\n',
                           "tests/fixtures/alembic/versions/0001_bad.py": 'revision = "0001_bad"\n'})
        self.assertEqual(bootstrap.detect(root).migration_roots, ["backend/alembic/versions"])

    def test_no_migrations_directory_writes_no_section(self):
        root = self._root({"backend/app.py": "x = 1\n"})
        d = bootstrap.detect(root)
        self.assertNotIn("[scan.migrations]", bootstrap.profile_text(root, d, "owners.yaml"))


if __name__ == "__main__":
    unittest.main()
