"""SQL_UNKNOWN_COLUMN: SQL column references checked against the declared schema.

Precision over recall: each negative test is a shape where a report would be wrong."""
from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

from repolens.analysis import Analysis
from repolens.core import javascript
from repolens.impact.config import Config
from repolens.impact.scanner import scan_repository

HAS_SQLGLOT = importlib.util.find_spec("sqlglot") is not None
HAS_STACK = javascript.available() and HAS_SQLGLOT

SCHEMA = '''datasource db {
  provider = "postgresql"
}

model OrderLines {
  id                 String            @id
  orderBatchId String            @map("order_batch_id")
  userId             String            @map("user_id")
  amount             Decimal
  channelType        String
  status             Status            @default(PENDING)
  legacy             String?           @ignore
  batch              OrderBatches @relation(fields: [orderBatchId], references: [id])
  user               Users             @relation(fields: [userId], references: [id])

  @@map("order_lines")
}

model OrderBatches {
  id           String                @id
  labelText     String                @map("label_text") // trailing comment with "quotes"
  lines        OrderLines[]

  @@map("order_batches")
}

model Users {
  id    String @id
  email String
  lines   OrderLines[]

  @@map("users")
}

model Hidden {
  id String @id

  @@ignore
  @@map("hidden")
}

enum Status {
  PENDING
  DONE
}
'''


class ColumnRepo(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.addCleanup(self.tmp.cleanup)

    def write(self, path: str, text: str) -> None:
        target = self.root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8")

    def unknown(self, sql: str = "", path: str = "scripts/q.sql") -> list:
        if sql:
            self.write(path, sql)
        self.graph = scan_repository(self.root)
        return [issue for issue in self.graph.issues if issue.code == "SQL_UNKNOWN_COLUMN"]

    def flagged(self, sql: str = "", path: str = "scripts/q.sql") -> set[str]:
        """Every `table.column` reported, across the per-location issues."""
        return {subject for issue in self.unknown(sql, path) for subject in issue.subject.split(", ")}


@unittest.skipUnless(HAS_STACK, "install repolens[stack]")
class PrismaColumnTests(ColumnRepo):
    def setUp(self):
        super().setUp()
        self.write("package.json", "{}")
        self.write("prisma/schema.prisma", SCHEMA)

    def test_a_pg_script_using_prisma_field_names_is_flagged_with_the_mapped_column(self):
        self.write("scripts/report.js", "const { Client } = require('pg');\nconst client = new Client();\n"
                                        "async function run() {\n"
                                        "  await client.query('SELECT st.\"orderBatchId\" FROM order_lines st');\n}\n")
        issues = self.unknown()
        self.assertEqual(len(issues), 1, [i.message for i in self.graph.issues])
        issue = issues[0]
        self.assertEqual((issue.severity, issue.evidence), ("warning", "scripts/report.js:4"))
        self.assertEqual(issue.message, 'Column "orderBatchId" does not exist on order_lines '
                                        "(Prisma maps it to order_batch_id).")
        self.assertIn("order_batch_id", issue.recommendation)
        self.assertTrue(Analysis(self.graph, [], Config()).complete)
        self.assertNotIn("sql_facts", json.dumps(self.graph.to_dict()))

    def test_mapped_snake_case_columns_are_not_flagged(self):
        self.assertEqual(self.flagged(
            "SELECT st.order_batch_id, st.user_id, st.amount, st.\"channelType\", st.status, st.legacy, st.ctid\n"
            "FROM order_lines st WHERE st.user_id = $1;\n"
            "INSERT INTO order_lines (id, order_batch_id, user_id, amount) VALUES ('a', 'b', 'c', 1)\n"
            "  ON CONFLICT (id) DO UPDATE SET amount = excluded.amount RETURNING id, user_id;\n"
            "UPDATE order_lines SET status = 'DONE' WHERE user_id = 'x';\n"), set())

    def test_unquoted_camel_case_folds_to_lower_case_and_is_flagged(self):
        issues = self.unknown("SELECT userId FROM order_lines;\nSELECT channelType FROM order_lines;\n")
        messages = {i.subject: i.message for i in issues}
        self.assertEqual(set(messages), {"order_lines.userid", "order_lines.channeltype"})
        self.assertEqual(messages["order_lines.userid"],
                         "Column userId does not exist on order_lines (Prisma maps it to user_id). "
                         "Unquoted names fold to lower case (userId is userid).")
        self.assertIn('(Prisma maps it to "channelType")', messages["order_lines.channeltype"])

    def test_insert_update_and_join_references_resolve_through_aliases(self):
        self.assertEqual(self.flagged(
            'INSERT INTO order_lines (id, "userId") VALUES ($1, $2);\n'
            'UPDATE order_lines AS s SET "userId" = u.id FROM users u WHERE s.user_id = u."emailAddress";\n'
            'SELECT s.amount, f."labelText" FROM order_lines s JOIN order_batches f ON f.id = s.order_batch_id;\n'),
            {"order_lines.userId", "users.emailAddress", "order_batches.labelText"})

    def test_output_names_ctes_derived_tables_and_ambiguous_names_are_not_checked(self):
        self.assertEqual(self.flagged(
            "SELECT amount AS total, count(*) FROM order_lines GROUP BY total ORDER BY total, count;\n"
            "WITH recent AS (SELECT id, amount AS spent FROM order_lines) SELECT recent.spent, anything FROM recent;\n"
            "SELECT d.whatever FROM (SELECT id FROM order_lines) d;\n"
            "SELECT anything FROM order_lines s JOIN users u ON u.id = s.user_id;\n"
            "SELECT s.id FROM order_lines s, LATERAL (SELECT nothing) l;\n"
            "SELECT id FROM users WHERE EXISTS (SELECT 1 FROM order_lines s WHERE s.user_id = users.id AND email IS NOT NULL);\n"
            "SELECT excluded FROM hidden;\nSELECT anything FROM hidden;\nSELECT anything FROM unknown_table;\n"
            "SELECT anything FROM other_schema.order_lines;\n"
            "DO $$ BEGIN PERFORM nothing FROM order_lines; END $$;\n"), set())

    def test_a_correlated_name_missing_everywhere_is_flagged(self):
        self.assertEqual(self.flagged(
            "SELECT id FROM users WHERE EXISTS (SELECT 1 FROM order_lines s WHERE s.user_id = users.id AND nowhere = 1);\n"),
            {"order_lines.nowhere"})

    def test_migrations_dynamic_sql_and_placeholders_in_name_positions_are_not_checked(self):
        self.write("prisma/migrations/2024_init/migration.sql", 'SELECT "userId" FROM order_lines;\n')
        self.write("db/migrations/V1__old.sql", 'SELECT "userId" FROM order_lines;\n')
        self.write("alembic/versions/0001_old.py", 'from alembic import op\nop.execute(\'SELECT "userId" FROM order_lines\')\n')
        self.write("scripts/dyn.ts", "export async function f(sql: any, col: string) {\n"
                                     "  await sql.query(`SELECT ${col} FROM order_lines`);\n}\n")
        self.assertEqual(self.unknown(), [])

    def test_a_stray_schema_file_does_not_change_the_columns(self):
        self.write("prisma/schema-enhanced.prisma", SCHEMA.replace('@map("user_id")', "").replace("amount ", "amountCents "))
        self.write("prisma/empty_schema.prisma", 'datasource db {\n  provider = "postgresql"\n}\n')
        self.assertEqual(self.flagged("SELECT user_id, amount FROM order_lines;\n"
                                      'SELECT "userId" FROM order_lines;\n'),
                         {"order_lines.userId"})

    def test_prisma_wins_over_create_table_in_another_script(self):
        self.write("db/setup.sql", 'CREATE TABLE order_lines (id text, "userId" text);\n')
        self.assertEqual(self.flagged('SELECT "userId" FROM order_lines;\n'), {"order_lines.userId"})

    def test_a_script_that_creates_or_alters_a_table_is_not_checked_against_it(self):
        self.assertEqual(self.flagged(
            'ALTER TABLE order_lines ADD COLUMN IF NOT EXISTS "noteKind" text;\n'
            'UPDATE order_lines SET "noteKind" = \'x\' WHERE "noteKind" IS NULL;\n'
            'DO $$ BEGIN ALTER TABLE users ADD COLUMN nickname text; END $$;\n'
            "SELECT nickname FROM users;\n"
            'SELECT "labelText" FROM order_batches;\n'), {"order_batches.labelText"})

    def test_one_issue_per_statement_lists_every_unknown_column(self):
        issues = self.unknown(
            'SELECT s."userId", s."channelType", s.nope, f."labelText", f.nope, f.nope\n'
            "FROM order_lines s JOIN order_batches f ON f.id = s.order_batch_id;\n")
        self.assertEqual(len(issues), 1)
        self.assertEqual(issues[0].message,
                         'Columns "userId" (user_id), nope do not exist on order_lines; '
                         'columns "labelText" (label_text), nope do not exist on order_batches.')
        self.assertEqual(issues[0].subject, "order_lines.userId, order_lines.nope, "
                                            "order_batches.labelText, order_batches.nope")
        self.assertIn("(user_id, label_text)", issues[0].recommendation)
        uniform = self.unknown('SELECT "userId", "orderBatchId" FROM order_lines;\n')
        self.assertEqual([i.message for i in uniform],
                         [('Columns "userId", "orderBatchId" do not exist on order_lines '
                           "(Prisma maps them to user_id, order_batch_id).")])


@unittest.skipUnless(HAS_SQLGLOT, "install repolens[stack]")
class SchemaSelectionTests(ColumnRepo):
    def test_package_json_prisma_schema_path_is_the_schema(self):
        self.write("package.json", json.dumps({"prisma": {"schema": "db/main.prisma"}}))
        self.write("db/main.prisma", SCHEMA)
        self.write("db/other.prisma", SCHEMA.replace('@map("user_id")', ""))
        self.assertEqual(self.flagged('SELECT "userId" FROM order_lines;\n'), {"order_lines.userId"})

    def test_prisma_config_ts_schema_path_is_the_schema(self):
        self.write("prisma.config.ts", "import { defineConfig } from 'prisma/config';\n"
                                       "export default defineConfig({ schema: 'db/main.prisma' });\n")
        self.write("db/main.prisma", SCHEMA)
        self.write("db/old.prisma", SCHEMA.replace('@map("user_id")', ""))
        self.assertEqual(self.flagged('SELECT "userId" FROM order_lines;\n'), {"order_lines.userId"})

    def test_without_a_selection_rule_only_agreeing_schemas_are_used(self):
        self.write("a/one.prisma", SCHEMA)
        self.write("b/two.prisma", SCHEMA.replace('@map("user_id")', ""))
        self.assertEqual(self.flagged('SELECT "userId", nope FROM order_lines;\nSELECT nope FROM users;\n'),
                         {"users.nope"})

    def test_a_non_postgres_provider_is_not_checked(self):
        self.write("prisma/schema.prisma", SCHEMA.replace('"postgresql"', '"mysql"'))
        self.assertEqual(self.flagged('SELECT "userId" FROM order_lines;\n'), set())

    def test_cockroachdb_is_checked_like_postgresql(self):
        # The accessor pass maps CockroachDB models as PostgreSQL tables; the column check agrees.
        self.write("prisma/schema.prisma", SCHEMA.replace('"postgresql"', '"cockroachdb"'))
        self.assertEqual(self.flagged('SELECT "userId" FROM order_lines;\n'), {"order_lines.userId"})


@unittest.skipUnless(HAS_SQLGLOT, "install repolens[stack]")
class SqlDdlColumnTests(ColumnRepo):
    def test_create_table_only_schema_is_checked_with_alter_table_columns(self):
        self.write("db/schema.sql", "CREATE TABLE public.orders (id int PRIMARY KEY, customer_id int, \"totalCents\" int);\n"
                                    "ALTER TABLE orders ADD COLUMN IF NOT EXISTS placed_at timestamptz;\n"
                                    "ALTER TABLE orders RENAME COLUMN customer_id TO buyer_id;\n")
        issues = self.unknown("SELECT id, buyer_id, customer_id, placed_at, \"totalCents\", total_cents FROM orders;\n"
                              "SELECT totalcents FROM orders;\nSELECT nope FROM orders;\n")
        by_subject = {i.subject: i.message for i in issues}
        self.assertEqual(by_subject, {
            "orders.total_cents": 'Column total_cents does not exist on orders (did you mean "totalCents"?).',
            "orders.totalcents": 'Column totalcents does not exist on orders (declared as "totalCents"; quoted names are case-sensitive).',
            "orders.nope": "Column nope does not exist on orders (per CREATE TABLE DDL).",
        })

    def test_derived_or_orm_declared_tables_are_not_checked(self):
        self.write("db/schema.sql", "CREATE TABLE copied AS SELECT 1 AS id;\n"
                                    "CREATE TABLE child (id int) INHERITS (parent);\n"
                                    "CREATE TABLE liked (LIKE parent);\n"
                                    "CREATE TABLE altered (id int);\n")
        self.write("alembic/versions/0002_add.py", "from alembic import op\nimport sqlalchemy as sa\n"
                                                   "op.add_column('altered', sa.Column('extra', sa.Text()))\n")
        self.assertEqual(self.flagged("SELECT nope FROM copied;\nSELECT nope FROM child;\nSELECT nope FROM liked;\n"
                                      "SELECT extra FROM altered;\n"), set())

    def test_dynamic_ddl_disables_only_the_tables_it_can_reach(self):
        self.write("db/schema.sql", "CREATE TABLE orders (id int);\nCREATE TABLE invoices (id int);\n"
                                    "DO $$ BEGIN EXECUTE 'ALTER TABLE orders ADD COLUMN ' || 'extra int'; "
                                    "EXECUTE format('CREATE TABLE %I (id int)', 'invoices_' || year); END $$;\n")
        self.assertEqual(self.flagged("SELECT extra FROM orders;\nSELECT extra FROM invoices;\n"), {"invoices.extra"})
        # A computed ALTER target could be any table in the package.
        self.write("db/grow.sql", "CREATE FUNCTION grow(t text) RETURNS void AS $$ BEGIN "
                                  "EXECUTE format('ALTER TABLE %I ADD COLUMN extra int', t); END $$ LANGUAGE plpgsql;\n")
        self.assertEqual(self.flagged(), set())

    def test_ddl_in_tests_and_fixtures_does_not_declare_columns(self):
        self.write("db/schema.sql", "CREATE TABLE orders (id int);\n")
        self.write("tests/fixtures/schema.sql", "CREATE TABLE invoices (id int);\nALTER TABLE orders ADD COLUMN nope int;\n")
        self.write("app/__tests__/setup.sql", "CREATE TABLE items (id int);\n")
        self.assertEqual(self.flagged("SELECT nope FROM orders;\nSELECT nope FROM invoices;\nSELECT nope FROM items;\n"),
                         {"orders.nope"})

    def test_an_unqualified_name_is_not_resolved_through_configured_schemas(self):
        self.write(".impact-tracer.json", json.dumps({"pg_schemas": ["app"]}))
        self.write("db/schema.sql", "CREATE TABLE app.orders (id int);\n")
        self.assertEqual(self.flagged("SELECT nope FROM orders;\nSELECT nope FROM app.orders;\n"), {"app.orders.nope"})

    def test_each_package_is_checked_against_its_own_ddl(self):
        self.write("services/billing/pyproject.toml", "[project]\nname = 'billing'\n")
        self.write("services/billing/db/schema.sql", "CREATE TABLE invoices (id int);\n")
        self.write("services/billing/q.sql", "SELECT nope FROM invoices;\n")
        self.write("services/shipping/package.json", "{}")
        self.write("services/shipping/db/schema.sql", "CREATE TABLE invoices (id int, nope int);\n")
        self.assertEqual([(i.subject, i.evidence) for i in self.unknown("SELECT nope FROM invoices;\n", "services/shipping/q.sql")],
                         [("invoices.nope", "services/billing/q.sql:1")])

    def test_alter_table_and_dynamic_ddl_in_another_package_apply_to_the_shared_database(self):
        # Packages of one repository usually share a database: what one package adds or
        # reshapes only suppresses reports in another; CREATE stays per package.
        self.write("services/api/package.json", "{}")
        self.write("services/api/db/schema.sql", "CREATE TABLE orders (id int);\nCREATE TABLE invoices (id int);\n")
        self.write("services/worker/package.json", "{}")
        self.write("services/worker/db/grow.sql", "ALTER TABLE orders ADD COLUMN extra int;\n"
                                                  "DO $$ BEGIN EXECUTE 'ALTER TABLE invoices RENAME TO ' || 'bills'; END $$;\n")
        self.assertEqual(self.flagged("SELECT extra FROM orders;\nSELECT extra FROM invoices;\nSELECT nope FROM orders;\n",
                                      "services/api/q.sql"), {"orders.nope"})
        self.write("services/worker/db/fn.sql", "CREATE FUNCTION grow(t text) RETURNS void AS $$ BEGIN "
                                                "EXECUTE format('ALTER TABLE %I ADD COLUMN extra int', t); END $$ LANGUAGE plpgsql;\n")
        self.assertEqual(self.flagged(), set())

    def test_tables_other_orms_create_alter_or_map_are_not_checked(self):
        self.write("db/schema.sql", "".join(f"CREATE TABLE {t} (id int);\n" for t in ("orders", "invoices", "items", "carts", "lines")))
        self.write("knex/1_orders.js", "exports.up = knex => knex.schema.alterTable('orders', t => { t.string('extra'); });\n")
        self.write("sequelize/2_invoices.js", "module.exports = { up: (qi, S) => qi.addColumn('invoices', 'extra', S.STRING) };\n")
        self.write("typeorm/3_items.ts", "export class AddExtra { async up(queryRunner: any) {\n"
                                         "  await queryRunner.addColumn('items', new TableColumn({ name: 'extra', type: 'text' }));\n} }\n")
        self.write("shop/models.py", "from django.db import models\nclass Cart(models.Model):\n"
                                     "    extra = models.TextField()\n    class Meta:\n        db_table = 'carts'\n")
        self.write("knex/4_lines.js", "exports.up = knex => knex.schema.table('lines', t => { t.string('extra'); });\n")
        self.assertEqual(self.flagged("".join(f"SELECT extra FROM {t};\n" for t in ("orders", "invoices", "items", "carts", "lines"))
                                      + "SELECT nope FROM orders;\n"), set())
        self.write("db/other.sql", "CREATE TABLE refunds (id int);\n")
        self.assertEqual(self.flagged("SELECT extra FROM refunds;\n"), {"refunds.extra"})


@unittest.skipUnless(HAS_SQLGLOT, "install repolens[stack]")
class UnreadSchemaSourceTests(ColumnRepo):
    """What the reader cannot see may reshape a table: those references are not checked."""

    def setUp(self):
        super().setUp()
        self.write("db/schema.sql", "".join(f"CREATE TABLE {t} (id int);\n" for t in ("orders", "invoices", "items", "carts")))

    def test_migrations_in_languages_the_scanner_does_not_read_disable_the_tables_they_name(self):
        self.write("db/migrate/20240101_add_extra.rb", "class AddExtra < ActiveRecord::Migration[7.1]\n"
                                                       "  def change\n    add_column :orders, :extra, :string\n  end\nend\n")
        self.write("database/migrations/2024_add.php", "<?php\nSchema::table('invoices', function ($t) { $t->string('extra'); });\n")
        self.write("src/main/resources/db/changelog/001.xml",
                   '<databaseChangeLog><changeSet id="1"><addColumn tableName="items"><column name="extra"/></addColumn>'
                   "</changeSet></databaseChangeLog>\n")
        self.assertEqual(self.flagged("".join(f"SELECT extra FROM {t};\n" for t in ("orders", "invoices", "items", "carts"))),
                         {"carts.extra"})

    def test_a_computed_table_name_in_an_unread_language_disables_every_ddl_catalog(self):
        self.write("cmd/migrate/main.go", 'package main\nfunc up(db *sql.DB, t string) {\n'
                                          '  db.Exec(fmt.Sprintf("ALTER TABLE %s ADD COLUMN extra int", t))\n}\n')
        self.assertEqual(self.flagged("SELECT extra FROM orders;\nSELECT extra FROM carts;\n"), set())

    def test_search_path_changes_leave_unqualified_names_unchecked(self):
        self.write("scripts/app.sql", "SET search_path TO app, public;\nSELECT extra FROM orders;\nSELECT extra FROM public.orders;\n")
        self.write("scripts/cfg.sql", "SELECT set_config('search_path', 'app', false);\nSELECT extra FROM invoices;\n")
        self.write("scripts/schema.sql", "SET SCHEMA 'app';\nSELECT extra FROM items;\n")
        self.assertEqual(self.flagged("SELECT extra FROM carts;\n"), {"public.orders.extra", "carts.extra"})
        # A role default or a connection option applies to every query, not only its own file.
        self.write("app/db.js", "const pool = new Pool({ options: '-c search_path=app' });\nmodule.exports = pool;\n")
        self.assertEqual(self.flagged(), {"public.orders.extra"})

    def test_an_unqualified_create_under_a_changed_search_path_declares_nothing(self):
        self.write("db/app.sql", "SET search_path TO app;\nCREATE TABLE refunds (id int);\nCREATE TABLE public.notes (id int);\n")
        self.assertEqual(self.flagged("SELECT extra FROM refunds;\nSELECT extra FROM notes;\n"), {"notes.extra"})

    def test_words_that_only_mention_schema_changes_disable_nothing(self):
        self.write("ios/Views.swift", 'Button("Create table") { }\n')
        self.write("android/Main.kt", 'val label = "Create table"\n')
        self.write("web/admin.php", "<button>Create table</button>\n")
        self.write("lib/helpers.rb", "# uses the create_table helper\n")
        self.write("jooq/Setup.java", "class Setup { void run() { dsl.createTable(ORDERS_T).execute(); } }\n")
        self.write("cache/store.go", 'package cache\nfunc open(name string) { db.Exec("CREATE TABLE IF NOT EXISTS " + name + " (k text)") }\n')
        self.write("docs/migration-guide.yml", 'title: "How to create table"\n')
        self.assertEqual(self.flagged("SELECT extra FROM orders;\n"), {"orders.extra"})
        # A computed ALTER may change any table; a migration whose table cannot be read too.
        self.write("db/migrate/2_rename.rb", "class R < ActiveRecord::Migration[7.1]\n  def change\n"
                                             "    create_table table_name do |t|\n    end\n  end\nend\n")
        self.assertEqual(self.flagged(), set())

    def test_only_a_search_path_the_sql_itself_sets_redirects_names(self):
        self.write("scripts/literal.sql", "SELECT extra FROM orders WHERE extra = 'SET search_path TO app';\n")
        self.write("scripts/comment.sql", "-- SET search_path TO app\nSELECT extra FROM invoices;\n")
        self.write("db/functions.sql", "CREATE FUNCTION f() RETURNS int LANGUAGE sql SECURITY DEFINER SET search_path = public "
                                       "AS $$ SELECT 1 $$;\nCREATE TABLE refunds (id int);\n")
        self.write("app/settings.py", "# note: search_path = public is the default\n")
        self.write("web/help.js", 'export const tip = "Set search_path to app in psql";\n')
        self.assertEqual(self.flagged("SELECT extra FROM carts;\nSELECT extra FROM refunds;\n"),
                         {"orders.extra", "invoices.extra", "carts.extra", "refunds.extra"})
        # A CREATE before the file's SET still declares the default schema's table.
        self.write("db/late.sql", "CREATE TABLE notes (id int);\nSET search_path TO app;\nCREATE TABLE drafts (id int);\n")
        self.assertEqual(self.flagged("SELECT extra FROM notes;\nSELECT extra FROM drafts;\n"),
                         {"orders.extra", "invoices.extra", "notes.extra"})
        # A connection option in code applies to every unqualified name.
        self.write("app/db.py", 'engine = create_engine(url, connect_args={"options": "-c search_path=app"})\n')
        self.assertEqual(self.flagged(), set())

    def test_run_time_ddl_in_test_code_does_not_disable_the_catalog(self):
        self.write("tests/fixtures/grow.sql", "DO $$ BEGIN EXECUTE format('ALTER TABLE %I ADD COLUMN extra int', 'orders'); END $$;\n")
        self.assertEqual(self.flagged("SELECT extra FROM carts;\n"), {"carts.extra"})

    def test_queries_in_tests_specs_and_e2e_suites_are_not_checked(self):
        for path in ("spec/models/order_spec.sql", "e2e/seed.sql", "cypress/support/reset.sql", "tests/q.sql"):
            self.write(path, "SELECT extra FROM orders;\n")
        self.assertEqual(self.flagged("SELECT extra FROM carts;\n"), {"carts.extra"})


@unittest.skipUnless(HAS_SQLGLOT, "install repolens[stack]")
class PrismaCatalogScopeTests(ColumnRepo):
    PRISMA = 'datasource db {\n  provider = "postgresql"\n}\nmodel Users {\n  id    String @id\n  email String\n  @@map("users")\n}\n'

    def test_columns_alter_table_adds_are_part_of_a_prisma_model(self):
        self.write("package.json", "{}")
        self.write("prisma/schema.prisma", self.PRISMA)
        self.write("prisma/migrations/20240101_search/migration.sql", "ALTER TABLE users ADD COLUMN search_vector tsvector;\n")
        self.assertEqual(self.flagged("SELECT search_vector, email FROM users;\nSELECT nope FROM users;\n"), {"users.nope"})

    def test_a_prisma_model_another_orm_or_run_time_ddl_reshapes_is_not_checked(self):
        self.write("package.json", "{}")
        self.write("prisma/schema.prisma", self.PRISMA)
        self.write("knex/1.js", "exports.up = knex => knex.schema.alterTable('users', t => { t.string('nickname'); });\n")
        self.assertEqual(self.flagged("SELECT nickname FROM users;\n"), set())

    def test_a_prisma_schema_applies_to_its_own_package_only(self):
        self.write("apps/api/package.json", "{}")
        self.write("apps/api/prisma/schema.prisma", self.PRISMA)
        self.write("apps/api/q.sql", "SELECT nickname FROM users;\n")
        self.write("apps/web/package.json", "{}")
        self.assertEqual([(i.subject, i.evidence) for i in self.unknown("SELECT nickname FROM users;\n", "apps/web/q.sql")],
                         [("users.nickname", "apps/api/q.sql:1")])

    def test_a_prisma_view_has_unknown_columns(self):
        # Prisma does not own a view's SQL: the block lists mapped fields, not what the view returns.
        self.write("package.json", "{}")
        self.write("prisma/schema.prisma", self.PRISMA + 'view UserTotals {\n  id String @unique\n  @@map("user_totals")\n}\n')
        self.assertEqual(self.flagged("SELECT extra FROM user_totals;\nSELECT nope FROM users;\n"), {"users.nope"})

    def test_a_prisma_schema_in_a_test_fixture_is_not_the_schema(self):
        self.write("package.json", "{}")
        self.write("tests/fixtures/schema.prisma", self.PRISMA)
        self.assertEqual(self.flagged("SELECT nickname FROM users;\n"), set())


@unittest.skipUnless(HAS_STACK, "install repolens[stack]")
class JavaScriptStoreFactTests(ColumnRepo):
    """The store facts the column check sits beside: Prisma accessors and document collections."""

    def stores(self, kind: str) -> set[tuple[str, str]]:
        self.graph = scan_repository(self.root)
        return {(self.graph.nodes[e.target].label, e.evidence.rsplit(":", 1)[0]) for e in self.graph.edges
                if e.kind == "TOUCHES_STORE" and self.graph.nodes[e.target].kind == kind}

    def test_prisma_accessors_use_the_selected_schema_without_comments_or_public(self):
        self.write("package.json", json.dumps({"prisma": {"schema": "prisma/schema.prisma"}}))
        self.write("prisma/schema.prisma", 'datasource db {\n  provider = "postgresql"\n}\n'
                                           "// model Ghost {\n//   id String @id\n// }\n"
                                           'model Users {\n  id String @id\n  @@schema("public")\n  @@map("users") // old: "people"\n}\n')
        self.write("prisma/zz_old.prisma", 'datasource db {\n  provider = "postgresql"\n}\nmodel Users {\n  id String @id\n  @@map("legacy_users")\n}\n')
        self.write("svc.ts", "import { PrismaClient } from '@prisma/client';\nconst prisma = new PrismaClient();\n"
                             "export async function list() { return prisma.users.findMany(); }\n")
        self.assertEqual(self.stores("postgres_table"), {("users", "prisma/schema.prisma"), ("users", "svc.ts")})

    def test_each_package_maps_prisma_accessors_with_its_own_provider(self):
        self.write("apps/inventory/package.json", "{}")
        self.write("apps/inventory/prisma/schema.prisma", 'datasource db {\n  provider = "postgresql"\n}\n'
                                                          'model Item {\n  id String @id\n  @@map("items")\n}\n')
        self.write("apps/inventory/svc.ts", "export const list = () => prisma.item.findMany();\n")
        self.write("apps/events/package.json", "{}")
        self.write("apps/events/prisma/schema.prisma", 'datasource db {\n  provider = "mongodb"\n}\n'
                                                       'model Event {\n  id String @id @map("_id")\n  @@map("events")\n}\n')
        self.write("apps/events/svc.ts", "export const list = () => prisma.event.findMany();\n")
        self.assertEqual(self.stores("postgres_table"), {("items", "apps/inventory/prisma/schema.prisma"),
                                                         ("items", "apps/inventory/svc.ts")})
        self.assertEqual(self.stores("mongo_collection"), {("events", "apps/events/prisma/schema.prisma"),
                                                           ("events", "apps/events/svc.ts")})
        self.assertNotIn("PRISMA_PROVIDER_UNSUPPORTED", {issue.code for issue in self.graph.issues})

    def test_a_package_with_an_unsupported_provider_does_not_borrow_another_packages_table(self):
        self.write("apps/web/package.json", "{}")
        self.write("apps/web/prisma/schema.prisma", 'datasource db {\n  provider = "postgresql"\n}\n'
                                                    'model User {\n  id String @id\n  @@map("users")\n}\n')
        self.write("apps/web/svc.ts", "export const list = () => prisma.user.findMany();\n")
        self.write("apps/legacy/package.json", "{}")
        self.write("apps/legacy/prisma/schema.prisma", 'datasource db {\n  provider = "mysql"\n}\n'
                                                       'model User {\n  id String @id\n  @@map("people")\n}\n')
        self.write("apps/legacy/svc.ts", "export const list = () => prisma.user.findMany();\n")
        self.assertEqual(self.stores("postgres_table"), {("users", "apps/web/prisma/schema.prisma"), ("users", "apps/web/svc.ts")})
        self.assertIn("PRISMA_PROVIDER_UNSUPPORTED", {issue.code for issue in self.graph.issues})

    def test_a_db_receiver_is_a_collection_only_for_a_mongodb_handle(self):
        self.write("sequelize.js", "const db = require('./models');\nasync function find() { return db.User.findOne({}); }\n")
        self.write("memory.js", "const db = { users: [] };\nfunction byId(id) { return db.users.find(u => u.id === id); }\n")
        self.write("prisma.ts", "export class Repo {\n  constructor(private db: any) {}\n"
                                "  async totals() { return this.db.user.aggregate({}); }\n}\n")
        self.write("param.js", "function listing(db) { return db.users.find(u => u.id); }\n")
        self.assertEqual(self.stores("mongo_collection"), set())
        self.write("driver.js", "const { MongoClient } = require('mongodb');\nconst db = new MongoClient('mongodb://x').db('shop');\n"
                                "async function load() { return db.orders.find({}); }\n")
        self.write("conn.ts", "export const client: any = null;\n")
        self.write("service.ts", "import { client } from './conn';\nexport class Baskets {\n  private db = client.db('shop');\n"
                                 "  async load() { return this.db.baskets.find({}); }\n}\n")
        self.write("mongoose.js", "import mongoose from 'mongoose';\nconst db = mongoose.connection.db;\n"
                                  "export async function add() { return db.invoices.insertOne({}); }\n")
        self.write("docker/mongo-init.js", "db = db.getSiblingDB('shop');\ndb.createCollection('carts');\ndb.carts.insertOne({ a: 1 });\n")
        self.assertEqual(self.stores("mongo_collection"), {("orders", "driver.js"), ("baskets", "service.ts"),
                                                           ("invoices", "mongoose.js"), ("carts", "docker/mongo-init.js")})

    def test_a_driver_import_does_not_make_every_db_binding_a_mongodb_handle(self):
        # When the receiver is bound in the file, that binding decides, whatever the file imports.
        self.write("models.js", "const mongoose = require('mongoose');\nconst db = require('./registry');\n"
                                "exports.f = () => db.User.find({});\n")
        self.write("drizzle.ts", "import { drizzle } from 'drizzle-orm/node-postgres';\nimport { MongoClient } from 'mongodb';\n"
                                 "const db = drizzle(pool);\nexport const f = () => db.users.findMany();\nexport const mc = MongoClient;\n")
        self.write("cache.js", "const { MongoClient } = require('mongodb');\nconst db = { cache: new Map() };\n"
                               "exports.f = () => db.sessions.deleteMany({});\n")
        self.write("firestore.js", "const admin = require('firebase-admin');\nconst db = admin.firestore();\n"
                                   "exports.f = () => db.collection('accounts').get();\n")
        self.write("untyped.ts", "export async function save(db) { return db.collection('drafts').insertOne({}); }\n")
        self.assertEqual(self.stores("mongo_collection"), set())
        self.write("conn.ts", "import { MongoClient } from 'mongodb';\nconst client = new MongoClient('mongodb://x');\n"
                              "export const db = client.db('shop');\n")
        self.write("imported.ts", "import { db } from './conn';\nexport const f = () => db.collection('orders').find({});\n")
        self.write("typed.ts", "import type { Db } from 'mongodb';\nexport const g = (db: Db) => db.collection('invoices').find({});\n")
        self.write("chained.js", "const { MongoClient } = require('mongodb');\nconst client = new MongoClient('mongodb://x');\n"
                                 "exports.h = () => client.db('shop').collection('carts').find({});\n")
        self.write("connection.js", "const mongoose = require('mongoose');\n"
                                    "exports.i = () => mongoose.connection.collection('events').insertOne({});\n")
        self.write("global.js", "const { MongoClient } = require('mongodb');\nexports.j = () => db.baskets.find({});\n")
        self.assertEqual(self.stores("mongo_collection"), {("orders", "imported.ts"), ("invoices", "typed.ts"),
                                                           ("carts", "chained.js"), ("events", "connection.js"),
                                                           ("baskets", "global.js")})

    def test_clearing_comments_nested_arguments_and_other_receivers_do_not_hide_a_handle(self):
        driver = "const { MongoClient } = require('mongodb');\nconst client = new MongoClient('mongodb://x');\n"
        self.write("commented.js", driver + "// db = null when disconnected\nconst db = client.db('shop');\n"
                                            "exports.f = () => db.orders.find({});\n")
        self.write("closed.js", driver + "let db = client.db('shop');\nexports.f = () => db.invoices.find({});\n"
                                         "exports.close = async () => { await client.close(); db = null; };\n")
        self.write("nested.js", driver + "exports.f = () => client.db(cfg.name()).collection('users').find({});\n")
        self.write("shared_line.js", driver + "const db = client.db('shop');\nconst other = { collection: () => null };\n"
                                              "exports.f = () => { db.collection('carts').find({}); other.collection('carts'); };\n")
        self.assertEqual(self.stores("mongo_collection"), {("orders", "commented.js"), ("invoices", "closed.js"),
                                                           ("users", "nested.js"), ("carts", "shared_line.js")})

    def test_mongodb_handle_checks_do_not_repeat_per_call_site(self):
        # Every call site re-read the whole file's bindings: 1000 calls took over ten seconds.
        import time
        from repolens.impact.scanner import _mongo_bindings
        calls = "".join(f"exports.f{i} = () => db.orders{i % 50}.find({{}});\n"
                        f"exports.g{i} = () => db.collection('c{i % 50}').find({{}});\n" for i in range(1000))
        self.write("big.js", "const { MongoClient } = require('mongodb');\nconst db = new MongoClient('mongodb://x').db('shop');\n"
                             + calls)
        started = time.monotonic()
        found = self.stores("mongo_collection")
        self.assertLess(time.monotonic() - started, 8)
        self.assertEqual(len(found), 100)
        started = time.monotonic()
        _mongo_bindings("configure({ " + "db: 1, " * 4000 + "});\n", "db", member=False, collection=False)
        self.assertLess(time.monotonic() - started, 2)

    def test_the_regex_fallback_needs_the_same_mongodb_handle_evidence(self):
        from unittest import mock
        self.write("sequelize.js", "const db = require('./models');\nasync function find() { return db.User.findOne({}); }\n")
        self.write("memory.js", "const db = { users: [] };\nfunction byId(id) { return db.users.find(u => u.id === id); }\n")
        self.write("driver.js", "const { MongoClient } = require('mongodb');\nconst db = new MongoClient('mongodb://x').db('shop');\n"
                                "async function load() { return db.orders.find({}); }\n")
        self.write("registry.js", "const mongoose = require('mongoose');\nconst db = require('./models');\n"
                                  "exports.f = () => db.users.find({});\n")
        with mock.patch.object(javascript, "available", return_value=False):
            self.assertEqual(self.stores("mongo_collection"), {("orders", "driver.js")})


if __name__ == "__main__":
    unittest.main()
