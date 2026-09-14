"""`performance/unbounded-sql-fetch`: grouped aggregates and `[scan.performance] scope_key_patterns`."""
from __future__ import annotations

import ast
import tempfile
import textwrap
import unittest
from pathlib import Path

from repolens.config import load_config
from repolens.core.findings import Finding
from repolens.scan import performance
from repolens.scan.settings import from_config

RULE = "performance/unbounded-sql-fetch"

GROUPED = '''
    from sqlalchemy import func, select

    async def counts_per_status(conn):
        return await conn.fetch("SELECT status, count(*) AS n FROM orders GROUP BY status")

    async def sums_per_month(conn):
        return await conn.fetch(
            "SELECT date_trunc('month', created_at) AS month, coalesce(sum(total), 0) "
            "FROM invoices WHERE paid GROUP BY date_trunc('month', created_at) ORDER BY month")

    async def by_position_with_a_constant(conn):
        return await conn.fetch("SELECT o.status AS state, 'orders' AS source, count(*) FROM orders o GROUP BY 1")

    async def grouped_by_output_alias(conn):
        return await conn.fetch("SELECT lower(status) AS state, max(total) FROM orders GROUP BY state")

    async def filtered_aggregate_after_a_cte(conn):
        return await conn.fetch(
            "WITH recent AS (SELECT * FROM orders WHERE created_at > now() - interval '1 day') "
            "SELECT status, count(*) FILTER (WHERE paid) FROM recent GROUP BY status")

    async def orm_grouped(session):
        stmt = select(Order.status, func.count(Order.id).label("n")).group_by(Order.status)
        return (await session.execute(stmt)).all()

    def legacy_orm_grouped(db):
        return db.query(Order.status, func.sum(Order.total)).group_by(Order.status).all()

    async def one_row_per_account(conn):
        return await conn.fetch(
            "SELECT a.id, a.name, count(*) FROM accounts a JOIN orders o ON o.account_id = a.id GROUP BY a.id")

    async def orm_grouped_with_another_column(session):
        stmt = select(Order.status, Order.customer_id, func.count()).group_by(Order.status)
        return (await session.execute(stmt)).all()

    async def group_by_only_inside_a_string(conn):
        return await conn.fetch("SELECT id, note FROM orders WHERE note = 'GROUP BY status'")

    async def every_row(conn):
        return await conn.fetch("SELECT id, total FROM orders")
'''

SCOPED = '''
    from fastapi import FastAPI
    from sqlalchemy import select

    app = FastAPI()

    @app.get("/orders")
    async def list_orders(account_id: str, conn):
        return await conn.fetch("SELECT id, total FROM orders WHERE account_id = $1")

    async def one_account(conn, account_id):
        return await conn.fetch("SELECT id, total FROM orders o WHERE o.account_id = ANY($1) AND paid")

    async def orm_one_account(session, account_id):
        stmt = select(Order).where(Order.account_id == account_id)
        return (await session.execute(stmt)).scalars().all()

    def legacy_one_account(db, account_id):
        return db.query(Order).filter_by(account_id=account_id).all()

    async def joined_not_filtered(conn):
        return await conn.fetch("SELECT o.id FROM orders o, accounts a WHERE o.account_id = a.id")

    async def orm_joined_not_filtered(session):
        return (await session.execute(select(Order).where(Order.account_id == Account.id))).scalars().all()

    async def another_column(conn, status):
        return await conn.fetch("SELECT id FROM orders WHERE status = $1")
'''


def _fetches(source: str, toml: str = "") -> dict[str, Finding]:
    """Function name -> its unbounded-fetch finding, for `source` scanned as `svc/orders.py`."""
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "repolens.toml").write_text('[scan]\npython_roots = ["."]\n' + toml, encoding="utf-8")
        (root / "svc").mkdir()
        (root / "svc" / "orders.py").write_text(textwrap.dedent(source), encoding="utf-8")
        findings = [f for f in performance.scan(from_config(load_config(str(root)))) if f.rule == RULE]
    tree = ast.parse(textwrap.dedent(source))
    spans = [(fn.lineno, fn.end_lineno, fn.name) for fn in ast.walk(tree)
             if isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef))]
    return {next(name for start, end, name in spans if start <= f.line <= end): f for f in findings}


class GroupedAggregateTests(unittest.TestCase):
    def test_one_row_per_group_is_not_an_unbounded_fetch_and_other_projections_still_are(self):
        self.assertEqual(sorted(_fetches(GROUPED)), ["every_row", "group_by_only_inside_a_string",
                                                     "one_row_per_account", "orm_grouped_with_another_column"])


class ScopeKeyTests(unittest.TestCase):
    SCOPE = '[scan.performance]\nscope_key_patterns = ["^account_id$"]\n'

    def test_without_patterns_nothing_is_scoped(self):
        found = _fetches(SCOPED)
        self.assertEqual(len(found), 7)
        self.assertEqual(found["list_orders"].severity, "medium")
        self.assertEqual({f.severity for name, f in found.items() if name != "list_orders"}, {"low"})
        self.assertFalse(any("scope key" in f.message for f in found.values()))

    def test_a_filter_on_a_scope_key_lowers_the_severity_and_names_the_column(self):
        found = _fetches(SCOPED, self.SCOPE)
        scoped = {"list_orders", "one_account", "orm_one_account", "legacy_one_account"}
        self.assertEqual({name for name, f in found.items() if "filtered on scope key `account_id`" in f.message}, scoped)
        self.assertEqual(found["list_orders"].severity, "low")
        self.assertEqual({found[name].severity for name in scoped - {"list_orders"}}, {"info"})
        for name in ("joined_not_filtered", "orm_joined_not_filtered", "another_column"):
            self.assertEqual(found[name].severity, "low", name)
        self.assertEqual({f.confidence for f in found.values()}, {"low"})

    def test_the_scope_note_does_not_change_the_fingerprint(self):
        plain, scoped = _fetches(SCOPED), _fetches(SCOPED, self.SCOPE)
        self.assertNotEqual(plain["one_account"].message, scoped["one_account"].message)
        self.assertEqual({n: f.fingerprint for n, f in plain.items()}, {n: f.fingerprint for n, f in scoped.items()})


if __name__ == "__main__":
    unittest.main()
