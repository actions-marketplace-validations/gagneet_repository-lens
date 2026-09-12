"""PostgreSQL syntax references, never a live schema or query-plan assertion."""
from __future__ import annotations

from .model import Edge, Graph, Issue, Node, stable_id


def add_sql(graph: Graph, source: str, sql: str, location: str, *, dynamic: bool = False) -> None:
    try:
        import sqlglot
        from sqlglot import exp
        from sqlglot.optimizer.scope import traverse_scope
    except ImportError:
        graph.issues.append(Issue("SQL_PARSER_UNAVAILABLE", "warning", "PostgreSQL parser is unavailable.",
                                  [source], location, "Install repolens[stack] to analyze SQL syntax."))
        return
    if dynamic:
        graph.issues.append(Issue("DYNAMIC_SQL", "info", "SQL contains runtime interpolation.",
                                  [source], location, "Review parameterization and any dynamic identifiers."))
        # Dynamic identifiers cannot safely be turned into a concrete table name.
        return
    try:
        expressions = sqlglot.parse(sql, read="postgres", error_level=sqlglot.errors.ErrorLevel.RAISE)
    except (sqlglot.errors.SqlglotError, RecursionError):
        graph.issues.append(Issue("SQL_PARSE_ERROR", "warning", "SQL could not be parsed as PostgreSQL.",
                                  [source], location, "Check the SQL dialect, interpolation and parser support."))
        return
    for expression in expressions:
        if expression is None:
            continue
        if isinstance(expression, exp.Command):
            graph.issues.append(Issue("SQL_UNSUPPORTED_STATEMENT", "info", "SQL statement has no supported syntax tree.",
                                      [source], location, "Review this statement manually."))
            continue
        tables = []
        # Scope-aware sources exclude CTE names and derived-table aliases.
        for scope in traverse_scope(expression):
            for _, resolved in scope.selected_sources.values():
                if isinstance(resolved, exp.Table):
                    tables.append((resolved, "reads"))
        if isinstance(expression, (exp.Insert, exp.Update, exp.Delete, exp.Create, exp.Alter, exp.Drop)):
            target = expression.this
            if isinstance(target, exp.Schema):
                target = target.this
            if isinstance(target, exp.Table):
                tables.append((target, "writes" if isinstance(expression, (exp.Insert, exp.Update, exp.Delete)) else "declares"))
            ctes = {cte.alias for cte in expression.find_all(exp.CTE)}
            for table in expression.find_all(exp.Table):
                if table is not target and (table.db or table.name not in ctes):
                    tables.append((table, "reads"))
        operations: dict[str, set[str]] = {}
        for table, relationship in tables:
            if not isinstance(table.this, exp.Identifier):
                continue
            name = ".".join(part.name for part in table.parts)
            operations.setdefault(name, set()).add(relationship)
        for name, relationships in operations.items():
            node_id = stable_id("postgres_table", name)
            graph.add_node(Node(node_id, "postgres_table", name,
                                metadata={"store": name, "dialect": "postgres", "catalog_verified": False}))
            graph.add_edge(Edge(
                source, node_id, "TOUCHES_STORE", "probable", location,
                origin="sqlglot",
                detail=f"SQL syntax reference ({', '.join(sorted(relationships))}); live schema and runtime access unverified",
            ))
