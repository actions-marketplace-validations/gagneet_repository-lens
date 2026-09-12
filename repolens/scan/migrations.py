"""Static checks for database migrations: the one place a schema change is written down
before it runs against a database that already holds data.

Alembic migrations are read with the AST, never with a regex over the file, and in the
order `upgrade()` runs them:

  * a loop over a literal list or tuple, or over a module-level one, is unrolled, so
    `for schema, table in TABLES: op.execute(f"ALTER TABLE {schema}.{table} ...")` is one
    statement per table;
  * a module function that upgrade() calls is read with the literal arguments it was
    given; a function only `downgrade()` calls is not read, because a downgrade that
    disables what the upgrade enabled is doing its job;
  * text passed to print() or a logger, and `comment=` / `doc=` / `info=` keywords, are
    messages about SQL, not SQL.

SQL text is split into statements with its comments removed, and an ALTER TABLE into its
actions, so `ENABLE ROW LEVEL SECURITY, FORCE ROW LEVEL SECURITY` counts as both.

  revision-id-too-long             the revision string is wider than the version table's
                                   column. The DDL applies, then recording the revision
                                   fails and PostgreSQL rolls the whole migration back.
  not-null-column-without-default  `add_column(Column(..., nullable=False))`, or
                                   `ALTER TABLE ... ADD COLUMN ... NOT NULL`, with no
                                   default: fails on any table that has rows.
  rls-without-force                row-level security ends ENABLED and not FORCEd: the
                                   table's owner is exempt from every policy on it.
  view-without-security-invoker    a view evaluates the row-level security of the tables
                                   under it as the VIEW OWNER unless it is created with
                                   security_invoker. Checked only where migrations use RLS.
  index-not-concurrent             CREATE INDEX on a table the migration did not create,
                                   without CONCURRENTLY, blocks writes for the whole build.
  table-without-rls                (opt-in: require_rls) a table created in an RLS schema
                                   that no migration secures.

What this cannot see. A name still computed after that walk (a parameter nobody passed a
literal, a list built at run time) is matched by its template: a computed ENABLE is taken
as paired with a computed FORCE in the same file, and a literal ENABLE left unforced is
reported with low confidence while a migration from that one on FORCEs a computed name.
Files run in their sort order. Whether a table is empty, the one case where a NOT NULL
column with no default is harmless, needs the database; a table created by the same
migration is taken as empty.

Configured by `[scan.migrations]` in repolens.toml.
"""
from __future__ import annotations

import ast
import os
import re
from dataclasses import dataclass, field
from pathlib import Path

from ..core.findings import Finding
from .python_ast import keyword_value, last, parse
from .settings import ScanSettings

TOOL = "migrations"
_VERSION_DIRS = (("alembic", "versions"), ("migrations", "versions"))
# Test fixtures hold migrations on purpose, often broken ones; they are not the schema.
_PRUNE = frozenset({".git", "node_modules", "venv", ".venv", "env", "__pycache__",
                    "site-packages", "dist", "build", ".next", ".tox",
                    "tests", "test", "fixtures", "testdata"})
#: Most values one loop or helper call is unrolled into.
_MAX_UNROLL = 256
#: Env key a `with op.batch_alter_table(...) as <name>:` binds (not a Python identifier).
_BATCH = "\0batch:"

# A table or view name: bare or schema-qualified, optionally quoted, or a template
# placeholder (`{table}`, `%s`) standing for one.
_NAME = r'"?[A-Za-z_{%][\w{}%]*"?(?:\."?[A-Za-z_{%][\w{}%]*"?)?'
_ALTER_TABLE = re.compile(rf"\bALTER\s+TABLE\s+(?:IF\s+EXISTS\s+)?(?:ONLY\s+)?({_NAME})\s+(.*)\Z",
                          re.IGNORECASE | re.DOTALL)
_RLS_ACTION = re.compile(r"(NO\s+FORCE|FORCE|ENABLE|DISABLE)\s+ROW\s+LEVEL\s+SECURITY\b", re.IGNORECASE)
_ADD_COLUMN = re.compile(r'ADD\s+(?:COLUMN\s+)?(?:IF\s+NOT\s+EXISTS\s+)?("?[A-Za-z_]\w*"?)\s+(.*)\Z',
                         re.IGNORECASE | re.DOTALL)
_ADD_NOT_A_COLUMN = frozenset({"CONSTRAINT", "PRIMARY", "UNIQUE", "FOREIGN", "CHECK", "EXCLUDE"})
_FILLS_EVERY_ROW = re.compile(r"\b(DEFAULT|GENERATED|(SMALL|BIG)?SERIAL)\b", re.IGNORECASE)
_VIEW = re.compile(rf"CREATE\s+(?:OR\s+REPLACE\s+)?(?:(?:TEMP|TEMPORARY|RECURSIVE)\s+)*VIEW\s+"
                   rf"({_NAME})(.{{0,500}}?)\bAS\b", re.IGNORECASE | re.DOTALL)
_ALTER_VIEW = re.compile(rf"ALTER\s+VIEW\s+(?:IF\s+EXISTS\s+)?({_NAME})\s+SET\s*\((.*?)\)", re.IGNORECASE | re.DOTALL)
_INVOKER = re.compile(r"security_invoker\s*(?:=\s*'?(\w+)'?)?", re.IGNORECASE)
_CREATE_TABLE = re.compile(rf"CREATE\s+(?:UNLOGGED\s+)?TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?({_NAME})", re.IGNORECASE)
# Anything an index can be built on: a temporary table or a materialized view is as new
# as a table, and holds no rows another session is waiting to write.
_CREATE_RELATION = re.compile(rf"CREATE\s+(?:OR\s+REPLACE\s+)?(?:(?:GLOBAL|LOCAL)\s+)?"
                              rf"(?:(?:TEMP|TEMPORARY|UNLOGGED)\s+)?(?:TABLE|MATERIALIZED\s+VIEW)\s+"
                              rf"(?:IF\s+NOT\s+EXISTS\s+)?({_NAME})", re.IGNORECASE)
_CREATE_INDEX = re.compile(rf"CREATE\s+(?:UNIQUE\s+)?INDEX\s+(CONCURRENTLY\s+)?(?:IF\s+NOT\s+EXISTS\s+)?"
                           rf"(?:{_NAME}\s+)?ON\s+(?:ONLY\s+)?({_NAME})", re.IGNORECASE)
_MESSAGE_CALLS = frozenset({"print", "debug", "info", "warning", "warn", "error", "exception",
                            "critical", "log", "echo", "secho"})
_NOT_SQL_KEYWORDS = frozenset({"comment", "doc", "info", "help", "description"})


def _norm(name: str) -> str:
    return name.replace('"', "").lower()


def _templated(name: str) -> bool:
    return "{" in name or "%" in name


def _bare(name: str) -> str:
    return name.rsplit(".", 1)[-1]


def _same_table(a: str, b: str) -> bool:
    """Two qualified names match only exactly; a bare name matches on its last part."""
    if a == b:
        return True
    if "." in a and "." in b:
        return False
    return _bare(a) == _bare(b)


def _invoker_on(options: str) -> bool:
    match = _INVOKER.search(options)
    return bool(match) and (match.group(1) or "true").lower() not in ("false", "off", "0", "no")


# ── SQL text ─────────────────────────────────────────────────────────────────────
def _statements(text: str) -> list[str]:
    """SQL split on `;`, comments dropped, quoted text kept whole. Dollar-quoted bodies
    are split too: the statements inside a DO block are statements."""
    out: list[str] = []
    buf: list[str] = []
    i, n = 0, len(text)
    while i < n:
        if text.startswith("--", i):
            end = text.find("\n", i)
            i = n if end < 0 else end
            continue
        if text.startswith("/*", i):
            end = text.find("*/", i + 2)
            i = n if end < 0 else end + 2
            buf.append(" ")
            continue
        c = text[i]
        if c in "'\"":
            j = i + 1
            while j < n and not (text[j] == c and not text.startswith(c * 2, j)):
                j += 2 if text.startswith(c * 2, j) else 1
            buf.append(text[i:j + 1])
            i = j + 1
            continue
        if c == ";":
            out.append("".join(buf))
            buf = []
        else:
            buf.append(c)
        i += 1
    out.append("".join(buf))
    return [s.strip() for s in out if s.strip()]


def _split_top(text: str) -> list[str]:
    """`a, b (c, d), 'e, f'` -> [a, b (c, d), 'e, f']: commas outside brackets and quotes."""
    parts: list[str] = []
    depth, start, quote = 0, 0, ""
    for i, c in enumerate(text):
        if quote:
            quote = "" if c == quote else quote
        elif c in "'\"":
            quote = c
        elif c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
        elif c == "," and depth == 0:
            parts.append(text[start:i])
            start = i + 1
    parts.append(text[start:])
    return [p.strip() for p in parts if p.strip()]


# ── reading the AST ──────────────────────────────────────────────────────────────
Env = dict[str, str]


def _hole(node: ast.AST, env: Env) -> str:
    """An interpolated value: its literal when the walk knows it, else `{its_source}`."""
    if isinstance(node, ast.Name) and node.id in env:
        return env[node.id]
    return "{" + (re.sub(r"\W+", "_", ast.unparse(node)).strip("_") or "value") + "}"


def _render(node: ast.AST | None, env: Env) -> str | None:
    """The text of a string expression (a literal, an f-string, `+` of them); None for
    anything that is not one."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.JoinedStr):
        return "".join(v.value if isinstance(v, ast.Constant) else _hole(v.value, env)
                       for v in node.values if isinstance(v, (ast.Constant, ast.FormattedValue)))
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left, right = _render(node.left, env), _render(node.right, env)
        if left is None and right is None:
            return None
        return ((_hole(node.left, env) if left is None else left)
                + (_hole(node.right, env) if right is None else right))
    return None


def _literal(node: ast.AST, env: Env) -> str | tuple[str, ...] | None:
    """A value a loop can be unrolled over: a string, or a tuple/list of strings."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.Name) and node.id in env:
        return env[node.id]
    if isinstance(node, (ast.Tuple, ast.List)):
        items = [_literal(e, env) for e in node.elts]
        return tuple(items) if all(isinstance(i, str) for i in items) else None  # type: ignore[arg-type]
    return None


def _string(node: ast.AST | None, env: Env) -> str | None:
    value = _literal(node, env) if node is not None else None
    return value if isinstance(value, str) else _render(node, env)


def _bind(target: ast.AST, value: str | tuple[str, ...]) -> Env | None:
    if isinstance(target, ast.Name) and isinstance(value, str):
        return {target.id: value}
    if (isinstance(target, (ast.Tuple, ast.List)) and isinstance(value, tuple)
            and len(value) == len(target.elts) and all(isinstance(t, ast.Name) for t in target.elts)):
        return {t.id: v for t, v in zip(target.elts, value)}  # type: ignore[union-attr]
    return None


def _arg(call: ast.Call, position: int, keyword: str, env: Env) -> str | None:
    node = call.args[position] if len(call.args) > position else keyword_value(call, keyword)
    return _string(node, env)


def _qualified(call: ast.Call, table: str, env: Env) -> str:
    schema = _string(keyword_value(call, "schema"), env)
    return _norm(f"{schema}.{table}" if schema else table)


@dataclass
class _Sql:
    text: str
    line: int


@dataclass
class _Call:
    node: ast.Call
    env: Env

    def batch_table(self) -> str | None:
        """`batch_op.create_index(...)` inside `with op.batch_alter_table("t") as batch_op`."""
        func = self.node.func
        if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
            return self.env.get(_BATCH + func.value.id)
        return None


@dataclass
class _Migration:
    rel: str
    revision: tuple[str, int] | None = None
    sql: list[_Sql] = field(default_factory=list)
    calls: list[_Call] = field(default_factory=list)
    created: dict[str, int] = field(default_factory=dict)       # table -> line created
    relations: set[str] = field(default_factory=set)            # anything an index can be on
    rls: list[tuple[int, str, str]] = field(default_factory=list)          # (line, table, action)
    added: list[tuple[int, str, str, str]] = field(default_factory=list)   # raw ADD COLUMN

    def made(self, table: str) -> bool:
        """Did this migration create `table` (so it holds no rows and no waiting writes)?"""
        return any(_same_table(table, t) for t in self.relations)


class _Walker:
    """Reads a migration's functions the way upgrade() runs them."""

    def __init__(self, tree: ast.Module, m: _Migration):
        self.m = m
        self.constants = _module_strings(tree)
        self.sequences: dict[str, list[ast.expr]] = {}
        self.globals: Env = {}
        self.functions: dict[str, ast.FunctionDef | ast.AsyncFunctionDef] = {}
        self._seen: set[tuple[int, tuple[tuple[str, str], ...]]] = set()
        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self.functions[node.name] = node
            elif isinstance(node, (ast.Assign, ast.AnnAssign)) and node.value is not None:
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                for target in (t for t in targets if isinstance(t, ast.Name)):
                    if isinstance(node.value, (ast.List, ast.Tuple, ast.Set)):
                        self.sequences[target.id] = node.value.elts
                    elif isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                        self.globals[target.id] = node.value.value

    def read(self) -> None:
        upgrade = self.functions.get("upgrade")
        # No upgrade(): not Alembic's shape, so every function but downgrade() is read.
        entries = [upgrade] if upgrade else [f for n, f in self.functions.items() if n != "downgrade"]
        for fn in entries:
            self._function(fn, dict(self.globals), (fn.name,))

    def _function(self, fn: ast.FunctionDef | ast.AsyncFunctionDef, env: Env, stack: tuple[str, ...]) -> None:
        body = fn.body
        if body and isinstance(body[0], ast.Expr) and _render(body[0].value, {}) is not None:
            body = body[1:]  # the docstring describes the SQL; it does not run it
        self._block(body, env, stack)

    def _block(self, stmts: list[ast.stmt], env: Env, stack: tuple[str, ...]) -> None:
        for stmt in stmts:
            self._stmt(stmt, env, stack)

    def _stmt(self, stmt: ast.stmt, env: Env, stack: tuple[str, ...]) -> None:
        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            return
        if isinstance(stmt, (ast.For, ast.AsyncFor)):
            envs = self._unroll(stmt, env)
            if envs is not None:
                for each in envs:
                    self._block(stmt.body, each, stack)
                self._block(stmt.orelse, env, stack)
                return
        if isinstance(stmt, (ast.With, ast.AsyncWith)):
            env = self._batches(stmt, env)
        for _, value in ast.iter_fields(stmt):
            for item in value if isinstance(value, list) else [value]:
                if isinstance(item, ast.stmt):
                    self._stmt(item, env, stack)
                elif isinstance(item, (ast.excepthandler, ast.match_case)):
                    self._block(item.body, env, stack)
                elif isinstance(item, ast.withitem):
                    self._expr(item.context_expr, env, stack)
                elif isinstance(item, ast.expr):
                    self._expr(item, env, stack)

    def _unroll(self, loop: ast.For | ast.AsyncFor, env: Env) -> list[Env] | None:
        values = self._sequence(loop.iter, env)
        if values is None:
            return None
        envs = []
        for value in values[:_MAX_UNROLL]:
            bound = _bind(loop.target, value)
            if bound is None:
                return None
            envs.append({**env, **bound})
        return envs

    def _sequence(self, node: ast.AST, env: Env) -> list[str | tuple[str, ...]] | None:
        if (isinstance(node, ast.Call) and last(node.func) in ("reversed", "sorted", "list", "tuple")
                and len(node.args) == 1):
            return self._sequence(node.args[0], env)
        items = (node.elts if isinstance(node, (ast.List, ast.Tuple, ast.Set))
                 else self.sequences.get(node.id) if isinstance(node, ast.Name) else None)
        if items is None:
            return None
        values = [_literal(e, env) for e in items]
        return None if any(v is None for v in values) else values  # type: ignore[return-value]

    def _batches(self, stmt: ast.With | ast.AsyncWith, env: Env) -> Env:
        for item in stmt.items:
            call = item.context_expr
            if (isinstance(call, ast.Call) and last(call.func) == "batch_alter_table"
                    and isinstance(item.optional_vars, ast.Name)
                    and (table := _arg(call, 0, "table_name", env))):
                env = {**env, _BATCH + item.optional_vars.id: _qualified(call, table, env)}
        return env

    def _expr(self, node: ast.AST, env: Env, stack: tuple[str, ...]) -> None:
        if isinstance(node, ast.Lambda):
            return
        if isinstance(node, ast.Call):
            if last(node.func) in _MESSAGE_CALLS:
                return  # a message about the SQL, not the SQL
            key = (id(node), tuple(sorted(env.items())))
            if key not in self._seen:
                self._seen.add(key)
                self.m.calls.append(_Call(node, env))
            self._expr(node.func, env, stack)
            for arg in node.args:
                self._expr(arg, env, stack)
            for kw in node.keywords:
                if kw.arg not in _NOT_SQL_KEYWORDS:
                    self._expr(kw.value, env, stack)
            name = node.func.id if isinstance(node.func, ast.Name) else ""
            if name in self.functions and name not in stack and name != "downgrade":
                self._call(self.functions[name], node, env, stack)
            return
        text = _render(node, env)
        if text is not None:
            self.m.sql.append(_Sql(text, getattr(node, "lineno", 0)))
            return
        if isinstance(node, ast.Name) and node.id in self.constants:
            self.m.sql.extend(self.constants[node.id])
            return
        for child in ast.iter_child_nodes(node):
            self._expr(child, env, stack)

    def _call(self, fn: ast.FunctionDef | ast.AsyncFunctionDef, call: ast.Call, env: Env,
              stack: tuple[str, ...]) -> None:
        """Read a module helper with the literal arguments this call passes; a parameter
        passed anything else stays a `{parameter}` template."""
        params = [a.arg for a in [*fn.args.posonlyargs, *fn.args.args]]
        bound = dict(self.globals)
        for name, arg in zip(params, call.args):
            if isinstance(value := _literal(arg, env), str):
                bound[name] = value
        for kw in call.keywords:
            if kw.arg in params and isinstance(value := _literal(kw.value, env), str):
                bound[kw.arg] = value
        self._function(fn, bound, (*stack, fn.name))


def _module_strings(tree: ast.Module) -> dict[str, list[_Sql]]:
    """Module constants holding SQL: `VIEW_SQL = \"\"\"...\"\"\"`, or a list of statements."""
    out: dict[str, list[_Sql]] = {}
    for node in tree.body:
        if isinstance(node, (ast.Assign, ast.AnnAssign)) and node.value is not None:
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            values = node.value.elts if isinstance(node.value, (ast.List, ast.Tuple)) else [node.value]
            texts = [_Sql(t, v.lineno) for v in values if (t := _render(v, {})) is not None]
            for target in targets:
                if isinstance(target, ast.Name) and texts:
                    out[target.id] = texts
    return out


def _read(s: ScanSettings, path: Path) -> _Migration | None:
    tree = parse(str(path))
    if tree is None:
        return None
    m = _Migration(s.rel(path))
    for node in tree.body:
        value = node.value if isinstance(node, (ast.Assign, ast.AnnAssign)) else None
        targets = (node.targets if isinstance(node, ast.Assign) else
                   [node.target] if isinstance(node, ast.AnnAssign) else [])
        if (any(isinstance(t, ast.Name) and t.id == "revision" for t in targets)
                and isinstance(value, ast.Constant) and isinstance(value.value, str)):
            m.revision = (value.value, node.lineno)
    _Walker(tree, m).read()
    for c in m.calls:
        if last(c.node.func) == "create_table" and (table := _arg(c.node, 0, "table_name", c.env)):
            m.created.setdefault(_qualified(c.node, table, c.env), c.node.lineno)
    for sql in m.sql:
        for stmt in _statements(sql.text):
            for table in _CREATE_TABLE.findall(stmt):
                m.created.setdefault(_norm(table), sql.line)
            m.relations.update(_norm(t) for t in _CREATE_RELATION.findall(stmt))
            alter = _ALTER_TABLE.search(stmt)
            if alter is None:
                continue
            table = _norm(alter.group(1))
            for action in _split_top(alter.group(2)):
                if rls := _RLS_ACTION.match(action):
                    m.rls.append((sql.line, table, " ".join(rls.group(1).lower().split())))
                elif (add := _ADD_COLUMN.match(action)) and add.group(1).upper() not in _ADD_NOT_A_COLUMN:
                    m.added.append((sql.line, table, _norm(add.group(1)), add.group(2)))
    m.relations.update(m.created)
    return m


def migration_roots(s: ScanSettings) -> list[Path]:
    """Configured roots, or every `alembic/versions` / `migrations/versions` directory
    outside a test tree."""
    if s.migrations.roots:
        return [s.root / r for r in s.migrations.roots if (s.root / r).is_dir()]
    found: list[Path] = []
    for dirpath, dirnames, _ in os.walk(s.root):
        rel = Path(dirpath).relative_to(s.root)
        if tuple(rel.parts[-2:]) in _VERSION_DIRS:
            found.append(Path(dirpath))
            dirnames[:] = []
            continue
        dirnames[:] = sorted(d for d in dirnames if d not in _PRUNE and not d.startswith("."))
    return found


def migration_files(s: ScanSettings) -> list[Path]:
    """Every migration module under the migration roots, sorted, without `__init__.py`."""
    return sorted(p for root in migration_roots(s) for p in root.glob("*.py")
                  if p.name != "__init__.py")


# ── the rules ────────────────────────────────────────────────────────────────────
def _revision(m: _Migration, width: int) -> list[Finding]:
    if m.revision is None or len(m.revision[0]) <= width:
        return []
    value, line = m.revision
    return [Finding(
        tool=TOOL, rule="migrations/revision-id-too-long", severity="high", confidence="high",
        category="correctness", file=m.rel, line=line,
        message=f"revision {value!r} is {len(value)} characters and the version table's column "
                f"holds {width}: the DDL applies, then recording the revision fails and the "
                "whole migration rolls back",
        remedy="Shorten the revision (and the file name with it) to `NNNN_few_words`, and "
               "update `down_revision` in the migration that follows it.",
    )]


def _not_null_finding(m: _Migration, line: int, table: str, column: str) -> Finding:
    return Finding(
        tool=TOOL, rule="migrations/not-null-column-without-default", severity="high",
        confidence="medium", category="correctness", file=m.rel, line=line,
        message=f"add column {table}.{column} is NOT NULL with no default: on a table that "
                "already has rows the ALTER fails, and the deploy with it",
        remedy="Give it a server default (a Python-side `default=` does not reach the DDL), "
               "or add it nullable, backfill it, then alter it to NOT NULL.",
    )


def _not_null(m: _Migration) -> list[Finding]:
    out: list[Finding] = []
    for c in m.calls:
        call = c.node
        if last(call.func) != "add_column":
            continue
        column = next((a for a in [*call.args, *(k.value for k in call.keywords)]
                       if isinstance(a, ast.Call) and last(a.func) == "Column"), None)
        if column is None:
            continue
        nullable = keyword_value(column, "nullable")
        default = keyword_value(column, "server_default")
        if not (isinstance(nullable, ast.Constant) and nullable.value is False):
            continue
        if default is not None and not (isinstance(default, ast.Constant) and default.value is None):
            continue
        if any(isinstance(a, ast.Call) and last(a.func) in ("Identity", "Computed")
               for a in [*column.args, *(k.value for k in column.keywords)]):
            continue  # the database fills every existing row
        named = _arg(call, 0, "table_name", c.env)
        table = c.batch_table() or (_qualified(call, named, c.env) if named else None)
        if table and m.made(table):
            continue  # created by this migration, so it has no rows yet
        name = _string(column.args[0], c.env) if column.args else None
        out.append(_not_null_finding(m, call.lineno, table or "(batch table)", name or "?"))
    for line, table, column, definition in m.added:
        if (re.search(r"\bNOT\s+NULL\b", definition, re.IGNORECASE)
                and not _FILLS_EVERY_ROW.search(definition) and not m.made(table)):
            out.append(_not_null_finding(m, line, table, column))
    return out


def _rls(migrations: list[_Migration]) -> tuple[list[Finding], bool]:
    events = [(i, m, line, table, action) for i, m in enumerate(migrations)
              for line, table, action in m.rls]
    computed_force = [i for i, _, _, table, action in events if action == "force" and _templated(table)]
    last_computed_force = max(computed_force, default=-1)
    out: list[Finding] = []
    for key in sorted({table for _, _, _, table, _ in events if not _templated(table)}):
        enabled = forced = False
        site: tuple[int, _Migration, int, str] | None = None
        for i, m, line, table, action in events:
            if _templated(table) or not _same_table(key, table):
                continue
            if action == "enable":
                enabled, site = True, (i, m, line, table)
            elif action == "disable":
                enabled = False
            else:
                forced = action == "force"
        if enabled and not forced and site is not None:
            i, m, line, table = site
            # A computed FORCE from this migration on may name this table; it cannot be told.
            out.append(_unforced(m, line, table, "low" if i <= last_computed_force else "medium"))
    for i, m, line, table, action in events:
        if action == "enable" and _templated(table) and not any(
                a == "force" and _templated(t) for _, t, a in m.rls):
            out.append(_unforced(m, line, table, "low"))
    return out, any(action == "enable" for *_, action in events)


def _unforced(m: _Migration, line: int, table: str, confidence: str) -> Finding:
    subject = (f"`{table}`, a table name computed at run time,"
               if _templated(table) else table)
    return Finding(
        tool=TOOL, rule="migrations/rls-without-force", severity="medium", confidence=confidence,
        category="security", file=m.rel, line=line,
        message=f"{subject} gets ENABLE ROW LEVEL SECURITY and no migration FORCEs it: the "
                "table's owner is exempt from every policy on it",
        remedy="Add `ALTER TABLE ... FORCE ROW LEVEL SECURITY` next to the ENABLE. Without "
               "FORCE, an application that connects as the owner reads every tenant's rows.",
    )


def _views(migrations: list[_Migration]) -> list[Finding]:
    statements = [(m, sql.line, stmt) for m in migrations for sql in m.sql for stmt in _statements(sql.text)]
    fixed_later = {_norm(name) for _, _, stmt in statements
                   for name, options in _ALTER_VIEW.findall(stmt) if _invoker_on(options)}
    out: list[Finding] = []
    for m, line, stmt in statements:
        for name, options in _VIEW.findall(stmt):
            view = _norm(name)
            if _invoker_on(options) or view in fixed_later:
                continue
            out.append(Finding(
                tool=TOOL, rule="migrations/view-without-security-invoker", severity="medium",
                confidence="medium", category="security", file=m.rel, line=line,
                message=f"view {view} evaluates the row-level security of the tables under "
                        "it as the VIEW OWNER, not the caller",
                remedy="Create it `WITH (security_invoker = true)` (PostgreSQL 15+). It looks "
                       "harmless while the owner and the caller are the same role, and keeps "
                       "returning rows — the wrong ones — once they are not.",
            ))
    return out


def _indexes(migrations: list[_Migration]) -> list[Finding]:
    out: list[Finding] = []
    for m in migrations:
        targets: set[tuple[int, str]] = set()
        for sql in m.sql:
            for stmt in _statements(sql.text):
                targets.update((sql.line, _norm(table)) for concurrently, table in _CREATE_INDEX.findall(stmt)
                               if not concurrently)
        for c in m.calls:
            if last(c.node.func) != "create_index":
                continue
            concurrent = keyword_value(c.node, "postgresql_concurrently")
            if isinstance(concurrent, ast.Constant) and concurrent.value:
                continue
            named = _arg(c.node, 1, "table_name", c.env) if c.batch_table() is None else None
            table = c.batch_table() or (_qualified(c.node, named, c.env) if named else None)
            if table:
                targets.add((c.node.lineno, table))
        for line, table in sorted(targets):
            if _templated(table) or m.made(table):
                continue
            out.append(Finding(
                tool=TOOL, rule="migrations/index-not-concurrent", severity="low", confidence="low",
                category="performance", file=m.rel, line=line,
                message=f"CREATE INDEX on {table}, which this migration did not create, without "
                        f"CONCURRENTLY: writes to {table} wait until the build finishes",
                remedy="Use CREATE INDEX CONCURRENTLY (op.create_index(..., "
                       "postgresql_concurrently=True)) inside `with "
                       "op.get_context().autocommit_block():`, since it cannot run in a "
                       "transaction. Harmless on a small table; the lock grows with the rows.",
            ))
    return out


def _unsecured(migrations: list[_Migration], schemas: tuple[str, ...]) -> list[Finding]:
    secured = [t for m in migrations for _, t, action in m.rls if action == "enable" and not _templated(t)]
    computed = {m.rel for m in migrations
                if any(action == "enable" and _templated(t) for _, t, action in m.rls)}
    out: list[Finding] = []
    for m in migrations:
        if m.rel in computed:
            continue  # a computed ENABLE in the same migration may name any of its tables
        for table, line in sorted(m.created.items()):
            schema = table.split(".", 1)[0] if "." in table else ""
            if (_templated(table) or (schemas and schema not in schemas)
                    or any(_same_table(table, t) for t in secured)):
                continue
            out.append(Finding(
                tool=TOOL, rule="migrations/table-without-rls", severity="medium", confidence="low",
                category="security", file=m.rel, line=line,
                message=f"{table} is created in a row-secured schema and no migration enables "
                        "row-level security on it",
                remedy="ENABLE and FORCE row-level security with a tenant policy, or take the "
                       "schema out of [scan.migrations] rls_schemas if it holds no tenant data.",
            ))
    return out


def scan(s: ScanSettings) -> list[Finding]:
    """Run the database-migration rules over every migration file and return the findings."""
    migrations = [m for p in migration_files(s) if (m := _read(s, p)) is not None]
    findings: list[Finding] = []
    for m in migrations:
        findings.extend(_revision(m, s.migrations.revision_max_length))
        findings.extend(_not_null(m))
    rls, uses_rls = _rls(migrations)
    findings.extend(rls)
    if uses_rls or s.migrations.require_rls:
        findings.extend(_views(migrations))
    findings.extend(_indexes(migrations))
    if s.migrations.require_rls:
        findings.extend(_unsecured(migrations, s.migrations.rls_schemas))
    # A helper called twice with the same arguments writes the same statement twice.
    unique: dict[tuple[str, str, int, str], Finding] = {}
    for f in findings:
        unique.setdefault((f.rule, f.file, f.line, f.message), f)
    return list(unique.values())
